package bundle_test

// Reproductions of the live-lab failures seen in run 36234401716 (kind,
// Kubernetes v1.31.4, audit log at Metadata level):
//
//  1. Secret metadata was granted by a namespaced RoleBinding (as
//     deploy/secret-metadata-rbac.yaml recommends), but the collector listed
//     Secrets cluster-wide. Every list was 403 ("list-failed" gaps, secrets
//     "inventory-unsynced"), so the protected Secret was missing from
//     inventory.json and the analysis could not derive the residual path.
//  2. The API server audit log spans the cluster's lifetime. Earlier runs
//     in the same cluster had created and deleted a Pod with the same
//     namespace/name as the attacker Pod, so the first matching create in
//     the bundle was an old one that (correctly) could not be correlated.
//
// The audit lines below are shaped like real kube-apiserver Metadata-level
// audit events (requestURI, sourceIPs, userAgent, groups, credential-id
// extra, authorization annotations), none of which may reach the bundle.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/rakshit-737/afterlock/services/collector/internal/audit"
	"github.com/rakshit-737/afterlock/services/collector/internal/bundle"
	"github.com/rakshit-737/afterlock/services/collector/internal/inventory"
	"github.com/rakshit-737/afterlock/services/collector/internal/spool"
)

func kindAuditLine(id string, at time.Time, verb, user, saUID string, extra map[string][]string, resource, name string, code int) string {
	ev := map[string]any{
		"kind": "Event", "apiVersion": "audit.k8s.io/v1", "level": "Metadata", "auditID": id, "stage": "ResponseComplete",
		"requestURI": "/api/v1/namespaces/demo/" + resource + "?fieldManager=kubectl-create", "verb": verb,
		"user": map[string]any{"username": user, "uid": saUID,
			"groups": []string{"system:serviceaccounts", "system:serviceaccounts:demo", "system:authenticated"}, "extra": extra},
		"sourceIPs": []string{"172.18.0.1"}, "userAgent": "kubectl/v1.31.4 (linux/amd64) kubernetes/48d9b16",
		"objectRef":                map[string]any{"resource": resource, "namespace": "demo", "name": name, "apiVersion": "v1"},
		"responseStatus":           map[string]any{"metadata": map[string]any{}, "code": code},
		"requestReceivedTimestamp": at.Add(-3 * time.Millisecond).Format(time.RFC3339Nano),
		"stageTimestamp":           at.Format(time.RFC3339Nano),
		"annotations":              map[string]string{"authorization.k8s.io/decision": "allow", "authorization.k8s.io/reason": `RBAC: allowed by RoleBinding "ci-pod-creator/demo"`},
	}
	b, _ := json.Marshal(ev)
	return string(b)
}

// liveLabAudit: an earlier run's attacker Pod create (Pod since deleted),
// then this run's create and the attacker Pod's Secret read.
func liveLabAudit() string {
	ci := "system:serviceaccount:demo:ci-runner"
	ciExtra := map[string][]string{"authentication.kubernetes.io/credential-id": {"JTI=0f6c1e1a-canary"}}
	podExtra := map[string][]string{
		"authentication.kubernetes.io/credential-id": {"JTI=7d2b-canary"},
		"authentication.kubernetes.io/node-name":     {"afterlock-lab-control-plane"},
		"authentication.kubernetes.io/pod-name":      {"diagnostic-job"},
		"authentication.kubernetes.io/pod-uid":       {"pod-attacker-0001"},
	}
	lines := []string{
		kindAuditLine("11111111-old-run", t0.Add(-40*time.Minute), "create", ci, "sa-ci-runner-0001", ciExtra, "pods", "diagnostic-job", 201),
		kindAuditLine("22222222-this-run", t0.Add(time.Second+400*time.Millisecond), "create", ci, "sa-ci-runner-0001", ciExtra, "pods", "diagnostic-job", 201),
		kindAuditLine("33333333-this-run", t0.Add(5*time.Second), "get", "system:serviceaccount:demo:release-reader", "sa-release-reader-0001", podExtra, "secrets", "release-credential", 200),
	}
	return strings.Join(lines, "\n") + "\n"
}

var forbidden = func(res string) error {
	return apierrors.NewForbidden(schema.GroupResource{Resource: res}, "",
		errors.New(`User "system:serviceaccount:afterlock:afterlock-collector" cannot list resource "secrets" in API group "" at the cluster scope`))
}

// namespacedSecretGrant makes the metadata client behave like a RoleBinding
// in "demo" only: cluster-wide list/watch of secrets is forbidden.
func namespacedSecretGrant(md *metadatafake.FakeMetadataClient) {
	md.PrependReactor("list", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() == "" {
			return true, nil, forbidden("secrets")
		}
		return false, nil, nil
	})
	md.PrependWatchReactor("secrets", func(a k8stesting.Action) (bool, watch.Interface, error) {
		if a.GetNamespace() == "" {
			return true, nil, forbidden("secrets")
		}
		return false, nil, nil
	})
}

type liveLabRun struct {
	events    []map[string]any
	inventory map[string]any
}

func runLiveLab(t *testing.T, secretNamespaces []string, since time.Time) liveLabRun {
	t.Helper()
	clock := func() time.Time { return t0.Add(30 * time.Minute) }
	sp, err := spool.Open(spool.Options{Path: filepath.Join(t.TempDir(), "spool.jsonl"), MaxBytes: 1 << 20, MaxRecords: 1000,
		SourceID: "lab-audit", ClusterID: "lab-local", Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	defer sp.Close()
	cs := fake.NewSimpleClientset(fakeCluster()...)
	scheme := runtime.NewScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	md := metadatafake.NewSimpleMetadataClient(scheme, fakeSecretMetadata()...)
	namespacedSecretGrant(md)
	store := inventory.NewStore()
	coll := inventory.New(cs, md, store, func(k, r string) { _ = sp.Gap(k, r) }, secretNamespaces...)
	coll.Backoff = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { coll.Run(ctx); close(done) }()
	// Like waitSynced in main: bounded; a forbidden kind never syncs.
	deadline := time.Now().Add(300 * time.Millisecond)
	for time.Now().Before(deadline) {
		all := true
		for _, k := range coll.Kinds() {
			all = all && store.Synced(k)
		}
		if all {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	in := audit.NewIngester(sp)
	in.Since = since
	if err := in.IngestLog(strings.NewReader(liveLabAudit()), "audit.log"); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	if err := in.RecordWindowGap(); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "bundle")
	if err := bundle.Write(bundle.Options{Dir: out, CaseID: "c", ClusterID: "lab-local", SourceID: "lab-audit", Now: clock(), SecretMetadata: true},
		sp.Records(), store.Snapshot(coll.Kinds()), store); err != nil {
		t.Fatal(err)
	}
	var run liveLabRun
	f, err := os.Open(filepath.Join(out, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		run.events = append(run.events, m)
	}
	raw, err := os.ReadFile(filepath.Join(out, "inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &run.inventory); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"events.jsonl", "inventory.json"} {
		b, _ := os.ReadFile(filepath.Join(out, name))
		for _, c := range []string{"canary", "requestURI", "172.18.0.1", "credential-id", "authorization.k8s.io", "pod-name"} {
			if strings.Contains(string(b), c) {
				t.Errorf("%s contains %q", name, c)
			}
		}
	}
	return run
}

func (r liveLabRun) gapKinds() map[string]int {
	out := map[string]int{}
	for _, e := range r.events {
		if e["event_type"] == "collector.gap" {
			out[fmt.Sprint(e["gap_kind"])]++
		}
	}
	return out
}

// podCreates returns the targets of successful diagnostic-job creates, in order.
func (r liveLabRun) podCreates() []map[string]any {
	var out []map[string]any
	for _, e := range r.events {
		a, _ := e["action"].(map[string]any)
		tg, _ := e["target"].(map[string]any)
		if a != nil && a["verb"] == "create" && a["resource"] == "pods" && tg["name"] == "diagnostic-job" {
			out = append(out, tg)
		}
	}
	return out
}

func (r liveLabRun) hasSecret(name string) bool {
	secs, _ := r.inventory["secrets"].([]any)
	for _, s := range secs {
		if m, _ := s.(map[string]any); m["name"] == name {
			return true
		}
	}
	return false
}

// TestLiveLabFailureReproduced pins the pre-fix behaviour: cluster-wide
// Secret list under a namespaced grant, and no audit evidence window.
func TestLiveLabFailureReproduced(t *testing.T) {
	r := runLiveLab(t, nil, time.Time{})
	g := r.gapKinds()
	if g["list-failed"] == 0 || g["inventory-unsynced"] != 1 {
		t.Fatalf("expected forbidden cluster-wide Secret lists to be recorded, gaps = %v", g)
	}
	if r.hasSecret("release-credential") {
		t.Fatal("Secret metadata must be absent when every list was forbidden")
	}
	creates := r.podCreates()
	if len(creates) != 2 {
		t.Fatalf("creates = %v", creates)
	}
	if _, ok := creates[0]["uid"]; ok || g["pod-uncorrelated"] != 1 {
		t.Fatalf("the earlier run's create must stay uncorrelated (never guessed): %v, gaps = %v", creates[0], g)
	}
}

func TestNamespacedSecretMetadataAndAuditWindowFixLiveLab(t *testing.T) {
	r := runLiveLab(t, []string{"demo"}, t0.Add(-time.Minute))
	g := r.gapKinds()
	for _, k := range []string{"list-failed", "inventory-unsynced", "pod-uncorrelated", "secret-metadata-disabled"} {
		if g[k] != 0 {
			t.Errorf("unexpected %s gaps: %v", k, g)
		}
	}
	if g["audit-before-window"] != 1 {
		t.Errorf("the excluded earlier-run event must be recorded as one explicit gap, gaps = %v", g)
	}
	if !r.hasSecret("release-credential") {
		t.Error("protected Secret metadata missing from inventory")
	}
	creates := r.podCreates()
	if len(creates) != 1 {
		t.Fatalf("only this run's create belongs to the case, got %v", creates)
	}
	if creates[0]["uid"] != "pod-attacker-0001" || creates[0]["service_account"] != "release-reader" || creates[0]["uid_source"] != "inventory-correlation" {
		t.Fatalf("create not correlated to the live Pod: %v", creates[0])
	}
}

// TestSecretNamespacesStillReportForbiddenNamespace: scoping never hides a
// namespace the grant does not cover.
func TestSecretNamespacesStillReportForbiddenNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := metav1.AddMetaToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	md := metadatafake.NewSimpleMetadataClient(scheme, fakeSecretMetadata()...)
	md.PrependReactor("list", "secrets", func(a k8stesting.Action) (bool, runtime.Object, error) {
		if a.GetNamespace() != "demo" {
			return true, nil, forbidden("secrets")
		}
		return false, nil, nil
	})
	store := inventory.NewStore()
	var gaps []string
	gapc := make(chan string, 64)
	coll := inventory.New(fake.NewSimpleClientset(), md, store, func(k, r string) {
		select {
		case gapc <- k + ": " + r:
		default:
		}
	}, "demo", "other", "demo")
	coll.Backoff = 5 * time.Millisecond
	want := map[string]bool{"secrets/demo": true, "secrets/other": true}
	for _, k := range coll.Kinds() {
		delete(want, k)
	}
	if len(want) != 0 {
		t.Fatalf("kinds = %v", coll.Kinds())
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { coll.Run(ctx); close(done) }()
	deadline := time.After(5 * time.Second)
	for !(store.Synced("secrets/demo") && len(gaps) > 0) {
		select {
		case g := <-gapc:
			if strings.HasPrefix(g, "list-failed:") && strings.Contains(g, "secrets/other") {
				gaps = append(gaps, g)
			}
		case <-deadline:
			t.Fatalf("synced=%v gaps=%v", store.Synced("secrets/demo"), gaps)
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done
	if store.Synced("secrets/other") {
		t.Fatal("forbidden namespace reported as synced")
	}
	if u := store.Snapshot(coll.Kinds()).Unsynced; len(u) != 1 || u[0] != "secrets/other" {
		t.Fatalf("unsynced = %v", u)
	}
}
