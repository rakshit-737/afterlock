package bundle_test

import (
	"bytes"
	"context"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	metadatafake "k8s.io/client-go/metadata/fake"

	"github.com/rakshit-737/afterlock/services/collector/internal/audit"
	"github.com/rakshit-737/afterlock/services/collector/internal/bundle"
	"github.com/rakshit-737/afterlock/services/collector/internal/inventory"
	"github.com/rakshit-737/afterlock/services/collector/internal/spool"
)

var update = flag.Bool("update", false, "rewrite testdata/golden-bundle")

const goldenDir = "../../testdata/golden-bundle"

// Canary values seeded into the fixture audit log and the fake cluster. None
// of them (nor the base64 form of the Secret canary) may reach any output.
var canaries = []string{
	"AFTERLOCK-CANARY",
	"eyJhbGciOiJSUzI1NiJ9",
	"QUZURVJMT0NLLUNBTkFSWS1zZWNyZXQ=",
	"c2lnbmF0dXJlLWNhbmFyeQ",
	"s3cr3t-canary-env",
}

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func meta(ns, name, uid string, created time.Time) metav1.ObjectMeta {
	return metav1.ObjectMeta{Namespace: ns, Name: name, UID: types.UID(uid), ResourceVersion: "opaque-" + uid,
		CreationTimestamp: metav1.NewTime(created),
		Annotations:       map[string]string{"kubectl.kubernetes.io/last-applied-configuration": `{"data":{"password":"QUZURVJMT0NLLUNBTkFSWS1zZWNyZXQ="},"note":"AFTERLOCK-CANARY-annotation"}`}}
}

func fakeCluster() []runtime.Object {
	sensitiveEnv := []corev1.EnvVar{{Name: "TOKEN", Value: "s3cr3t-canary-env AFTERLOCK-CANARY-podenv"}}
	return []runtime.Object{
		&corev1.ServiceAccount{ObjectMeta: meta("demo", "ci-runner", "sa-ci-runner-0001", t0)},
		&corev1.ServiceAccount{ObjectMeta: meta("demo", "release-reader", "sa-release-reader-0001", t0)},
		&corev1.Pod{ObjectMeta: meta("demo", "ci-runner-7f9c", "pod-ci-0001", t0), Spec: corev1.PodSpec{ServiceAccountName: "ci-runner",
			Containers: []corev1.Container{{Name: "c", Env: sensitiveEnv}}}},
		&corev1.Pod{ObjectMeta: meta("demo", "release-app", "pod-release-0001", t0), Spec: corev1.PodSpec{ServiceAccountName: "release-reader"}},
		&corev1.Pod{ObjectMeta: meta("demo", "diagnostic-job", "pod-attacker-0001", t0.Add(time.Second)), Spec: corev1.PodSpec{
			ServiceAccountName: "release-reader", Containers: []corev1.Container{{Name: "c", Env: sensitiveEnv}},
			Volumes: []corev1.Volume{{Name: "tok", VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{Audience: "vault"}}}}}}}}},
		&rbacv1.Role{ObjectMeta: meta("demo", "pod-creator", "role-0001", t0), Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create", "get", "list"}}}},
		&rbacv1.Role{ObjectMeta: meta("demo", "release-secret-reader", "role-0002", t0), Rules: []rbacv1.PolicyRule{{Resources: []string{"secrets"}, ResourceNames: []string{"release-credential"}, Verbs: []string{"get"}}}},
		&rbacv1.ClusterRole{ObjectMeta: meta("", "health-reader", "crole-0001", t0), Rules: []rbacv1.PolicyRule{{NonResourceURLs: []string{"/healthz"}, Verbs: []string{"get"}}}},
		&rbacv1.RoleBinding{ObjectMeta: meta("demo", "ci-pod-creator", "rb-0001", t0), RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "pod-creator"},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "ci-runner", Namespace: "demo"}}},
		&rbacv1.RoleBinding{ObjectMeta: meta("demo", "release-reader-secret", "rb-0002", t0), RoleRef: rbacv1.RoleRef{Kind: "Role", Name: "release-secret-reader"},
			Subjects: []rbacv1.Subject{{Kind: "ServiceAccount", Name: "release-reader", Namespace: "demo"}}},
		&rbacv1.ClusterRoleBinding{ObjectMeta: meta("", "health", "crb-0001", t0), RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "health-reader"},
			Subjects: []rbacv1.Subject{{Kind: "Group", Name: "system:authenticated"}}},
		&admissionv1.ValidatingAdmissionPolicy{ObjectMeta: meta("", "restrict-ci-service-accounts", "vap-0001", t0)},
		// A full Secret in the typed fake: the collector must never list it
		// through this client (it uses the metadata client instead).
		&corev1.Secret{ObjectMeta: meta("demo", "release-credential", "secret-0001", t0), Data: map[string][]byte{"password": []byte("AFTERLOCK-CANARY-secret")}},
	}
}

func fakeSecretMetadata() []runtime.Object {
	m := meta("demo", "release-credential", "secret-0001", t0)
	return []runtime.Object{&metav1.PartialObjectMetadata{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"}, ObjectMeta: m}}
}

// collect runs the full pipeline against the fake cluster and fixture log.
func collect(t *testing.T, out string) *fake.Clientset {
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
	store := inventory.NewStore()
	coll := inventory.New(cs, md, store, func(k, r string) { _ = sp.Gap(k, r) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { coll.Run(ctx); close(done) }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		all := true
		for _, k := range coll.Kinds() {
			all = all && store.Synced(k)
		}
		if all {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("inventory did not sync")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	in := audit.NewIngester(sp)
	f, err := os.Open("../../testdata/audit.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := in.IngestLog(f, "audit.log"); err != nil {
		t.Fatal(err)
	}
	if got := in.Counters.Duplicates.Load(); got != 1 {
		t.Errorf("duplicates = %d, want 1", got)
	}
	if got := in.Counters.BodiesDropped.Load(); got != 2 {
		t.Errorf("bodies dropped = %d, want 2", got)
	}
	err = bundle.Write(bundle.Options{Dir: out, CaseID: "collector-golden", ClusterID: "lab-local", SourceID: "lab-audit",
		Now: clock(), SecretMetadata: true, Case: goldenCase()}, sp.Records(), store.Snapshot(coll.Kinds()), store)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func goldenCase() map[string]any {
	return map[string]any{
		"profile":       "k8s-1.31-core-v1",
		"analysis_time": "2026-01-01T12:30:00Z",
		"description":   "Golden bundle produced by the Go collector test from a fake cluster and a fixture audit log.",
		"assumptions":   []any{"Initial compromise of the CI service account is seeded, not exploited."},
		"compromised_credentials": []any{map[string]any{
			"id": "ci-runner-token", "kind": "sa_token", "username": "system:serviceaccount:demo:ci-runner",
			"sa_uid": "sa-ci-runner-0001", "bound_pod_uid": "pod-ci-0001", "audience": "https://kubernetes.default.svc.cluster.local"}},
		"objectives": []any{map[string]any{"id": "protect-secret", "kind": "no_secret_read", "namespace": "demo", "secret": "release-credential",
			"description": "Prevent further Kubernetes reads of demo/release-credential by modeled attacker credentials."}},
		"legitimate_operations":          []any{},
		"remediation":                    []any{map[string]any{"kind": "remove_binding", "name": "ci-pod-creator", "namespace": "demo"}},
		"required_sources":               []any{"lab-audit"},
		"max_evidence_staleness_seconds": 300,
	}
}

func TestGoldenBundle(t *testing.T) {
	out := t.TempDir()
	cs := collect(t, out)
	for _, a := range cs.Actions() {
		if v := a.GetVerb(); v != "list" && v != "watch" {
			t.Errorf("collector issued non-read verb %q on %s", v, a.GetResource().Resource)
		}
		if a.GetResource().Resource == "secrets" {
			t.Errorf("collector used the typed client for Secrets (%s); only metadata access is allowed", a.GetVerb())
		}
	}
	for _, name := range []string{"manifest.json", "inventory.json", "events.jsonl", "case.json"} {
		got, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range canaries {
			if bytes.Contains(got, []byte(c)) {
				t.Errorf("%s contains seeded canary %q", name, c)
			}
		}
		if bytes.Contains(got, []byte(`"data"`)) || bytes.Contains(got, []byte("responseObject")) || bytes.Contains(got, []byte("requestURI")) {
			t.Errorf("%s contains a body or request field", name)
		}
		golden := filepath.Join(goldenDir, name)
		if *update {
			if err := os.MkdirAll(goldenDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(golden, got, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatalf("%v (run: go test ./internal/bundle -run TestGoldenBundle -update)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from golden; rerun with -update and review the diff", name)
		}
	}
	events, _ := os.ReadFile(filepath.Join(out, "events.jsonl"))
	for _, want := range []string{
		`"event_id":"audit:a-0001"`, `"uid":"pod-attacker-0001"`, `"uid_source":"inventory-correlation"`,
		`"gap_kind":"audit-unmodeled"`, `"gap_kind":"audit-malformed"`, `"gap_kind":"admission-policy-unmodeled"`,
		`"gap_kind":"rbac-rule-unmodeled"`, `"gap_kind":"pod-uncorrelated"`, `"event_type":"collector.heartbeat"`, `"[redacted]"`,
	} {
		if !strings.Contains(string(events), want) {
			t.Errorf("events.jsonl lacks %s", want)
		}
	}
	if n := strings.Count(string(events), `"event_id":"audit:a-0001"`); n != 1 {
		t.Errorf("audit a-0001 appears %d times; duplicate delivery must be harmless", n)
	}
}
