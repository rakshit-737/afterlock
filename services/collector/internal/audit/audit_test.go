package audit

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rakshit-737/afterlock/services/collector/internal/spool"
)

func newIngester(t *testing.T) (*Ingester, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spool.jsonl")
	sp, err := spool.Open(spool.Options{Path: path, MaxBytes: 1 << 20, MaxRecords: 100, SourceID: "src", ClusterID: "c",
		Now: func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sp.Close() })
	return NewIngester(sp), path
}

func TestFixtureLogCanariesNeverReachSpool(t *testing.T) {
	in, path := newIngester(t)
	f, err := os.Open("../../testdata/audit.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := in.IngestLog(f, "audit.log"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, c := range []string{"AFTERLOCK-CANARY", "eyJhbGciOiJSUzI1NiJ9", "QUZURVJMT0NLLUNBTkFSWS1zZWNyZXQ=", "requestURI", "sourceIPs", "annotations", "credential-id", "groups"} {
		if bytes.Contains(raw, []byte(c)) {
			t.Errorf("spool contains %q", c)
		}
	}
	c := in.Counters
	if c.Accepted.Load() != 5 || c.Duplicates.Load() != 1 || c.IgnoredStage.Load() != 1 || c.Malformed.Load() != 2 || c.Unmodeled.Load() != 1 {
		t.Errorf("counters accepted=%d dup=%d ignored=%d malformed=%d unmodeled=%d", c.Accepted.Load(), c.Duplicates.Load(),
			c.IgnoredStage.Load(), c.Malformed.Load(), c.Unmodeled.Load())
	}
}

func TestOversizedLineBecomesGap(t *testing.T) {
	in, path := newIngester(t)
	big := `{"apiVersion":"audit.k8s.io/v1","auditID":"x","requestObject":"` + strings.Repeat("A", maxEventLine) + `"}` + "\n"
	if err := in.IngestLog(strings.NewReader(big), "big.log"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Contains(raw, []byte("exceeds the line limit")) || bytes.Contains(raw, []byte("AAAA")) {
		t.Fatal("oversized line was not recorded as a gap, or its content leaked")
	}
}

const token = "webhook-token-0123456789"

func post(h http.Handler, auth, body string) int {
	r := httptest.NewRequest(http.MethodPost, "/v1/audit", strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestWebhookRequiresTokenAndDeduplicates(t *testing.T) {
	in, path := newIngester(t)
	h, err := NewWebhookHandler(in, token+"\n")
	if err != nil {
		t.Fatal(err)
	}
	batch := `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"w-1",` +
		`"stage":"ResponseComplete","verb":"get","user":{"username":"u"},"objectRef":{"resource":"secrets","namespace":"demo","name":"s"},` +
		`"responseStatus":{"code":200},"stageTimestamp":"2026-01-01T00:00:00.5Z","responseObject":{"data":{"k":"AFTERLOCK-CANARY-webhook"}}}]}`
	if code := post(h, "", batch); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", code)
	}
	if code := post(h, "Bearer wrong-token-0123456789", batch); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", code)
	}
	for i := 0; i < 2; i++ { // redelivery of the same batch
		if code := post(h, "Bearer "+token, batch); code != http.StatusOK {
			t.Fatalf("valid batch: %d", code)
		}
	}
	if code := post(h, "Bearer "+token, "not json"); code != http.StatusBadRequest {
		t.Fatalf("malformed batch: %d", code)
	}
	if in.Counters.Accepted.Load() != 1 || in.Counters.Duplicates.Load() != 1 {
		t.Fatalf("accepted=%d duplicates=%d", in.Counters.Accepted.Load(), in.Counters.Duplicates.Load())
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("AFTERLOCK-CANARY")) || bytes.Contains(raw, []byte(token)) {
		t.Fatal("webhook body or token reached the spool")
	}
	if !bytes.Contains(raw, []byte("webhook batch is not an audit EventList")) {
		t.Fatal("malformed batch was not recorded as a gap")
	}
	if _, err := NewWebhookHandler(in, "short"); err == nil {
		t.Fatal("short token accepted")
	}
}

// An API server audit log spans the cluster's lifetime; events before the
// evidence window (e.g. an earlier lab run's Pod create with the same
// namespace/name) are excluded, counted, and surfaced as one explicit gap.
func TestAuditSinceExcludesEarlierEventsWithOneGap(t *testing.T) {
	in, path := newIngester(t)
	in.Since = time.Date(2026, 9, 26, 10, 5, 0, 0, time.UTC)
	line := func(id, ts string) string {
		return `{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"` + id + `","stage":"ResponseComplete",` +
			`"requestURI":"/api/v1/namespaces/demo/pods","verb":"create","user":{"username":"system:serviceaccount:demo:ci-runner","uid":"sa-1"},` +
			`"objectRef":{"resource":"pods","namespace":"demo","name":"diagnostic-job","apiVersion":"v1"},"responseStatus":{"metadata":{},"code":201},` +
			`"stageTimestamp":"` + ts + `"}` + "\n"
	}
	log := line("old-1", "2026-09-26T10:01:31.123456Z") + line("old-2", "2026-09-26T10:04:59.999999Z") + line("new-1", "2026-09-26T10:05:00.000001Z")
	if err := in.IngestLog(strings.NewReader(log), "audit.log"); err != nil {
		t.Fatal(err)
	}
	if err := in.RecordWindowGap(); err != nil {
		t.Fatal(err)
	}
	if in.Counters.Accepted.Load() != 1 || in.Counters.BeforeWindow.Load() != 2 {
		t.Fatalf("accepted=%d before=%d", in.Counters.Accepted.Load(), in.Counters.BeforeWindow.Load())
	}
	raw, _ := os.ReadFile(path)
	if bytes.Contains(raw, []byte("audit:old-")) || !bytes.Contains(raw, []byte("audit:new-1")) {
		t.Fatal("window not applied")
	}
	if bytes.Count(raw, []byte(`"gap_kind":"audit-before-window"`)) != 1 || !bytes.Contains(raw, []byte("2 audit events before")) {
		t.Fatalf("missing window gap: %s", raw)
	}
}

// Phase 9 review: kube-apiserver takes a client-supplied Audit-ID header as the
// event's auditID. Deduplicating on auditID alone let an attacker reuse an
// earlier request's ID so its own request was dropped as a "duplicate" (no gap).
// Only a byte-identical redelivery is a duplicate.
func TestReusedAuditIDWithDifferentContentIsKept(t *testing.T) {
	in, path := newIngester(t)
	ev := func(verb, resource, name string, code int) string {
		return `{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"chosen-by-client","stage":"ResponseComplete",` +
			`"verb":"` + verb + `","user":{"username":"system:serviceaccount:demo:release-reader","uid":"sa-2"},` +
			`"objectRef":{"resource":"` + resource + `","namespace":"demo","name":"` + name + `"},"responseStatus":{"code":` +
			strconv.Itoa(code) + `},"stageTimestamp":"2026-09-26T10:06:00Z"}` + "\n"
	}
	benign := ev("list", "configmaps", "", 200)
	log := benign + benign + ev("get", "secrets", "release-credential", 200)
	if err := in.IngestLog(strings.NewReader(log), "audit.log"); err != nil {
		t.Fatal(err)
	}
	if in.Counters.Accepted.Load() != 2 || in.Counters.Duplicates.Load() != 1 {
		t.Fatalf("accepted=%d dup=%d", in.Counters.Accepted.Load(), in.Counters.Duplicates.Load())
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Contains(raw, []byte("release-credential")) {
		t.Fatal("secret read with a reused auditID was dropped")
	}
}
