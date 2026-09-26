package redact

import (
	"encoding/base64"
	"strings"
	"testing"
)

// Phase 9 review: encoded credentials and key variants must be caught, mirroring
// packages/afterlock/evidence.py, or the collector emits values the loader rejects.
func TestEncodedCredentialsAreSensitive(t *testing.T) {
	jwt := "eyJhbGciOiJSUzI1NiIsImtpZCI6ImZha2UifQ.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl"
	for _, in := range []string{
		base64.StdEncoding.EncodeToString([]byte(jwt)),
		base64.RawURLEncoding.EncodeToString([]byte(jwt)),
		strings.ReplaceAll(jwt, ".", "%2E"),
		base64.StdEncoding.EncodeToString([]byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE")),
	} {
		if !Sensitive(in) {
			t.Errorf("Sensitive(%q) = false", in)
		}
	}
	for _, k := range []string{"accessToken", "id_token", "clientSecret", "apiKey", "private_key"} {
		if p := Check([]byte(`{"` + k + `":"opaque"}`)); len(p) != 1 {
			t.Errorf("key %q: problems = %v, want 1", k, p)
		}
	}
	if p := Check([]byte(`{"token_audiences":["x"],"source_secret":"s"}`)); len(p) != 0 {
		t.Errorf("benign keys flagged: %v", p)
	}
}

func TestStringRedactsCredentialLikeValues(t *testing.T) {
	for _, in := range []string{
		"AFTERLOCK-CANARY-abc123",
		"prefix eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4eXoifQ.sig suffix",
		"-----BEGIN RSA PRIVATE KEY-----",
		"Bearer abcdefghijklmnop",
	} {
		if got := String(in); got != Placeholder {
			t.Errorf("String(%q) = %q, want placeholder", in, got)
		}
	}
	if got := String("system:serviceaccount:demo:ci-runner"); got != "system:serviceaccount:demo:ci-runner" {
		t.Errorf("ordinary value changed: %q", got)
	}
}

func TestStringTruncatesOnRuneBoundary(t *testing.T) {
	got := String(strings.Repeat("é", 400)) // 800 bytes
	if len(got) > MaxString || !strings.HasPrefix(strings.Repeat("é", 400), got) {
		t.Fatalf("bad truncation: len=%d", len(got))
	}
}

func TestCheckFindsForbiddenKeysAndValues(t *testing.T) {
	p := Check([]byte(`{"a":{"Data":{"x":"y"}},"b":["AFTERLOCK-CANARY-z"],"c":"fine"}`))
	if len(p) != 2 {
		t.Fatalf("problems = %v, want 2", p)
	}
	if p := Check([]byte(`{"actor":{"username":"u"}}`)); len(p) != 0 {
		t.Fatalf("unexpected problems %v", p)
	}
}
