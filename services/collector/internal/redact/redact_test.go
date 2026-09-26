package redact

import (
	"strings"
	"testing"
)

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
