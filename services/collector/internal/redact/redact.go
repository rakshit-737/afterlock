// Package redact enforces the collector's credential-material boundary.
//
// Every string that leaves the collector (spool records, bundle files, logs)
// passes through String. The patterns and forbidden keys mirror
// packages/afterlock/evidence.py so that anything the collector emits is also
// acceptable to the Python replay loader; Check is a final fail-closed guard.
package redact

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"
)

// MaxString mirrors evidence.MAX_STRING.
const MaxString = 512

// Placeholder replaces any value that resembles credential material.
const Placeholder = "[redacted]"

var sensitive = []*regexp.Regexp{
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`), // JWT
	regexp.MustCompile(`ZXlK[A-Za-z0-9+/_-]{16,}`),                // base64 of a JWT ("eyJ" -> "ZXlK")
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`LS0tLS1CRUdJTi`),                // base64 of "-----BEGIN"
	regexp.MustCompile(`AFTERLOCK-CANARY-[A-Za-z0-9]+`), // seeded redaction canaries
	regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._~+/=-]{8,}`),
}

// ForbiddenKeys mirrors evidence.FORBIDDEN_KEYS (compared case-insensitively).
var ForbiddenKeys = map[string]bool{
	"token": true, "bearer": true, "authorization": true, "data": true,
	"stringdata": true, "string_data": true, "password": true, "secret_value": true,
	"response_body": true, "responseobject": true, "request_body": true,
	"requestobject": true, "credential_value": true,
}

// forbiddenKeySuffixes mirrors evidence.FORBIDDEN_KEY_SUFFIXES: a key is
// normalized to lowercase alphanumerics (accessToken, id_token, client-secret).
var forbiddenKeySuffixes = []string{"token", "password", "secretvalue", "clientsecret", "secretkey", "apikey", "privatekey", "accesskey", "authorization"}

// ForbiddenKey reports whether a JSON key names credential or payload material.
func ForbiddenKey(k string) bool {
	lower := strings.ToLower(k)
	var b strings.Builder
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	norm := b.String()
	if ForbiddenKeys[lower] || ForbiddenKeys[norm] {
		return true
	}
	for _, s := range forbiddenKeySuffixes {
		if strings.HasSuffix(norm, s) {
			return true
		}
	}
	return false
}

// percentDecode decodes every valid %XX escape and leaves invalid ones as they
// are (like Python's urllib.parse.unquote), so one malformed escape cannot
// switch decoding off for the rest of the value.
func percentDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			v, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b.WriteByte(byte(v))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

var redactions atomic.Int64

// Redactions reports how many values have been replaced since process start.
func Redactions() int64 { return redactions.Load() }

// Sensitive reports whether s, or its percent-decoded form, resembles
// credential material.
func Sensitive(s string) bool {
	candidates := []string{s}
	if strings.Contains(s, "%") {
		candidates = append(candidates, percentDecode(s))
	}
	for _, c := range candidates {
		for _, re := range sensitive {
			if re.MatchString(c) {
				return true
			}
		}
	}
	return false
}

// String returns s unless it resembles credential material, in which case the
// whole value (not just the match) is replaced. Output is truncated to
// MaxString bytes on a UTF-8 boundary.
func String(s string) string {
	if Sensitive(s) {
		redactions.Add(1)
		return Placeholder
	}
	if len(s) <= MaxString {
		return s
	}
	cut := MaxString
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// Check walks a JSON document and reports every forbidden key or
// credential-like value. It is used as a last guard before bytes are written.
func Check(doc []byte) []string {
	var v any
	if err := json.Unmarshal(doc, &v); err != nil {
		return []string{"not JSON: " + err.Error()}
	}
	var problems []string
	walk(v, "$", &problems)
	return problems
}

func walk(v any, path string, problems *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			if ForbiddenKey(k) {
				*problems = append(*problems, fmt.Sprintf("%s.%s: forbidden key", path, k))
				continue
			}
			walk(x, path+"."+k, problems)
		}
	case []any:
		for i, x := range t {
			walk(x, fmt.Sprintf("%s[%d]", path, i), problems)
		}
	case string:
		if Sensitive(t) {
			*problems = append(*problems, path+": value resembles credential material")
		}
	}
}
