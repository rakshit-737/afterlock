package audit

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
)

// MaxWebhookBody bounds a single webhook batch.
const MaxWebhookBody = 8 * 1024 * 1024

// WebhookHandler accepts audit.k8s.io/v1 EventList batches from the
// kube-apiserver webhook audit backend. Callers must present the configured
// bearer token. The token, request headers and bodies are never logged or
// persisted; only the metadata envelope derived from each event is spooled.
type WebhookHandler struct {
	In       *Ingester
	tokenSum [32]byte
	batches  atomic.Int64
}

// NewWebhookHandler returns a handler that requires token (must be non-empty).
func NewWebhookHandler(in *Ingester, token string) (*WebhookHandler, error) {
	token = strings.TrimSpace(token)
	if len(token) < 16 {
		return nil, errors.New("webhook token must be at least 16 characters")
	}
	return &WebhookHandler{In: in, tokenSum: sha256.Sum256([]byte(token))}, nil
}

func (h *WebhookHandler) authorized(r *http.Request) bool {
	const prefix = "Bearer "
	a := r.Header.Get("Authorization")
	if !strings.HasPrefix(a, prefix) {
		return false
	}
	got := sha256.Sum256([]byte(strings.TrimSpace(a[len(prefix):])))
	return subtle.ConstantTimeCompare(got[:], h.tokenSum[:]) == 1
}

func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxWebhookBody))
	if err != nil {
		h.In.Counters.Malformed.Add(1)
		_ = h.In.Spool.Gap("audit-dropped", "a webhook audit batch exceeded the size limit or was truncated and was dropped")
		http.Error(w, "batch too large", http.StatusRequestEntityTooLarge)
		return
	}
	n := h.batches.Add(1)
	if err := h.In.IngestList(body, "webhook batch "+strconv.FormatInt(n, 10)); err != nil {
		http.Error(w, "rejected", http.StatusBadRequest)
		return
	}
	// Acknowledge only after the spool is durable.
	if err := h.In.Spool.Sync(); err != nil {
		http.Error(w, "spool unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}
