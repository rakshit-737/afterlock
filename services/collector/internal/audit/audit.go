// Package audit converts Kubernetes audit events (audit.k8s.io/v1) into
// metadata-only AFTERLOCK evidence envelopes.
//
// Only an allowlist of metadata fields is ever copied. Request and response
// bodies, annotations, request URIs, source IPs, user groups and user extras
// other than the bound Pod UID are dropped at decode time and never reach the
// spool. Events are deduplicated by auditID; only the ResponseComplete and
// Panic stages are evidence (earlier stages lack an outcome).
package audit

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/rakshit-737/afterlock/services/collector/internal/redact"
	"github.com/rakshit-737/afterlock/services/collector/internal/spool"
)

const (
	apiVersion   = "audit.k8s.io/v1"
	podUIDExtra  = "authentication.kubernetes.io/pod-uid"
	saPrefix     = "system:serviceaccount:"
	maxEventLine = 4 * 1024 * 1024
)

type user struct {
	Username string              `json:"username"`
	UID      string              `json:"uid"`
	Extra    map[string][]string `json:"extra"`
}

type objectRef struct {
	Resource    string `json:"resource"`
	Namespace   string `json:"namespace"`
	Name        string `json:"name"`
	UID         string `json:"uid"`
	APIGroup    string `json:"apiGroup"`
	Subresource string `json:"subresource"`
}

type status struct {
	Code int `json:"code"`
}

// event is the subset of audit.k8s.io/v1 Event the collector reads.
// requestObject/responseObject are declared only so their presence can be
// counted; they are discarded immediately after decoding.
type event struct {
	Kind             string          `json:"kind"`
	APIVersion       string          `json:"apiVersion"`
	AuditID          string          `json:"auditID"`
	Stage            string          `json:"stage"`
	Verb             string          `json:"verb"`
	User             user            `json:"user"`
	ImpersonatedUser *user           `json:"impersonatedUser"`
	ObjectRef        *objectRef      `json:"objectRef"`
	ResponseStatus   *status         `json:"responseStatus"`
	StageTimestamp   string          `json:"stageTimestamp"`
	RequestObject    json.RawMessage `json:"requestObject"`
	ResponseObject   json.RawMessage `json:"responseObject"`
}

type eventList struct {
	Kind  string            `json:"kind"`
	Items []json.RawMessage `json:"items"`
}

// Counters are exported as metrics.
type Counters struct {
	Accepted, Duplicates, IgnoredStage, Malformed, BodiesDropped, Unmodeled, Dropped atomic.Int64
	// BeforeWindow counts events whose stageTimestamp precedes Ingester.Since.
	BeforeWindow atomic.Int64
}

// Ingester turns audit events into spooled envelopes.
type Ingester struct {
	Spool    *spool.Spool
	Counters *Counters
	// Since, when non-zero, is the start of the evidence window: events whose
	// stageTimestamp is before it are outside the case and are not spooled.
	// An API server audit log covers the cluster's whole lifetime, so without
	// a window, activity from earlier, unrelated runs (e.g. a Pod of the same
	// namespace/name created and deleted before collection started) enters
	// the bundle. Excluded events are counted; RecordWindowGap turns the
	// count into an explicit gap so the boundary is never silent.
	Since time.Time
}

// RecordWindowGap records one gap if any event fell before Since.
func (in *Ingester) RecordWindowGap() error {
	n := in.Counters.BeforeWindow.Load()
	if n == 0 {
		return nil
	}
	return in.Spool.Gap("audit-before-window", fmt.Sprintf("%d audit events before the evidence window start %s were excluded; activity before that time is not analysed",
		n, in.Since.UTC().Format(time.RFC3339)))
}

// NewIngester returns an ingester writing to sp.
func NewIngester(sp *spool.Spool) *Ingester {
	return &Ingester{Spool: sp, Counters: &Counters{}}
}

// IngestRaw ingests one audit event encoded as JSON. where identifies the
// record in gap reasons (e.g. "audit.log line 7").
func (in *Ingester) IngestRaw(raw []byte, where string) error {
	var ev event
	if err := json.Unmarshal(raw, &ev); err != nil {
		in.Counters.Malformed.Add(1)
		return in.Spool.Gap("audit-malformed", where+": audit record is not valid JSON and was dropped")
	}
	if len(ev.RequestObject) > 0 || len(ev.ResponseObject) > 0 {
		in.Counters.BodiesDropped.Add(1)
	}
	ev.RequestObject, ev.ResponseObject = nil, nil
	return in.ingest(&ev, where)
}

func (in *Ingester) ingest(ev *event, where string) error {
	if ev.APIVersion != apiVersion || (ev.Kind != "" && ev.Kind != "Event") || ev.AuditID == "" {
		in.Counters.Malformed.Add(1)
		return in.Spool.Gap("audit-malformed", where+": record is not an audit.k8s.io/v1 Event with an auditID and was dropped")
	}
	if ev.Stage != "ResponseComplete" && ev.Stage != "Panic" {
		in.Counters.IgnoredStage.Add(1)
		return nil
	}
	ts, err := time.Parse(time.RFC3339Nano, ev.StageTimestamp)
	if err != nil {
		in.Counters.Malformed.Add(1)
		return in.Spool.Gap("audit-malformed", where+": audit event has no valid stageTimestamp and was dropped")
	}
	if !in.Since.IsZero() && ts.Before(in.Since) {
		in.Counters.BeforeWindow.Add(1)
		return nil
	}
	auditID := redact.String(ev.AuditID)
	if ev.ImpersonatedUser != nil {
		// Impersonation changes the effective identity; the analysis model does
		// not represent it, so the event is recorded as an unmodeled gap.
		in.Counters.Unmodeled.Add(1)
		return in.Spool.Gap("audit-unmodeled", fmt.Sprintf("audit event %s used impersonation, which is not modeled; its effect is unknown", auditID))
	}
	if ev.ObjectRef == nil || ev.ResponseStatus == nil {
		// Non-resource requests (e.g. /healthz) carry no supported semantics.
		in.Counters.IgnoredStage.Add(1)
		return nil
	}
	rec := toEnvelope(ev, ts)
	rec["event_id"] = "audit:" + auditID
	// The API server accepts a client-supplied Audit-ID header, so the auditID alone
	// is attacker-choosable. Only a redelivery with identical metadata is a duplicate;
	// a reused ID with different content is kept (it gets its own source_sequence).
	content, err := json.Marshal(rec) // map keys are sorted: deterministic
	if err != nil {
		return err
	}
	sum := sha256.Sum256(content)
	_, err = in.Spool.Append(rec, "audit:"+auditID+":"+hex.EncodeToString(sum[:8]))
	switch {
	case errors.Is(err, spool.ErrDuplicate):
		in.Counters.Duplicates.Add(1)
		return nil
	case errors.Is(err, spool.ErrOverflow):
		in.Counters.Dropped.Add(1)
		return nil
	case err != nil:
		return err
	}
	in.Counters.Accepted.Add(1)
	return nil
}

func toEnvelope(ev *event, ts time.Time) map[string]any {
	actor := map[string]any{"username": redact.String(ev.User.Username)}
	if strings.HasPrefix(ev.User.Username, saPrefix) && ev.User.UID != "" {
		actor["sa_uid"] = redact.String(ev.User.UID)
	}
	if v := ev.User.Extra[podUIDExtra]; len(v) == 1 && v[0] != "" {
		actor["pod_uid"] = redact.String(v[0])
	}
	o := ev.ObjectRef
	resource := o.Resource
	if o.Subresource != "" {
		resource += "/" + o.Subresource
	}
	action := map[string]any{
		"verb":      redact.String(ev.Verb),
		"api_group": redact.String(o.APIGroup),
		"resource":  redact.String(resource),
	}
	if o.Namespace != "" {
		action["namespace"] = redact.String(o.Namespace)
	}
	target := map[string]any{}
	if o.Name != "" {
		target["name"] = redact.String(o.Name)
	}
	if o.UID != "" {
		target["uid"] = redact.String(o.UID)
	}
	return map[string]any{
		"event_type":  "k8s.api.response",
		"observed_at": ts.UTC().Format(time.RFC3339),
		"actor":       actor,
		"action":      action,
		"target":      target,
		"outcome":     map[string]any{"http_status": ev.ResponseStatus.Code},
		"provenance":  map[string]any{"transport": "authenticated-collector", "payload_class": "metadata-only"},
	}
}

// IngestLog reads a JSON-lines audit log (the audit log backend format).
// Oversized or malformed lines are recorded as gaps, never silently skipped.
func (in *Ingester) IngestLog(r io.Reader, name string) error {
	br := bufio.NewReaderSize(r, 64*1024)
	for lineno := 1; ; lineno++ {
		line, tooLong, err := readLine(br)
		where := fmt.Sprintf("%s line %d", name, lineno)
		if tooLong {
			in.Counters.Malformed.Add(1)
			if gerr := in.Spool.Gap("audit-malformed", where+": audit record exceeds the line limit and was dropped"); gerr != nil && !errors.Is(gerr, spool.ErrOverflow) {
				return gerr
			}
		} else if len(bytes.TrimSpace(line)) > 0 {
			if ierr := in.IngestRaw(line, where); ierr != nil && !errors.Is(ierr, spool.ErrOverflow) {
				return ierr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// readLine returns the next line; lines over maxEventLine are consumed and
// reported as tooLong without being buffered in full.
func readLine(br *bufio.Reader) ([]byte, bool, error) {
	var buf []byte
	tooLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > maxEventLine {
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return buf, tooLong, err
	}
}

// IngestList ingests an audit.k8s.io/v1 EventList (the webhook backend body).
func (in *Ingester) IngestList(body []byte, where string) error {
	var list eventList
	if err := json.Unmarshal(body, &list); err != nil || (list.Kind != "" && list.Kind != "EventList") {
		in.Counters.Malformed.Add(1)
		if gerr := in.Spool.Gap("audit-malformed", where+": webhook batch is not an audit EventList and was dropped"); gerr != nil && !errors.Is(gerr, spool.ErrOverflow) {
			return gerr
		}
		return errors.New("malformed EventList")
	}
	for i, item := range list.Items {
		if err := in.IngestRaw(item, fmt.Sprintf("%s item %d", where, i)); err != nil && !errors.Is(err, spool.ErrOverflow) {
			return err
		}
	}
	return nil
}
