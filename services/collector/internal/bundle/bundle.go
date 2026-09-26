// Package bundle writes an afterlock.replay/1 bundle from spooled evidence
// and an inventory snapshot.
//
// The layout and checksums match packages/afterlock/evidence.py
// (ReplayBundle.load): manifest.json lists exactly inventory.json,
// events.jsonl and case.json with their SHA-256. Every file is checked by
// redact.Check before it is written; the writer fails closed.
package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rakshit-737/afterlock/services/collector/internal/inventory"
	"github.com/rakshit-737/afterlock/services/collector/internal/redact"
)

// Schema is the replay bundle schema identifier.
const Schema = "afterlock.replay/1"

// DefaultProfile is the semantic profile used when no case template is given.
const DefaultProfile = "k8s-1.31-core-v1"

// Options configures a bundle.
type Options struct {
	Dir, CaseID, ClusterID, SourceID string
	// Case is the analyst-authored case.json content. When nil, a case with no
	// objectives, no seeded compromise and this collector as required source
	// is written; it must be completed before analysis is meaningful.
	Case map[string]any
	Now  time.Time
	// CorrelationWindow bounds how long before an audit event's stage
	// timestamp a Pod's creationTimestamp may be for UID correlation.
	CorrelationWindow time.Duration
	SecretMetadata    bool
}

// Write assembles and writes the bundle.
func Write(opt Options, records []map[string]any, snap inventory.Snapshot, store *inventory.Store) error {
	if opt.CorrelationWindow == 0 {
		opt.CorrelationWindow = 10 * time.Second
	}
	now := opt.Now.UTC().Format(time.RFC3339)
	events := make([]map[string]any, 0, len(records)+8)
	var seq int64
	for _, r := range records {
		events = append(events, r)
		if n, ok := num(r["source_sequence"]); ok && n > seq {
			seq = n
		}
	}
	gapN := 0
	extra := func(rec map[string]any) {
		seq++
		rec["schema_version"] = "1"
		rec["source_id"] = opt.SourceID
		rec["cluster_id"] = opt.ClusterID
		rec["source_sequence"] = seq
		rec["event_id"] = fmt.Sprintf("%s-%d", opt.SourceID, seq)
		rec["observed_at"] = now
		rec["ingested_at"] = now
		events = append(events, rec)
	}
	gap := func(kind, reason string) {
		gapN++
		extra(map[string]any{"event_type": "collector.gap", "gap_kind": kind,
			"gap_id": fmt.Sprintf("%s:bundle:%s:%d", opt.SourceID, kind, gapN), "reason": redact.String(reason)})
	}

	for _, ev := range events[:len(records)] {
		correlate(ev, store, opt.CorrelationWindow, gap)
	}
	for _, k := range snap.Unsynced {
		gap("inventory-unsynced", fmt.Sprintf("inventory for %s never completed a list; it is missing from inventory.json", k))
	}
	for _, name := range snap.AdmissionPolicies {
		gap("admission-policy-unmodeled", fmt.Sprintf("ValidatingAdmissionPolicy %s was observed but its CEL rules are not translated; admission effects are not modeled", name))
	}
	for _, r := range snap.SkippedRules {
		gap("rbac-rule-unmodeled", fmt.Sprintf("%s has non-resource rules that are not modeled", r))
	}
	if !opt.SecretMetadata {
		gap("secret-metadata-disabled", "Secret metadata collection was disabled; Secret versions are not observed")
	}
	extra(map[string]any{"event_type": "collector.heartbeat"})

	caseDoc := opt.Case
	if caseDoc == nil {
		caseDoc = map[string]any{
			"profile":       DefaultProfile,
			"analysis_time": now,
			"description":   "Collector-produced bundle. Objectives, remediation and the seeded compromise must be supplied by the analyst.",
			"assumptions": []any{
				"No compromise is seeded; the case must be completed by an analyst before its result is meaningful.",
			},
			"compromised_credentials":        []any{},
			"objectives":                     []any{},
			"legitimate_operations":          []any{},
			"remediation":                    []any{},
			"required_sources":               []any{opt.SourceID},
			"max_evidence_staleness_seconds": 300,
		}
	}

	var ev bytes.Buffer
	for _, e := range events {
		line, err := marshal(e, false)
		if err != nil {
			return err
		}
		if p := redact.Check(line); len(p) > 0 {
			return fmt.Errorf("bundle: refusing to write event with credential material: %v", p)
		}
		ev.Write(line)
		ev.WriteByte('\n')
	}
	inv, err := marshal(snap.Inventory, true)
	if err != nil {
		return err
	}
	cs, err := marshal(caseDoc, true)
	if err != nil {
		return err
	}
	blobs := map[string][]byte{"inventory.json": append(inv, '\n'), "case.json": append(cs, '\n'), "events.jsonl": ev.Bytes()}
	for _, name := range []string{"inventory.json", "case.json"} {
		if p := redact.Check(blobs[name]); len(p) > 0 {
			return fmt.Errorf("bundle: refusing to write %s with credential material: %v", name, p)
		}
	}
	if err := os.MkdirAll(opt.Dir, 0o750); err != nil {
		return err
	}
	files := map[string]any{}
	names := []string{"case.json", "events.jsonl", "inventory.json"}
	for _, name := range names {
		sum := sha256.Sum256(blobs[name])
		files[name] = "sha256:" + hex.EncodeToString(sum[:])
		if err := os.WriteFile(filepath.Join(opt.Dir, name), blobs[name], 0o640); err != nil {
			return err
		}
	}
	manifest, err := marshal(map[string]any{"schema": Schema, "case_id": opt.CaseID, "cluster_id": opt.ClusterID, "files": files}, true)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(opt.Dir, "manifest.json"), append(manifest, '\n'), 0o640)
}

// correlate fills the UID of a Pod targeted by a successful create (or exec)
// from Pods observed by the inventory watch. The audit record alone does not
// carry it at Metadata level. Ambiguity or absence becomes a gap; a UID is
// never guessed from the name alone.
func correlate(ev map[string]any, store *inventory.Store, window time.Duration, gap func(string, string)) {
	if ev["event_type"] != "k8s.api.response" {
		return
	}
	action, _ := ev["action"].(map[string]any)
	target, _ := ev["target"].(map[string]any)
	outcome, _ := ev["outcome"].(map[string]any)
	if action == nil || target == nil || outcome == nil || action["verb"] != "create" {
		return
	}
	res, _ := action["resource"].(string)
	if res != "pods" && res != "pods/exec" {
		return
	}
	if code, ok := num(outcome["http_status"]); !ok || code < 200 || code >= 300 {
		return
	}
	if _, has := target["uid"]; has {
		return
	}
	ns, _ := action["namespace"].(string)
	name, _ := target["name"].(string)
	at, err := time.Parse(time.RFC3339, fmt.Sprint(ev["observed_at"]))
	if err != nil || ns == "" || name == "" {
		gap("pod-uncorrelated", fmt.Sprintf("%s: Pod target of a successful %s has no namespace/name to correlate", ev["event_id"], res))
		return
	}
	var match []inventory.Pod
	for _, p := range store.PodsNamed(ns, name) {
		created := p.Created.Truncate(time.Second)
		if res == "pods" && !created.Before(at.Add(-window)) && !created.After(at.Add(time.Second)) {
			match = append(match, p)
		}
		if res == "pods/exec" && !created.After(at.Add(time.Second)) {
			match = append(match, p)
		}
	}
	if len(match) != 1 {
		gap("pod-uncorrelated", fmt.Sprintf("%s: %d observed Pods match %s/%s for a successful %s; the target Pod UID is unknown", ev["event_id"], len(match), ns, name, res))
		return
	}
	target["uid"] = match[0].UID
	if res == "pods" {
		target["service_account"] = match[0].ServiceAccount
	}
	target["uid_source"] = "inventory-correlation"
}

func num(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

func marshal(v any, indent bool) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}
