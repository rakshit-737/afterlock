package spool

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func open(t *testing.T, path string, maxRecords int, alarms *int) *Spool {
	t.Helper()
	s, err := Open(Options{Path: path, MaxBytes: 1 << 20, MaxRecords: maxRecords, SourceID: "src", ClusterID: "c",
		Now:        func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) },
		OnOverflow: func(int64) { *alarms++ }})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func rec() map[string]any {
	return map[string]any{"event_type": "k8s.api.response", "observed_at": "2026-01-01T00:00:00Z"}
}

func TestDuplicateDeliveryIsHarmless(t *testing.T) {
	alarms := 0
	s := open(t, filepath.Join(t.TempDir(), "s.jsonl"), 10, &alarms)
	defer s.Close()
	if _, err := s.Append(rec(), "audit:x"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Append(rec(), "audit:x"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("second append err = %v, want ErrDuplicate", err)
	}
	if n := len(s.Records()); n != 1 {
		t.Fatalf("records = %d, want 1", n)
	}
}

func TestOverflowRaisesAlarmAndRecordsGaps(t *testing.T) {
	alarms := 0
	s := open(t, filepath.Join(t.TempDir(), "s.jsonl"), 5, &alarms)
	defer s.Close()
	accepted, dropped := 0, 0
	for i := 0; i < 10; i++ {
		_, err := s.Append(rec(), "")
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrOverflow):
			dropped++
		default:
			t.Fatal(err)
		}
	}
	if accepted != 3 || dropped != 7 || alarms != 1 {
		t.Fatalf("accepted=%d dropped=%d alarms=%d, want 3/7/1", accepted, dropped, alarms)
	}
	recs := s.Records()
	var kinds []string
	for _, r := range recs {
		if r["event_type"] == "collector.gap" {
			kinds = append(kinds, r["gap_kind"].(string))
		}
	}
	if strings.Join(kinds, ",") != "spool-overflow,spool-overflow-summary" {
		t.Fatalf("gap kinds = %v", kinds)
	}
	if last := recs[len(recs)-1]["reason"].(string); !strings.HasPrefix(last, "7 evidence records were dropped") {
		t.Fatalf("summary reason = %q", last)
	}
	if st := s.Stats(); !st.Overflowed || st.Dropped != 7 {
		t.Fatalf("stats = %+v", st)
	}
}

func TestRestartResumesSequenceAndDedupAndRecordsGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	alarms := 0
	s := open(t, path, 100, &alarms)
	for _, k := range []string{"audit:a", "audit:b"} {
		if _, err := s.Append(rec(), k); err != nil {
			t.Fatal(err)
		}
	}
	_ = s.Close()
	// Simulate a torn write at crash time.
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString(`{"event_type":"k8s.api`)
	_ = f.Close()

	s = open(t, path, 100, &alarms)
	defer s.Close()
	if _, err := s.Append(rec(), "audit:a"); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("dedup not restored across restart: %v", err)
	}
	seq, err := s.Append(rec(), "audit:c")
	if err != nil || seq != 4 { // 1,2 = a,b; 3 = restart gap
		t.Fatalf("seq = %d err = %v, want 4", seq, err)
	}
	recs := s.Records()
	gap := recs[2]
	if gap["gap_kind"] != "collector-restart" || !strings.Contains(gap["reason"].(string), "partially written") {
		t.Fatalf("restart gap = %v", gap)
	}
	for _, r := range recs {
		if _, ok := r["_dedup"]; ok {
			t.Fatal("internal field leaked from Records")
		}
	}
	lines, _ := ReadLines(path)
	if len(lines) != 4 {
		t.Fatalf("spool has %d lines, want 4 (torn tail discarded)", len(lines))
	}
}

func TestRefusesCredentialMaterial(t *testing.T) {
	alarms := 0
	s := open(t, filepath.Join(t.TempDir(), "s.jsonl"), 10, &alarms)
	defer s.Close()
	r := rec()
	r["target"] = map[string]any{"name": "AFTERLOCK-CANARY-leak"}
	if _, err := s.Append(r, ""); err == nil {
		t.Fatal("spool accepted a canary value")
	}
	r = rec()
	r["data"] = "x"
	if _, err := s.Append(r, ""); err == nil {
		t.Fatal("spool accepted a forbidden key")
	}
}

// Regression (live lab, 2026-09-26): a collector killed before it wrote any record left an
// empty spool, and the restart went unrecorded.
func TestRestartWithEmptySpoolStillRecordsGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.jsonl")
	alarms := 0
	s := open(t, path, 100, &alarms)
	_ = s.Close()

	s = open(t, path, 100, &alarms)
	defer s.Close()
	recs := s.Records()
	if len(recs) != 1 || recs[0]["gap_kind"] != "collector-restart" {
		t.Fatalf("records after restart = %v, want one collector-restart gap", recs)
	}
}

func TestFirstStartRecordsNoRestartGap(t *testing.T) {
	alarms := 0
	s := open(t, filepath.Join(t.TempDir(), "s.jsonl"), 100, &alarms)
	defer s.Close()
	if n := len(s.Records()); n != 0 {
		t.Fatalf("fresh spool has %d records, want 0", n)
	}
}
