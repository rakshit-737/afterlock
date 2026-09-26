// Package spool is the collector's bounded, append-only local evidence spool.
//
// Each record is one evidence envelope (a JSON object, one per line). The
// spool assigns the per-source monotonically increasing source_sequence and
// enforces byte and record limits. When a limit is reached, new records are
// dropped, an overflow alarm fires, and an explicit collector.gap record is
// written into capacity reserved for exactly that purpose, so loss is never
// silent. Reopening an existing spool resumes the sequence and the audit-ID
// deduplication set, and records the restart itself as a gap.
package spool

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/rakshit-737/afterlock/services/collector/internal/redact"
)

// ErrOverflow is returned when a record is dropped because the spool is full.
var ErrOverflow = errors.New("spool: capacity exhausted; record dropped")

// ErrDuplicate is returned when a record's dedup key was already spooled.
var ErrDuplicate = errors.New("spool: duplicate record")

const (
	reservedRecords = 2
	reservedBytes   = 4096
	maxLineBytes    = 64 * 1024 // mirrors evidence.MAX_LINE_BYTES
)

// Options configures a spool.
type Options struct {
	Path       string
	MaxBytes   int64
	MaxRecords int
	SourceID   string
	ClusterID  string
	Now        func() time.Time
	// OnOverflow is the overflow alarm. It is called once per overflow episode.
	OnOverflow func(dropped int64)
}

// Spool is safe for concurrent use.
type Spool struct {
	mu        sync.Mutex
	opt       Options
	f         *os.File
	size      int64
	records   []map[string]any
	seen      map[string]bool
	seq       int64
	gapSeq    int64
	dropped   int64
	overflow  bool
	summaryOK bool
}

// Stats is a snapshot of spool health for metrics.
type Stats struct {
	Records    int
	Bytes      int64
	Dropped    int64
	Overflowed bool
}

// Open opens or creates the spool at opt.Path.
func Open(opt Options) (*Spool, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	if opt.MaxBytes <= reservedBytes || opt.MaxRecords <= reservedRecords {
		return nil, fmt.Errorf("spool: limits too small (need > %d bytes and > %d records)", reservedBytes, reservedRecords)
	}
	s := &Spool{opt: opt, seen: map[string]bool{}}
	existing, err := os.ReadFile(opt.Path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// A restart is detected from the spool file already existing, not from it holding
	// records: a collector killed before writing anything must still leave a gap.
	restarted := err == nil
	truncated := false
	if len(existing) > 0 {
		n := parseExisting(existing, s)
		truncated = n < len(existing)
		existing = existing[:n]
	}
	f, err := os.OpenFile(opt.Path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Truncate(int64(len(existing))); err != nil {
		_ = f.Close()
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		_ = f.Close()
		return nil, err
	}
	s.f = f
	s.size = int64(len(existing))
	if restarted {
		reason := "collector restarted with an existing spool; events emitted while it was not running may be missing"
		if truncated {
			reason += "; a partially written trailing record was discarded"
		}
		if err := s.gapLocked("collector-restart", reason); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// parseExisting adopts every complete record and returns the byte length of
// the valid prefix; anything after it (a torn write) is discarded.
func parseExisting(data []byte, s *Spool) int {
	offset := 0
	for offset < len(data) {
		nl := bytes.IndexByte(data[offset:], '\n')
		if nl < 0 {
			break // partial trailing line
		}
		line := data[offset : offset+nl]
		var rec map[string]any
		if json.Unmarshal(line, &rec) != nil {
			break
		}
		s.adopt(rec)
		offset += nl + 1
	}
	return offset
}

func (s *Spool) adopt(rec map[string]any) {
	s.records = append(s.records, rec)
	if n, ok := rec["source_sequence"].(float64); ok && int64(n) > s.seq {
		s.seq = int64(n)
	}
	if k, ok := rec["_dedup"].(string); ok {
		s.seen[k] = true
	}
	if rec["event_type"] == "collector.gap" {
		s.gapSeq++
	}
}

// Append spools rec. dedupKey (may be empty) suppresses duplicate delivery.
// The spool sets schema_version, source_id, cluster_id, source_sequence and
// event_id (if absent). It returns the assigned sequence.
func (s *Spool) Append(rec map[string]any, dedupKey string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if dedupKey != "" && s.seen[dedupKey] {
		return 0, ErrDuplicate
	}
	if s.full(0) {
		s.dropped++
		if !s.overflow {
			s.overflow = true
			if s.opt.OnOverflow != nil {
				s.opt.OnOverflow(s.dropped)
			}
			if err := s.gapLocked("spool-overflow", fmt.Sprintf("local spool reached its limit (%d records, %d bytes); subsequent evidence is dropped", s.opt.MaxRecords, s.opt.MaxBytes)); err != nil {
				return 0, err
			}
		}
		return 0, ErrOverflow
	}
	if dedupKey != "" {
		rec["_dedup"] = dedupKey
	}
	seq, err := s.writeLocked(rec)
	if err != nil {
		return 0, err
	}
	if dedupKey != "" {
		s.seen[dedupKey] = true
	}
	return seq, nil
}

// Gap appends an explicit collector.gap record. Gaps may use reserved capacity.
func (s *Spool) Gap(kind, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gapLocked(kind, reason)
}

func (s *Spool) gapLocked(kind, reason string) error {
	if s.full(reservedRecords) {
		// Even the reserve is exhausted: count it; the summary gap written by
		// Close carries the total.
		s.dropped++
		return ErrOverflow
	}
	s.gapSeq++
	rec := map[string]any{
		"event_type":  "collector.gap",
		"gap_id":      fmt.Sprintf("%s:%s:%d", s.opt.SourceID, kind, s.gapSeq),
		"gap_kind":    kind,
		"reason":      redact.String(reason),
		"observed_at": s.opt.Now().UTC().Format(time.RFC3339),
	}
	_, err := s.writeLocked(rec)
	return err
}

// full reports whether writing one more record would eat into the reserve.
// reserveUse is how much of the reserve the caller may use.
func (s *Spool) full(reserveUse int) bool {
	recLimit := s.opt.MaxRecords - reservedRecords + reserveUse
	byteLimit := s.opt.MaxBytes - reservedBytes
	if reserveUse > 0 {
		byteLimit = s.opt.MaxBytes - 512
	}
	return len(s.records) >= recLimit || s.size >= byteLimit
}

func (s *Spool) writeLocked(rec map[string]any) (int64, error) {
	s.seq++
	rec["schema_version"] = "1"
	rec["source_id"] = s.opt.SourceID
	rec["cluster_id"] = s.opt.ClusterID
	rec["source_sequence"] = s.seq
	if _, ok := rec["event_id"]; !ok {
		rec["event_id"] = fmt.Sprintf("%s-%d", s.opt.SourceID, s.seq)
	}
	if _, ok := rec["ingested_at"]; !ok {
		rec["ingested_at"] = s.opt.Now().UTC().Format(time.RFC3339)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		s.seq--
		return 0, err
	}
	if len(line)+1 > maxLineBytes {
		s.seq--
		return 0, fmt.Errorf("spool: record exceeds %d bytes", maxLineBytes)
	}
	if problems := redact.Check(line); len(problems) > 0 {
		s.seq--
		return 0, fmt.Errorf("spool: refusing record with credential material: %v", problems)
	}
	line = append(line, '\n')
	if _, err := s.f.Write(line); err != nil {
		s.seq--
		return 0, err
	}
	// Round-trip so in-memory records match what a reopened spool would hold.
	var stored map[string]any
	_ = json.Unmarshal(line, &stored)
	s.records = append(s.records, stored)
	s.size += int64(len(line))
	return s.seq, nil
}

// Sync flushes the spool to stable storage.
func (s *Spool) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Sync()
}

// Stats returns a health snapshot.
func (s *Spool) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Stats{Records: len(s.records), Bytes: s.size, Dropped: s.dropped, Overflowed: s.overflow}
}

// Records returns spooled envelopes ordered by source_sequence, without
// internal bookkeeping fields. If records were dropped, a summary gap with the
// final drop count is appended first (it uses reserved capacity).
func (s *Spool) Records() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dropped > 0 && !s.summaryOK {
		s.summaryOK = true
		_ = s.gapLocked("spool-overflow-summary", fmt.Sprintf("%d evidence records were dropped because the local spool was full", s.dropped))
	}
	out := make([]map[string]any, 0, len(s.records))
	for _, r := range s.records {
		// Deep copy so callers cannot mutate spooled state.
		var c map[string]any
		b, _ := json.Marshal(r)
		_ = json.Unmarshal(b, &c)
		delete(c, "_dedup")
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := out[i]["source_sequence"].(float64)
		b, _ := out[j]["source_sequence"].(float64)
		return a < b
	})
	return out
}

// Close syncs and closes the spool file.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Sync()
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	s.f = nil
	return err
}

// ReadLines is a helper for tests and tools: it returns the spool's lines.
func ReadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}
