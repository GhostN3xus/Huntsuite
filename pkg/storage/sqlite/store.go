package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Store implements a lightweight persistence layer that mimics a SQLite-backed store.
type Store struct {
	mu      sync.Mutex
	path    string
	data    *storeData
	nextIDs map[string]int64
}

type storeData struct {
	Targets   []Target   `json:"targets"`
	Scans     []Scan     `json:"scans"`
	Findings  []Finding  `json:"findings"`
	Requests  []Request  `json:"requests"`
	Responses []Response `json:"responses"`
}

// Open initialises the store and loads data from disk.
func Open(_ context.Context, path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	st := &Store{
		path:    path,
		data:    &storeData{},
		nextIDs: map[string]int64{},
	}
	if err := st.load(); err != nil {
		return nil, err
	}
	return st, nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.data = &storeData{}
		s.nextIDs = map[string]int64{}
		return nil
	} else if err != nil {
		return err
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	if err := dec.Decode(&s.data); err != nil {
		return err
	}

	s.reindex()
	return nil
}

func (s *Store) reindex() {
	s.nextIDs = map[string]int64{}
	update := func(kind string, current int64) {
		if current > s.nextIDs[kind] {
			s.nextIDs[kind] = current
		}
	}
	for _, t := range s.data.Targets {
		update("targets", t.ID)
	}
	for _, sc := range s.data.Scans {
		update("scans", sc.ID)
	}
	for _, f := range s.data.Findings {
		update("findings", f.ID)
	}
	for _, r := range s.data.Requests {
		update("requests", r.ID)
	}
	for _, r := range s.data.Responses {
		update("responses", r.ID)
	}
}

func (s *Store) persist() error {
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(s.data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Close satisfies the interface for resource cleanup.
func (s *Store) Close() error { return nil }

// Target represents a scanning target.
type Target struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Scope     *string   `json:"scope,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Scan represents a scan execution.
type Scan struct {
	ID          int64      `json:"id"`
	TargetID    int64      `json:"target_id"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	Summary     *string    `json:"summary,omitempty"`
	Options     *string    `json:"options,omitempty"`
}

// Finding represents an identified vulnerability.
type Finding struct {
	ID          int64     `json:"id"`
	ScanID      int64     `json:"scan_id"`
	Title       string    `json:"title"`
	Type        string    `json:"type"`
	Severity    string    `json:"severity"`
	CVSS        *float64  `json:"cvss,omitempty"`
	Description *string   `json:"description,omitempty"`
	Evidence    *string   `json:"evidence,omitempty"`
	PoC         *string   `json:"poc,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Request represents an HTTP request issued during scanning.
type Request struct {
	ID        int64     `json:"id"`
	ScanID    *int64    `json:"scan_id,omitempty"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Headers   string    `json:"headers"`
	Body      []byte    `json:"body"`
	Timestamp time.Time `json:"timestamp"`
}

// Response represents the HTTP response to a stored request.
type Response struct {
	ID        int64     `json:"id"`
	RequestID int64     `json:"request_id"`
	Status    *int      `json:"status,omitempty"`
	Headers   string    `json:"headers"`
	Body      []byte    `json:"body"`
	LatencyMs int64     `json:"latency_ms"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Store) next(kind string) int64 {
	s.nextIDs[kind]++
	return s.nextIDs[kind]
}

// UpsertTarget ensures a target exists and returns its identifier.
func (s *Store) UpsertTarget(ctx context.Context, name, scope string) (int64, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.data.Targets {
		if t.Name == name {
			return t.ID, nil
		}
	}
	id := s.next("targets")
	var scopePtr *string
	if scope != "" {
		scopePtr = &scope
	}
	target := Target{ID: id, Name: name, Scope: scopePtr, CreatedAt: time.Now()}
	s.data.Targets = append(s.data.Targets, target)
	if err := s.persist(); err != nil {
		return 0, err
	}
	return id, nil
}

// CreateScan inserts a new scan row.
func (s *Store) CreateScan(ctx context.Context, targetID int64, status, options string) (int64, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.next("scans")
	var optPtr *string
	if options != "" {
		opt := options
		optPtr = &opt
	}
	scan := Scan{ID: id, TargetID: targetID, Status: status, StartedAt: time.Now(), Options: optPtr}
	s.data.Scans = append(s.data.Scans, scan)
	if err := s.persist(); err != nil {
		return 0, err
	}
	return id, nil
}

// UpdateScanStatus updates the status/summary fields.
func (s *Store) UpdateScanStatus(ctx context.Context, scanID int64, status, summary string, completed bool) error {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, sc := range s.data.Scans {
		if sc.ID == scanID {
			s.data.Scans[i].Status = status
			if summary != "" {
				sum := summary
				s.data.Scans[i].Summary = &sum
			}
			if completed {
				now := time.Now()
				s.data.Scans[i].CompletedAt = &now
			}
			break
		}
	}
	return s.persist()
}

// InsertFinding stores a vulnerability finding.
func (s *Store) InsertFinding(ctx context.Context, f *Finding) (int64, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.next("findings")
	finding := *f
	finding.ID = id
	finding.CreatedAt = time.Now()
	s.data.Findings = append(s.data.Findings, finding)
	if err := s.persist(); err != nil {
		return 0, err
	}
	return id, nil
}

// RecordRequest persists a request and returns its identifier.
func (s *Store) RecordRequest(ctx context.Context, scanID int64, method, url, headers string, body []byte) (int64, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.next("requests")
	var scanPtr *int64
	if scanID != 0 {
		sid := scanID
		scanPtr = &sid
	}
	req := Request{ID: id, ScanID: scanPtr, Method: method, URL: url, Headers: headers, Body: append([]byte(nil), body...), Timestamp: time.Now()}
	s.data.Requests = append(s.data.Requests, req)
	if err := s.persist(); err != nil {
		return 0, err
	}
	return id, nil
}

// RecordResponse stores the associated response payload.
func (s *Store) RecordResponse(ctx context.Context, requestID int64, status int, headers string, body []byte, latency time.Duration) (int64, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.next("responses")
	var statusPtr *int
	if status != 0 {
		st := status
		statusPtr = &st
	}
	resp := Response{ID: id, RequestID: requestID, Status: statusPtr, Headers: headers, Body: append([]byte(nil), body...), LatencyMs: latency.Milliseconds(), CreatedAt: time.Now()}
	s.data.Responses = append(s.data.Responses, resp)
	if err := s.persist(); err != nil {
		return 0, err
	}
	return id, nil
}

// FindingsByScan lists stored findings for a scan.
func (s *Store) FindingsByScan(ctx context.Context, scanID int64) ([]Finding, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	var results []Finding
	for _, f := range s.data.Findings {
		if f.ScanID == scanID {
			results = append(results, f)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].CreatedAt.Before(results[j].CreatedAt) })
	return results, nil
}

// ScansForTarget returns scan history for a target.
func (s *Store) ScansForTarget(ctx context.Context, targetID int64) ([]Scan, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	var results []Scan
	for _, sc := range s.data.Scans {
		if sc.TargetID == targetID {
			results = append(results, sc)
		}
	}
	sort.Slice(results, func(i, j int) bool { return results[i].StartedAt.After(results[j].StartedAt) })
	return results, nil
}

// GetScan fetches a scan by identifier.
func (s *Store) GetScan(ctx context.Context, scanID int64) (*Scan, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, sc := range s.data.Scans {
		if sc.ID == scanID {
			copy := sc
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("scan %d not found", scanID)
}

// GetTarget fetches a target by identifier.
func (s *Store) GetTarget(ctx context.Context, id int64) (*Target, error) {
	_ = ctx
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.data.Targets {
		if t.ID == id {
			copy := t
			return &copy, nil
		}
	}
	return nil, fmt.Errorf("target %d not found", id)
}
