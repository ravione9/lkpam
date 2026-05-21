// Package audit persists immutable audit events. Two sinks: SQLite for query
// and a JSONL file on disk for shipping to SIEM (Splunk, Elastic, etc.).
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
)

// Sink writes audit events to disk + DB.
type Sink struct {
	DB       *db.DB
	JSONPath string
	mu       sync.Mutex
	f        *os.File
}

// Open prepares the JSONL file for append.
func Open(d *db.DB, jsonPath string) (*Sink, error) {
	if err := os.MkdirAll(filepath.Dir(jsonPath), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(jsonPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit: open jsonl: %w", err)
	}
	return &Sink{DB: d, JSONPath: jsonPath, f: f}, nil
}

// Close flushes and closes the file handle.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// Write persists one event to both sinks.
func (s *Sink) Write(ctx context.Context, ev events.Event) error {
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	if ev.Severity == "" {
		ev.Severity = "info"
	}

	// DB sink
	detailJSON, _ := json.Marshal(ev.Detail)
	if _, err := s.DB.ExecContext(ctx, `
		INSERT INTO audit_events(ts, actor, kind, target, detail, severity, source)
		VALUES(?,?,?,?,?,?,?)`,
		ev.Time.Unix(), ev.Actor, ev.Kind, ev.Target, string(detailJSON), ev.Severity, ev.Source); err != nil {
		return fmt.Errorf("audit: db write: %w", err)
	}

	// JSONL sink (append-only)
	s.mu.Lock()
	defer s.mu.Unlock()
	line, _ := json.Marshal(ev)
	if _, err := s.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: file write: %w", err)
	}
	return nil
}

// Consume subscribes to the bus and writes every event.
func (s *Sink) Consume(ctx context.Context, bus events.Publisher) {
	ch := bus.Subscribe()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			if err := s.Write(ctx, ev); err != nil {
				// log only; never lose events to a downstream failure
				fmt.Fprintf(os.Stderr, "audit consume: %v\n", err)
			}
		}
	}
}
