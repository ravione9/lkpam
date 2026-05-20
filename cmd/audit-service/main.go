// audit-service exposes a write endpoint for any service to ship events to,
// and a query endpoint for the UI to read recent events. In production this
// is replaced with a Kafka consumer + ElasticSearch ingest pipeline.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"

	"github.com/example/pam-platform/internal/audit"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/httpx"
)

type record struct {
	TS       int64  `json:"ts"`
	Actor    string `json:"actor"`
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
}

type session struct {
	ID            string `json:"id"`
	UserID        int64  `json:"user_id"`
	TargetID      int64  `json:"target_id"`
	StartedAt     int64  `json:"started_at"`
	EndedAt       *int64 `json:"ended_at,omitempty"`
	RecordingPath string `json:"recording_path"`
	ClientIP      string `json:"client_ip"`
	EndedReason   string `json:"ended_reason"`
}

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("audit: db: %v", err)
	}
	defer d.Close()

	sink, err := audit.Open(d, config.Get("PAM_AUDIT_JSONL", "./data/audit.jsonl"))
	if err != nil {
		log.Fatalf("audit: open sink: %v", err)
	}
	defer sink.Close()

	mux := http.NewServeMux()

	mux.HandleFunc("POST /events", func(w http.ResponseWriter, r *http.Request) {
		var ev events.Event
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if err := sink.Write(r.Context(), ev); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusAccepted, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /events", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 1000 {
			limit = 200
		}
		rows, err := d.QueryContext(context.Background(), `
			SELECT ts, actor, kind, COALESCE(target,''), COALESCE(detail,''), severity
			FROM audit_events ORDER BY id DESC LIMIT ?`, limit)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		defer rows.Close()
		out := []record{}
		for rows.Next() {
			var rec record
			if err := rows.Scan(&rec.TS, &rec.Actor, &rec.Kind, &rec.Target, &rec.Detail, &rec.Severity); err == nil {
				out = append(out, rec)
			}
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("GET /sessions", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		rows, err := d.QueryContext(context.Background(), `
			SELECT id, user_id, target_id, started_at, ended_at,
			       COALESCE(recording_path,''), COALESCE(client_ip,''), COALESCE(ended_reason,'')
			FROM sessions ORDER BY started_at DESC LIMIT ?`, limit)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		defer rows.Close()
		out := []session{}
		for rows.Next() {
			var s session
			var ended sql.NullInt64
			if err := rows.Scan(&s.ID, &s.UserID, &s.TargetID, &s.StartedAt, &ended,
				&s.RecordingPath, &s.ClientIP, &s.EndedReason); err == nil {
				if ended.Valid {
					s.EndedAt = &ended.Int64
				}
				out = append(out, s)
			}
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	addr := config.Get("PAM_AUDIT_ADDR", ":8085")
	log.Printf("audit-service listening on %s", addr)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
