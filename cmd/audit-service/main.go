// audit-service exposes a write endpoint for any service to ship events to,
// and a query endpoint for the UI to read recent events. In production this
// is replaced with a Kafka consumer + ElasticSearch ingest pipeline.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/example/pam-platform/internal/audit"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/httpx"
	"github.com/example/pam-platform/internal/sessions"
	"github.com/example/pam-platform/internal/vault"
)

func errStr(s string) error { return errors.New(s) }

const (
	pendingSessionTimeoutSeconds = 120
	webSessionIdleTimeoutSeconds = 30 * 60 // web tabs closed without End still need cleanup
)

type record struct {
	TS       int64  `json:"ts"`
	Actor    string `json:"actor"`
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	Detail   string `json:"detail"`
	Severity string `json:"severity"`
	Source   string `json:"source"`
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
	Protocol      string `json:"protocol,omitempty"`
}

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("audit: db: %v", err)
	}
	defer d.Close()

	v, err := vault.New(d, config.Get("PAM_MASTER_KEY", ""))
	if err != nil {
		log.Fatalf("audit: vault: %v", err)
	}

	sink, err := audit.Open(d, config.Get("PAM_AUDIT_JSONL", "./data/audit.jsonl"))
	if err != nil {
		log.Fatalf("audit: open sink: %v", err)
	}
	defer sink.Close()

	mux := http.NewServeMux()
	httpx.RegisterHealth(mux)

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
		q := r.URL.Query()
		conds := []string{}
		args := []any{}
		if srcs := strings.TrimSpace(q.Get("source")); srcs != "" {
			parts := strings.Split(srcs, ",")
			placeholders := []string{}
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				placeholders = append(placeholders, "?")
				args = append(args, p)
			}
			if len(placeholders) > 0 {
				conds = append(conds, "source IN ("+strings.Join(placeholders, ",")+")")
			}
		}
		if sev := strings.TrimSpace(q.Get("severity")); sev != "" {
			conds = append(conds, "severity = ?")
			args = append(args, sev)
		}
		if since := strings.TrimSpace(q.Get("since")); since != "" {
			if v, err := strconv.ParseInt(since, 10, 64); err == nil {
				conds = append(conds, "ts >= ?")
				args = append(args, v)
			}
		}
		where := ""
		if len(conds) > 0 {
			where = "WHERE " + strings.Join(conds, " AND ")
		}
		args = append(args, limit)
		rows, err := d.QueryContext(context.Background(), `
			SELECT ts, actor, kind, COALESCE(target,''), COALESCE(detail,''), severity, COALESCE(source,'')
			FROM audit_events `+where+` ORDER BY id DESC LIMIT ?`, args...)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		defer rows.Close()
		out := []record{}
		for rows.Next() {
			var rec record
			if err := rows.Scan(&rec.TS, &rec.Actor, &rec.Kind, &rec.Target, &rec.Detail, &rec.Severity, &rec.Source); err == nil {
				out = append(out, rec)
			}
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("GET /event-sources", func(w http.ResponseWriter, r *http.Request) {
		rows, err := d.QueryContext(r.Context(), `
			SELECT DISTINCT source FROM audit_events WHERE source != '' ORDER BY source`)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		defer rows.Close()
		out := []string{}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err == nil {
				out = append(out, s)
			}
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	// POST /sessions/{id}/terminate — admin requests termination (SSH proxy or RDP proxy polls).
	mux.HandleFunc("POST /sessions/{id}/terminate", func(w http.ResponseWriter, r *http.Request) {
		uidStr := r.Header.Get("X-PAM-UID")
		role := r.Header.Get("X-PAM-Role")
		uid, _ := strconv.ParseInt(uidStr, 10, 64)
		if role != "admin" {
			httpx.Error(w, http.StatusForbidden,
				errStr("admin role required"))
			return
		}
		sid := r.PathValue("id")
		var req struct {
			Reason string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		// Confirm session exists and is active.
		var ended sql.NullInt64
		var ownerID int64
		var protocol string
		err := d.QueryRowContext(r.Context(),
			`SELECT ended_at, user_id, COALESCE(protocol,'') FROM sessions WHERE id = ?`, sid).
			Scan(&ended, &ownerID, &protocol)
		if err == sql.ErrNoRows {
			httpx.Error(w, http.StatusNotFound, errStr("session not found"))
			return
		}
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		if ended.Valid {
			httpx.Error(w, http.StatusConflict, errStr("session already ended"))
			return
		}
		if role != "admin" {
			if uid <= 0 || ownerID != uid {
				httpx.Error(w, http.StatusForbidden, errStr("admin role required"))
				return
			}
			if protocol != "web" {
				httpx.Error(w, http.StatusForbidden, errStr("only web sessions can be ended by the owner"))
				return
			}
		}
		if _, err := d.ExecContext(r.Context(), `
			INSERT INTO session_terminations(session_id, requested_by, requested_at, reason)
			VALUES(?,?,?,?)
			ON CONFLICT(session_id) DO UPDATE SET
			  requested_by=excluded.requested_by,
			  requested_at=excluded.requested_at,
			  reason=excluded.reason`,
			sid, uid, db.Now(), req.Reason); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		// Immediately mark the session as terminated so the UI updates even
		// when no proxy is actively polling (e.g. dangling native sessions).
		// The proxy that owns an active tunnel will still kill the live process
		// within ~5s via its own poller, then acknowledge the row.
		_, _ = sessions.End(r.Context(), d, v, sid, "terminated")
		// Best-effort audit row.
		_, _ = d.ExecContext(r.Context(), `
			INSERT INTO audit_events(ts, actor, kind, target, detail, severity)
			VALUES(?,?,?,?,?,?)`,
			db.Now(), r.Header.Get("X-PAM-User"), "session.terminate.requested",
			sid, req.Reason, "warn")
		httpx.JSON(w, http.StatusAccepted, map[string]string{"status": "requested"})
	})

	mux.HandleFunc("GET /sessions/terminations", func(w http.ResponseWriter, r *http.Request) {
		// SSH proxy polls this endpoint to discover sessions it must kill.
		rows, err := d.QueryContext(r.Context(), `
			SELECT session_id, requested_by, requested_at, reason
			FROM session_terminations
			WHERE acknowledged_at IS NULL`)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		defer rows.Close()
		type term struct {
			SessionID   string `json:"session_id"`
			RequestedBy int64  `json:"requested_by"`
			RequestedAt int64  `json:"requested_at"`
			Reason      string `json:"reason"`
		}
		out := []term{}
		for rows.Next() {
			var t term
			if err := rows.Scan(&t.SessionID, &t.RequestedBy, &t.RequestedAt, &t.Reason); err == nil {
				out = append(out, t)
			}
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("POST /sessions/terminations/{id}/ack", func(w http.ResponseWriter, r *http.Request) {
		sid := r.PathValue("id")
		_, err := d.ExecContext(r.Context(),
			`UPDATE session_terminations SET acknowledged_at=? WHERE session_id=?`,
			db.Now(), sid)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /sessions", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if limit <= 0 || limit > 500 {
			limit = 100
		}
		cleanupPendingSessions(r.Context(), d, v)
		rows, err := d.QueryContext(context.Background(), `
			SELECT id, user_id, target_id, started_at, ended_at,
			       COALESCE(recording_path,''), COALESCE(client_ip,''), COALESCE(ended_reason,''),
			       COALESCE(protocol,'ssh')
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
				&s.RecordingPath, &s.ClientIP, &s.EndedReason, &s.Protocol); err == nil {
				if ended.Valid {
					s.EndedAt = &ended.Int64
				}
				out = append(out, s)
			}
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("GET /sessions/{id}/recording", func(w http.ResponseWriter, r *http.Request) {
		sid := r.PathValue("id")
		var recPath string
		err := d.QueryRowContext(r.Context(),
			`SELECT COALESCE(recording_path,'') FROM sessions WHERE id = ?`, sid).Scan(&recPath)
		if err == sql.ErrNoRows {
			httpx.Error(w, http.StatusNotFound, errStr("session not found"))
			return
		}
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		if recPath == "" {
			httpx.Error(w, http.StatusNotFound, errStr("no recording for this session"))
			return
		}
		file, err := resolveRecordingFile(recPath)
		if err != nil {
			httpx.Error(w, http.StatusNotFound, errStr(err.Error()))
			return
		}
		ext := filepath.Ext(file)
		switch ext {
		case ".guac":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(file)+`"`)
		case ".log":
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			if r.URL.Query().Get("download") == "1" {
				w.Header().Set("Content-Disposition", `attachment; filename="`+filepath.Base(file)+`"`)
			}
		default:
			httpx.Error(w, http.StatusNotFound, errStr("unsupported recording format"))
			return
		}
		http.ServeFile(w, r, file)
	})

	addr := config.Get("PAM_AUDIT_ADDR", ":8085")
	log.Printf("audit-service listening on %s", addr)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

// cleanupPendingSessions marks browser-launched sessions as failed when the
// viewer/proxy never produced a recording. These rows are created before
// guacd proves the target connection works, so failed launches can otherwise
// sit in the UI as "active" forever.
func cleanupPendingSessions(ctx context.Context, d *db.DB, v *vault.Vault) {
	cutoff := db.Now() - pendingSessionTimeoutSeconds
	rows, err := d.QueryContext(ctx, `
		SELECT id, COALESCE(recording_path,'')
		  FROM sessions
		 WHERE ended_at IS NULL
		   AND started_at <= ?
		   AND COALESCE(recording_path,'') != ''
		   AND COALESCE(protocol,'ssh') IN ('ssh','rdp')`,
		cutoff)
	if err != nil {
		return
	}
	defer rows.Close()

	type pending struct {
		id, recPath string
	}
	var stale []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.id, &p.recPath); err != nil {
			continue
		}
		if pendingRecordingMissing(p.recPath) {
			stale = append(stale, p)
		}
	}
	for _, p := range stale {
		_, _ = sessions.End(ctx, d, v, p.id, "failed")
		_, _ = d.ExecContext(ctx, `
			INSERT INTO audit_events(ts, actor, kind, target, detail, severity)
			VALUES(?,?,?,?,?,?)`,
			db.Now(), "audit", "session.auto.failed", p.id,
			"no browser recording/connection appeared before timeout", "warn")
	}

	webRows, err := d.QueryContext(ctx, `
		SELECT id, started_at FROM sessions
		 WHERE ended_at IS NULL AND COALESCE(protocol,'') = 'web'`)
	if err != nil {
		return
	}
	defer webRows.Close()
	webCutoff := db.Now() - webSessionIdleTimeoutSeconds
	for webRows.Next() {
		var id string
		var started int64
		if err := webRows.Scan(&id, &started); err != nil {
			continue
		}
		_, vaultErr := v.GetSecret(ctx, sessions.WebVaultSecretName(id))
		reason := ""
		if vaultErr != nil {
			reason = "orphaned"
		} else if started <= webCutoff {
			reason = "idle"
		}
		if reason == "" {
			continue
		}
		if ok, _ := sessions.End(ctx, d, v, id, reason); ok {
			_, _ = d.ExecContext(ctx, `
				INSERT INTO audit_events(ts, actor, kind, target, detail, severity)
				VALUES(?,?,?,?,?,?)`,
				db.Now(), "audit", "session.auto."+reason, id,
				"web session cleaned up ("+reason+")", "info")
		}
	}
}

// resolveRecordingFile maps a session recording_path to a readable file on disk.
// Supports native SSH .log files and browser RDP/SSH .guac recordings in a directory.
func resolveRecordingFile(recPath string) (string, error) {
	info, err := os.Stat(recPath)
	if err != nil {
		return "", errors.New("recording file not found on disk")
	}
	if !info.IsDir() {
		ext := filepath.Ext(recPath)
		if ext == ".log" || ext == ".guac" {
			return recPath, nil
		}
		return "", errors.New("unsupported recording format")
	}
	entries, _ := os.ReadDir(recPath)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if ext := filepath.Ext(e.Name()); ext == ".guac" || ext == ".log" {
			return filepath.Join(recPath, e.Name()), nil
		}
	}
	return "", errors.New("recording not ready yet — session may still be active")
}

func pendingRecordingMissing(recPath string) bool {
	info, err := os.Stat(recPath)
	if err != nil {
		return true
	}
	if !info.IsDir() {
		return false
	}
	entries, err := os.ReadDir(recPath)
	if err != nil {
		return true
	}
	for _, e := range entries {
		if !e.IsDir() {
			ext := filepath.Ext(e.Name())
			if ext == ".guac" || ext == ".log" {
				return false
			}
		}
	}
	return true
}
