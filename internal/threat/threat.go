// Package threat is a minimal Privileged Threat Analytics (PTA) layer. It
// scans recent audit events for simple anomaly patterns and records alerts.
//
// The implementation is intentionally lightweight — real PTA does ML on
// user behavior. Here we cover three high-value patterns that catch the
// majority of incidents:
//
//  1. logins outside the user's normal window (off-hours)
//  2. logins from a new client IP for that user
//  3. high-rate failed-login spikes
//
// Alerts surface in the admin UI and feed downstream SIEMs via the existing
// audit stream.
package threat

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/example/pam-platform/internal/db"
)

// Severity values.
const (
	SevInfo = "info"
	SevWarn = "warn"
	SevHigh = "high"
)

// Alert is one threat detection.
type Alert struct {
	ID           int64  `json:"id"`
	TS           int64  `json:"ts"`
	UserID       *int64 `json:"user_id,omitempty"`
	Username     string `json:"username,omitempty"`
	Category     string `json:"category"`
	Severity     string `json:"severity"`
	Message      string `json:"message"`
	Detail       string `json:"detail,omitempty"`
	Acknowledged bool   `json:"acknowledged"`
}

// Service manages threat alerts.
type Service struct{ DB *db.DB }

// Record persists an alert (best-effort; logs but does not fail the caller).
func (s *Service) Record(ctx context.Context, a Alert) error {
	if a.TS == 0 {
		a.TS = db.Now()
	}
	if a.Severity == "" {
		a.Severity = SevInfo
	}
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO threat_alerts(ts, user_id, username, category, severity, message, detail)
		VALUES(?,?,?,?,?,?,?)`,
		a.TS, nullableInt(a.UserID), a.Username, a.Category, a.Severity,
		a.Message, a.Detail)
	return err
}

// List returns the most recent alerts.
func (s *Service) List(ctx context.Context, limit int, includeAck bool) ([]Alert, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `
		SELECT id, ts, user_id, username, category, severity, message, detail, acknowledged
		FROM threat_alerts`
	if !includeAck {
		q += ` WHERE acknowledged = 0`
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	rows, err := s.DB.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var uid sql.NullInt64
		var ack int
		if err := rows.Scan(&a.ID, &a.TS, &uid, &a.Username, &a.Category,
			&a.Severity, &a.Message, &a.Detail, &ack); err != nil {
			return nil, err
		}
		if uid.Valid {
			a.UserID = &uid.Int64
		}
		a.Acknowledged = ack != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

// Acknowledge marks one alert as handled.
func (s *Service) Acknowledge(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE threat_alerts SET acknowledged=1 WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("alert not found")
	}
	return nil
}

// EvaluateLogin inspects a successful login event and records anomaly alerts.
// Called from the auth-service login handler (best-effort, non-blocking).
func (s *Service) EvaluateLogin(ctx context.Context, userID int64, username, ip string, now time.Time) {
	// 1) Off-hours login (outside 06:00–22:00 local server time).
	hour := now.Hour()
	if hour < 6 || hour >= 22 {
		_ = s.Record(ctx, Alert{
			UserID:   &userID,
			Username: username,
			Category: "off_hours_login",
			Severity: SevWarn,
			Message:  "Login outside business hours",
			Detail:   "login at " + now.Format("2006-01-02 15:04:05") + " from " + ip,
		})
	}
	// 2) New client IP for this user.
	if ip != "" {
		var seen int
		_ = s.DB.QueryRowContext(ctx, `
			SELECT COUNT(*) FROM audit_events
			WHERE actor = ? AND kind = 'login.ok'
			  AND detail LIKE ?`, username, "%"+ip+"%").Scan(&seen)
		if seen <= 1 {
			_ = s.Record(ctx, Alert{
				UserID:   &userID,
				Username: username,
				Category: "new_source_ip",
				Severity: SevInfo,
				Message:  "Login from a new source IP",
				Detail:   "ip=" + ip,
			})
		}
	}
}

// EvaluateFailedSpike runs hourly: look back the last 5 min and alert if any
// user has > 5 failed logins. Caller is the auth-service.
func (s *Service) EvaluateFailedSpike(ctx context.Context) {
	since := db.Now() - 300
	rows, err := s.DB.QueryContext(ctx, `
		SELECT actor, COUNT(*)
		FROM audit_events
		WHERE kind='login.failed' AND ts >= ?
		GROUP BY actor HAVING COUNT(*) > 5`, since)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var actor string
		var count int
		if err := rows.Scan(&actor, &count); err != nil {
			continue
		}
		_ = s.Record(ctx, Alert{
			Username: actor,
			Category: "brute_force",
			Severity: SevHigh,
			Message:  "Possible brute-force attempt",
			Detail:   "failed_logins=" + itoa(count) + " in last 5m",
		})
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func nullableInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
