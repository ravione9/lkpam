// Package reports computes pre-canned admin reports. CyberArk ships a full
// reporting engine — here we expose the queries the UI most often needs.
package reports

import (
	"context"
	"database/sql"

	"github.com/example/pam-platform/internal/db"
)

// Summary is the high-level "platform health" snapshot.
type Summary struct {
	Users               int `json:"users"`
	UsersDisabled       int `json:"users_disabled"`
	UsersMFA            int `json:"users_mfa_enabled"`
	Groups              int `json:"groups"`
	Targets             int `json:"targets"`
	Safes               int `json:"safes"`
	PrivilegedAccounts  int `json:"privileged_accounts"`
	AccountsOverdue     int `json:"accounts_overdue_rotation"`
	PendingRequests     int `json:"pending_requests"`
	ActiveSessions      int `json:"active_sessions"`
	Sessions24h         int `json:"sessions_24h"`
	LoginFailed24h      int `json:"login_failed_24h"`
	OpenAlerts          int `json:"open_alerts"`
}

// AccessByUser is one row of the "who is using what" report.
type AccessByUser struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Sessions int    `json:"sessions"`
	Targets  int    `json:"targets"`
}

// PasswordAge is one row of the "stale credentials" report.
type PasswordAge struct {
	AccountID   int64  `json:"account_id"`
	AccountName string `json:"account_name"`
	SafeName    string `json:"safe_name"`
	LastRotated *int64 `json:"last_rotated,omitempty"`
	NextDue     *int64 `json:"next_due,omitempty"`
	AgeDays     int    `json:"age_days"`
	Status      string `json:"status"`
}

// Service is the reports facade.
type Service struct{ DB *db.DB }

// Summary returns the platform-wide stats snapshot.
func (s *Service) Summary(ctx context.Context) (*Summary, error) {
	sum := &Summary{}
	q := func(dst *int, sql string, args ...any) {
		_ = s.DB.QueryRowContext(ctx, sql, args...).Scan(dst)
	}
	now := db.Now()
	q(&sum.Users, `SELECT COUNT(*) FROM users`)
	q(&sum.UsersDisabled, `SELECT COUNT(*) FROM users WHERE disabled = 1`)
	q(&sum.UsersMFA, `SELECT COUNT(*) FROM users WHERE mfa_enabled = 1`)
	q(&sum.Groups, `SELECT COUNT(*) FROM groups`)
	q(&sum.Targets, `SELECT COUNT(*) FROM targets`)
	q(&sum.Safes, `SELECT COUNT(*) FROM safes`)
	q(&sum.PrivilegedAccounts, `SELECT COUNT(*) FROM privileged_accounts`)
	q(&sum.AccountsOverdue, `SELECT COUNT(*) FROM privileged_accounts WHERE next_rotation IS NOT NULL AND next_rotation < ?`, now)
	q(&sum.PendingRequests, `SELECT COUNT(*) FROM access_requests WHERE status = 'pending'`)
	q(&sum.ActiveSessions, `SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL`)
	q(&sum.Sessions24h, `SELECT COUNT(*) FROM sessions WHERE started_at >= ?`, now-86400)
	q(&sum.LoginFailed24h, `SELECT COUNT(*) FROM audit_events WHERE kind='login.failed' AND ts >= ?`, now-86400)
	q(&sum.OpenAlerts, `SELECT COUNT(*) FROM threat_alerts WHERE acknowledged = 0`)
	return sum, nil
}

// AccessByUser returns the top users by session count in the lookback window.
func (s *Service) AccessByUser(ctx context.Context, days int) ([]AccessByUser, error) {
	if days <= 0 {
		days = 30
	}
	since := db.Now() - int64(days)*86400
	rows, err := s.DB.QueryContext(ctx, `
		SELECT u.id, u.username, COUNT(s.id), COUNT(DISTINCT s.target_id)
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.started_at >= ?
		GROUP BY u.id, u.username
		ORDER BY COUNT(s.id) DESC LIMIT 50`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccessByUser
	for rows.Next() {
		var r AccessByUser
		if err := rows.Scan(&r.UserID, &r.Username, &r.Sessions, &r.Targets); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// PasswordAge lists privileged accounts sorted by stalest password first.
func (s *Service) PasswordAge(ctx context.Context) ([]PasswordAge, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT a.id, a.name, sf.name, a.last_rotated, a.next_rotation
		FROM privileged_accounts a
		JOIN safes sf ON sf.id = a.safe_id
		ORDER BY COALESCE(a.last_rotated, a.created_at) ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := db.Now()
	var out []PasswordAge
	for rows.Next() {
		var p PasswordAge
		var lr, nr sql.NullInt64
		if err := rows.Scan(&p.AccountID, &p.AccountName, &p.SafeName, &lr, &nr); err != nil {
			continue
		}
		if lr.Valid {
			v := lr.Int64
			p.LastRotated = &v
			p.AgeDays = int((now - v) / 86400)
		}
		if nr.Valid {
			v := nr.Int64
			p.NextDue = &v
		}
		p.Status = "ok"
		if p.NextDue != nil && *p.NextDue < now {
			p.Status = "overdue"
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
