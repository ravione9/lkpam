// Package approval implements the JIT access request workflow.
package approval

import (
	"context"
	"errors"
	"time"

	"github.com/example/pam-platform/internal/db"
)

// Request is a pending access request.
type Request struct {
	ID         int64  `json:"id"`
	UserID     int64  `json:"user_id"`
	TargetID   int64  `json:"target_id"`
	Reason     string `json:"reason"`
	Status     string `json:"status"`
	ApproverID *int64 `json:"approver_id,omitempty"`
	CreatedAt  int64  `json:"created_at"`
	DecidedAt  *int64 `json:"decided_at,omitempty"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// Service is the approval workflow facade.
type Service struct{ DB *db.DB }

// Create files a new access request.
func (s *Service) Create(ctx context.Context, userID, targetID int64, reason string, ttl time.Duration) (int64, error) {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO access_requests(user_id, target_id, reason, status, created_at, ttl_seconds)
		VALUES(?,?,?,'pending',?,?)`,
		userID, targetID, reason, db.Now(), int(ttl.Seconds()))
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// Decide marks a request approved or denied.
func (s *Service) Decide(ctx context.Context, id, approverID int64, approve bool) error {
	status := "denied"
	if approve {
		status = "approved"
	}
	res, err := s.DB.ExecContext(ctx, `
		UPDATE access_requests
		SET status = ?, approver_id = ?, decided_at = ?
		WHERE id = ? AND status = 'pending'`,
		status, approverID, db.Now(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("request not found or already decided")
	}
	return nil
}

// IsApproved returns true if there is a non-expired approved request for the
// (user, target) pair.
func (s *Service) IsApproved(ctx context.Context, userID, targetID int64) (bool, error) {
	row := s.DB.QueryRowContext(ctx, `
		SELECT id, decided_at, ttl_seconds FROM access_requests
		WHERE user_id = ? AND target_id = ? AND status = 'approved'
		ORDER BY decided_at DESC LIMIT 1`, userID, targetID)
	var id, decided int64
	var ttl int
	if err := row.Scan(&id, &decided, &ttl); err != nil {
		return false, nil
	}
	return time.Now().Unix() < decided+int64(ttl), nil
}

// ListPending lists open requests.
func (s *Service) ListPending(ctx context.Context) ([]Request, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, user_id, target_id, reason, status, created_at, ttl_seconds
		FROM access_requests WHERE status = 'pending' ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Request
	for rows.Next() {
		var r Request
		if err := rows.Scan(&r.ID, &r.UserID, &r.TargetID, &r.Reason, &r.Status, &r.CreatedAt, &r.TTLSeconds); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// RequestView enriches a request with human-readable names for the UI.
type RequestView struct {
	Request
	Username   string `json:"username"`
	TargetName string `json:"target_name"`
}

// ListPendingEnriched lists open requests with joined user/target names.
func (s *Service) ListPendingEnriched(ctx context.Context) ([]RequestView, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT ar.id, ar.user_id, ar.target_id, ar.reason, ar.status, ar.created_at, ar.ttl_seconds,
		       u.username, t.name
		FROM access_requests ar
		JOIN users u ON u.id = ar.user_id
		JOIN targets t ON t.id = ar.target_id
		WHERE ar.status = 'pending'
		ORDER BY ar.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RequestView
	for rows.Next() {
		var v RequestView
		if err := rows.Scan(&v.ID, &v.UserID, &v.TargetID, &v.Reason, &v.Status, &v.CreatedAt, &v.TTLSeconds,
			&v.Username, &v.TargetName); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
