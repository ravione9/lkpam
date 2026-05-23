// Package approval implements the JIT access request workflow with a
// multi-approver "approval matrix" — admins define rules (target kind + tier
// range -> approver groups + required approval count) and each Decide call
// either records an approval/denial or finalizes the request once thresholds
// are met.
package approval

import (
	"context"
	"database/sql"
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
	TTLSeconds    int    `json:"ttl_seconds"`
	SudoRequested int    `json:"sudo_requested,omitempty"`
	SudoGranted   int    `json:"sudo_granted,omitempty"`
}

// Service is the approval workflow facade.
//
// Matrix and GroupMembers are optional collaborators — when set, Decide
// enforces the approval matrix (rule lookup, approver-group membership check,
// multi-approver thresholds). When nil, Decide falls back to "any admin who is
// not the requester can decide" so the platform still works during initial
// setup.
type Service struct {
	DB           *db.DB
	Matrix       *MatrixService
	GroupMembers GroupMembershipLookup
}

// GroupMembershipLookup is satisfied by groups.Service. It is declared as an
// interface here so internal/approval does not import internal/groups and
// avoid a possible circular dependency in the future.
type GroupMembershipLookup interface {
	UserGroupIDs(ctx context.Context, userID int64) ([]int64, error)
}

// Create files a new access request.
func (s *Service) Create(ctx context.Context, userID, targetID int64, reason string, ttl time.Duration, sudoRequested bool) (int64, error) {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	sudo := 0
	if sudoRequested {
		sudo = 1
	}
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO access_requests(user_id, target_id, reason, status, created_at, ttl_seconds, sudo_requested)
		VALUES(?,?,?,'pending',?,?,?)`,
		userID, targetID, reason, db.Now(), int(ttl.Seconds()), sudo)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// ErrSelfApproval is returned when a requester tries to approve their own request.
var ErrSelfApproval = errors.New("cannot approve your own request")

// ErrNotApprover is returned when the caller is not in the approver group(s)
// for the matched matrix rule.
var ErrNotApprover = errors.New("you are not an approver for this request")

// ErrAlreadyDecided is returned when an approver tries to decide twice.
var ErrAlreadyDecided = errors.New("you have already voted on this request")

// ErrRequestClosed is returned when the request is not pending.
var ErrRequestClosed = errors.New("request is not pending")

// Get loads a single access request by ID.
func (s *Service) Get(ctx context.Context, id int64) (*Request, error) {
	row := s.DB.QueryRowContext(ctx, `
		SELECT id, user_id, target_id, reason, status, created_at, ttl_seconds,
		       COALESCE(sudo_requested,0), COALESCE(sudo_granted,0)
		FROM access_requests WHERE id = ?`, id)
	var r Request
	if err := row.Scan(&r.ID, &r.UserID, &r.TargetID, &r.Reason, &r.Status, &r.CreatedAt, &r.TTLSeconds,
		&r.SudoRequested, &r.SudoGranted); err != nil {
		return nil, errors.New("request not found")
	}
	return &r, nil
}

// DecisionRecord is a single vote captured against a request.
type DecisionRecord struct {
	RequestID  int64  `json:"request_id"`
	ApproverID int64  `json:"approver_id"`
	Approver   string `json:"approver,omitempty"`
	Approve    bool   `json:"approve"`
	Comment    string `json:"comment,omitempty"`
	DecidedAt  int64  `json:"decided_at"`
}

// DecideResult tells the caller what happened.
type DecideResult struct {
	Status         string `json:"status"`          // pending | approved | denied
	ApprovalsHave  int    `json:"approvals_have"`
	ApprovalsNeed  int    `json:"approvals_need"`
}

// Decide records one approver's vote against a request. Behavior:
//   - Caller must not be the requester (ErrSelfApproval).
//   - When a Matrix is configured and a rule matches, the caller must be a
//     member of one of the approver groups (ErrNotApprover); otherwise the
//     caller must hold the "admin" role.
//   - One denial finalizes the request as denied. Approvals accumulate until
//     `required_approvals` is met, at which point the request flips to
//     approved.
//   - Re-voting by the same approver is rejected (ErrAlreadyDecided).
func (s *Service) Decide(
	ctx context.Context,
	id, approverID int64,
	approverRole string,
	approve bool,
	comment string,
) (*DecideResult, error) {
	req, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if req.Status != "pending" {
		return nil, ErrRequestClosed
	}
	if req.UserID == approverID {
		return nil, ErrSelfApproval
	}

	// Lookup matrix rule for the target + requester's groups.
	required := 1
	var approverGroupIDs []int64
	if s.Matrix != nil {
		targetKind, tier, err := s.targetMeta(ctx, req.TargetID)
		if err != nil {
			return nil, err
		}
		requesterGroups, _ := s.requesterGroups(ctx, req.UserID)
		rule, err := s.Matrix.FindRule(ctx, targetKind, tier, requesterGroups)
		if err != nil {
			return nil, err
		}
		if rule != nil {
			required = rule.RequiredApprovals
			approverGroupIDs = rule.ApproverGroupIDs
		}
	}

	// Authorize the approver.
	if len(approverGroupIDs) > 0 && s.GroupMembers != nil {
		userGroups, err := s.GroupMembers.UserGroupIDs(ctx, approverID)
		if err != nil {
			return nil, err
		}
		if !anyIntersection(approverGroupIDs, userGroups) {
			return nil, ErrNotApprover
		}
	} else if approverRole != "admin" {
		return nil, ErrNotApprover
	}

	// Record vote; UNIQUE(request_id, approver_id) blocks duplicates.
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO approval_decisions(request_id, approver_id, approve, comment, decided_at)
		VALUES(?,?,?,?,?)`,
		id, approverID, boolToInt(approve), comment, db.Now())
	if err != nil {
		return nil, ErrAlreadyDecided
	}

	// Tally and finalize.
	approvals, denials, err := s.tally(ctx, id)
	if err != nil {
		return nil, err
	}
	result := &DecideResult{
		Status:        "pending",
		ApprovalsHave: approvals,
		ApprovalsNeed: required,
	}
	switch {
	case denials > 0:
		if err := s.finalize(ctx, id, "denied", approverID); err != nil {
			return nil, err
		}
		result.Status = "denied"
	case approvals >= required:
		if err := s.finalize(ctx, id, "approved", approverID); err != nil {
			return nil, err
		}
		result.Status = "approved"
	}
	return result, nil
}

func (s *Service) targetMeta(ctx context.Context, targetID int64) (string, int, error) {
	var kind string
	var tier int
	err := s.DB.QueryRowContext(ctx,
		`SELECT kind, tier FROM targets WHERE id = ?`, targetID).Scan(&kind, &tier)
	if err != nil {
		return "", 0, errors.New("target not found")
	}
	return kind, tier, nil
}

func (s *Service) requesterGroups(ctx context.Context, userID int64) ([]int64, error) {
	if s.GroupMembers == nil {
		return nil, nil
	}
	return s.GroupMembers.UserGroupIDs(ctx, userID)
}

func (s *Service) tally(ctx context.Context, id int64) (int, int, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT approve, COUNT(*) FROM approval_decisions WHERE request_id = ? GROUP BY approve`, id)
	if err != nil {
		return 0, 0, err
	}
	defer rows.Close()
	var approvals, denials int
	for rows.Next() {
		var ap, count int
		if err := rows.Scan(&ap, &count); err != nil {
			return 0, 0, err
		}
		if ap == 1 {
			approvals = count
		} else {
			denials = count
		}
	}
	return approvals, denials, rows.Err()
}

func (s *Service) finalize(ctx context.Context, id int64, status string, approverID int64) error {
	if status == "approved" {
		// When approving, automatically grant sudo if it was requested.
		// The admin can still toggle it off afterwards via the grant-sudo endpoint,
		// but requiring a separate manual step means users silently never get sudo.
		_, err := s.DB.ExecContext(ctx, `
			UPDATE access_requests
			SET status = ?, approver_id = ?, decided_at = ?,
			    sudo_granted = CASE WHEN COALESCE(sudo_requested,0)=1 THEN 1 ELSE 0 END
			WHERE id = ? AND status = 'pending'`,
			status, approverID, db.Now(), id)
		return err
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE access_requests
		SET status = ?, approver_id = ?, decided_at = ?
		WHERE id = ? AND status = 'pending'`,
		status, approverID, db.Now(), id)
	return err
}

// ListDecisions returns the recorded votes for a request, enriched with the
// approver username.
func (s *Service) ListDecisions(ctx context.Context, requestID int64) ([]DecisionRecord, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT d.request_id, d.approver_id, COALESCE(u.username,''),
		       d.approve, d.comment, d.decided_at
		FROM approval_decisions d
		LEFT JOIN users u ON u.id = d.approver_id
		WHERE d.request_id = ?
		ORDER BY d.decided_at`, requestID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DecisionRecord
	for rows.Next() {
		var d DecisionRecord
		var ap int
		if err := rows.Scan(&d.RequestID, &d.ApproverID, &d.Approver,
			&ap, &d.Comment, &d.DecidedAt); err != nil {
			return nil, err
		}
		d.Approve = ap != 0
		out = append(out, d)
	}
	return out, rows.Err()
}

// RequiredApprovals returns the matched matrix rule's threshold for a request.
// Falls back to 1 when no matrix or no matching rule.
func (s *Service) RequiredApprovals(ctx context.Context, requestID int64) (int, error) {
	if s.Matrix == nil {
		return 1, nil
	}
	req, err := s.Get(ctx, requestID)
	if err != nil {
		return 0, err
	}
	kind, tier, err := s.targetMeta(ctx, req.TargetID)
	if err != nil {
		return 0, err
	}
	requesterGroups, _ := s.requesterGroups(ctx, req.UserID)
	rule, err := s.Matrix.FindRule(ctx, kind, tier, requesterGroups)
	if err != nil {
		return 0, err
	}
	if rule == nil {
		return 1, nil
	}
	return rule.RequiredApprovals, nil
}

func anyIntersection(a, b []int64) bool {
	set := make(map[int64]struct{}, len(a))
	for _, x := range a {
		set[x] = struct{}{}
	}
	for _, y := range b {
		if _, ok := set[y]; ok {
			return true
		}
	}
	return false
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// IsApproved returns true if there is a non-expired approved request for the
// (user, target) pair.
func (s *Service) IsApproved(ctx context.Context, userID, targetID int64) (bool, error) {
	row := s.DB.QueryRowContext(ctx, `
		SELECT id, decided_at, ttl_seconds FROM access_requests
		WHERE user_id = ? AND target_id = ? AND status = 'approved'
		ORDER BY decided_at DESC LIMIT 1`, userID, targetID)
	var id int64
	var decided, ttl sql.NullInt64
	if err := row.Scan(&id, &decided, &ttl); err != nil {
		return false, nil
	}
	// NULL decided_at or NULL ttl → treat as never-expired (permanent grant).
	if !decided.Valid || !ttl.Valid {
		return true, nil
	}
	return time.Now().Unix() < decided.Int64+ttl.Int64, nil
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
	Username       string           `json:"username"`
	TargetName     string           `json:"target_name"`
	TargetKind     string           `json:"target_kind,omitempty"`
	TargetTier     int              `json:"target_tier,omitempty"`
	ApprovalsHave  int              `json:"approvals_have"`
	ApprovalsNeed  int              `json:"approvals_need"`
	Decisions      []DecisionRecord `json:"decisions,omitempty"`
}

// ListPendingEnriched lists open requests with joined user/target names plus
// approval progress for the UI.
func (s *Service) ListPendingEnriched(ctx context.Context) ([]RequestView, error) {
	return s.queryEnriched(ctx, `
		SELECT ar.id, ar.user_id, ar.target_id, ar.reason, ar.status, ar.created_at, ar.ttl_seconds, ar.decided_at,
		       COALESCE(ar.sudo_requested,0), COALESCE(ar.sudo_granted,0),
		       u.username, t.name, t.kind, t.tier
		FROM access_requests ar
		JOIN users u ON u.id = ar.user_id
		JOIN targets t ON t.id = ar.target_id
		WHERE ar.status = 'pending'
		ORDER BY ar.created_at DESC`)
}

// ListMineEnriched returns all requests filed by a user (any status).
func (s *Service) ListMineEnriched(ctx context.Context, userID int64) ([]RequestView, error) {
	return s.queryEnriched(ctx, `
		SELECT ar.id, ar.user_id, ar.target_id, ar.reason, ar.status, ar.created_at, ar.ttl_seconds, ar.decided_at,
		       COALESCE(ar.sudo_requested,0), COALESCE(ar.sudo_granted,0),
		       u.username, t.name, t.kind, t.tier
		FROM access_requests ar
		JOIN users u ON u.id = ar.user_id
		JOIN targets t ON t.id = ar.target_id
		WHERE ar.user_id = ?
		ORDER BY ar.created_at DESC
		LIMIT 50`, userID)
}

// Revoke immediately revokes an approved request by setting status to "denied"
// and recording the current timestamp as decided_at. This lets admins cancel
// active access grants before they expire naturally.
func (s *Service) Revoke(ctx context.Context, requestID, revokerID int64) error {
	res, err := s.DB.ExecContext(ctx, `
		UPDATE access_requests
		SET status = 'denied', approver_id = ?, decided_at = ?
		WHERE id = ? AND status = 'approved'`,
		revokerID, db.Now(), requestID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("request not found or not currently approved")
	}
	return nil
}

// ListApprovedEnriched returns approved requests for the admin panel.
// Shows BOTH active (non-expired) and recently-expired (within last 24h) grants
// so admins can see and renew grants that timed out under the old 30-min TTL.
func (s *Service) ListApprovedEnriched(ctx context.Context) ([]RequestView, error) {
	return s.queryEnriched(ctx, `
		SELECT ar.id, ar.user_id, ar.target_id, ar.reason, ar.status, ar.created_at, ar.ttl_seconds, ar.decided_at,
		       COALESCE(ar.sudo_requested,0), COALESCE(ar.sudo_granted,0),
		       u.username, t.name, t.kind, t.tier
		FROM access_requests ar
		JOIN users u ON u.id = ar.user_id
		JOIN targets t ON t.id = ar.target_id
		WHERE ar.status = 'approved'
		  AND (ar.decided_at IS NULL
		       OR ar.ttl_seconds IS NULL
		       OR ar.decided_at + ar.ttl_seconds > strftime('%s','now') - 86400)
		ORDER BY ar.decided_at DESC`)
}

// RenewApproval resets decided_at to now and extends TTL, reactivating an expired grant.
func (s *Service) RenewApproval(ctx context.Context, requestID int64, ttlSeconds int) error {
	if ttlSeconds <= 0 {
		ttlSeconds = 28800 // 8 hours
	}
	res, err := s.DB.ExecContext(ctx, `
		UPDATE access_requests
		SET decided_at = ?, ttl_seconds = ?
		WHERE id = ? AND status = 'approved'`,
		db.Now(), ttlSeconds, requestID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("request not found or not approved")
	}
	return nil
}

// GrantSudo marks sudo_granted=1 on an approved request.
func (s *Service) GrantSudo(ctx context.Context, requestID int64, grant bool) error {
	v := 0
	if grant {
		v = 1
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE access_requests SET sudo_granted=? WHERE id=?`, v, requestID)
	return err
}

func (s *Service) queryEnriched(ctx context.Context, q string, args ...any) ([]RequestView, error) {
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RequestView
	for rows.Next() {
		var v RequestView
		var decidedAt sql.NullInt64
		var sudoReq, sudoGrant int
		if err := rows.Scan(&v.ID, &v.UserID, &v.TargetID, &v.Reason, &v.Status,
			&v.CreatedAt, &v.TTLSeconds, &decidedAt, &sudoReq, &sudoGrant,
			&v.Username, &v.TargetName, &v.TargetKind, &v.TargetTier); err != nil {
			return nil, err
		}
		if decidedAt.Valid {
			v.DecidedAt = &decidedAt.Int64
		}
		v.SudoRequested = sudoReq
		v.SudoGranted = sudoGrant
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Enrich with approval progress and decisions.
	for i := range out {
		if need, err := s.RequiredApprovals(ctx, out[i].ID); err == nil {
			out[i].ApprovalsNeed = need
		} else {
			out[i].ApprovalsNeed = 1
		}
		decs, err := s.ListDecisions(ctx, out[i].ID)
		if err == nil {
			out[i].Decisions = decs
			for _, d := range decs {
				if d.Approve {
					out[i].ApprovalsHave++
				}
			}
		}
	}
	return out, nil
}
