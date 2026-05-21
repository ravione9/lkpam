// matrix.go defines the approval matrix — the rules that determine who can
// approve a given access request and how many approvals are required.
//
// A matrix rule matches by (target_kind, tier range, requester groups) and
// lists one or more approver groups. Empty requester_group_ids means the
// rule applies to all requesters. Lower priority wins.
package approval

import (
	"context"
	"database/sql"
	"errors"
	"strconv"
	"strings"

	"github.com/example/pam-platform/internal/db"
)

// MatrixRule describes one row of the approval matrix.
type MatrixRule struct {
	ID                 int64   `json:"id"`
	Name               string  `json:"name"`
	TargetKind         string  `json:"target_kind"`
	TierMin            int     `json:"tier_min"`
	TierMax            int     `json:"tier_max"`
	RequiredApprovals  int     `json:"required_approvals"`
	RequesterGroupIDs  []int64 `json:"requester_group_ids"`
	ApproverGroupIDs   []int64 `json:"approver_group_ids"`
	Priority           int     `json:"priority"`
	Enabled            bool    `json:"enabled"`
	CreatedAt          int64   `json:"created_at"`
}

// MatrixService manages the approval matrix table.
type MatrixService struct{ DB *db.DB }

const matrixSelectCols = `
	id, name, target_kind, tier_min, tier_max,
	required_approvals,
	COALESCE(requester_group_ids, ''),
	approver_group_ids,
	priority, enabled, created_at`

func scanMatrixRule(rows *sql.Rows) (MatrixRule, error) {
	var r MatrixRule
	var reqCSV, apprCSV string
	var en int
	if err := rows.Scan(&r.ID, &r.Name, &r.TargetKind, &r.TierMin, &r.TierMax,
		&r.RequiredApprovals, &reqCSV, &apprCSV, &r.Priority, &en, &r.CreatedAt); err != nil {
		return r, err
	}
	r.Enabled = en != 0
	r.RequesterGroupIDs = parseCSVInts(reqCSV)
	r.ApproverGroupIDs = parseCSVInts(apprCSV)
	return r, nil
}

// List returns all matrix rules ordered by priority.
func (m *MatrixService) List(ctx context.Context) ([]MatrixRule, error) {
	rows, err := m.DB.QueryContext(ctx, `
		SELECT`+matrixSelectCols+`
		FROM approval_matrix ORDER BY priority ASC, id ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MatrixRule
	for rows.Next() {
		r, err := scanMatrixRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Create inserts a matrix rule.
func (m *MatrixService) Create(ctx context.Context, r MatrixRule) (int64, error) {
	if r.Name == "" {
		return 0, errors.New("rule name required")
	}
	if r.TargetKind == "" {
		r.TargetKind = "*"
	}
	if r.RequiredApprovals < 1 {
		r.RequiredApprovals = 1
	}
	en := 1
	if !r.Enabled {
		en = 0
	}
	res, err := m.DB.ExecContext(ctx, `
		INSERT INTO approval_matrix(name, target_kind, tier_min, tier_max,
		  required_approvals, requester_group_ids, approver_group_ids,
		  priority, enabled, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		r.Name, r.TargetKind, r.TierMin, r.TierMax,
		r.RequiredApprovals,
		joinCSVInts(r.RequesterGroupIDs), joinCSVInts(r.ApproverGroupIDs),
		r.Priority, en, db.Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Update modifies an existing matrix rule.
func (m *MatrixService) Update(ctx context.Context, r MatrixRule) error {
	if r.ID <= 0 {
		return errors.New("id required")
	}
	en := 1
	if !r.Enabled {
		en = 0
	}
	if r.RequiredApprovals < 1 {
		r.RequiredApprovals = 1
	}
	res, err := m.DB.ExecContext(ctx, `
		UPDATE approval_matrix SET name=?, target_kind=?, tier_min=?, tier_max=?,
		  required_approvals=?, requester_group_ids=?, approver_group_ids=?,
		  priority=?, enabled=?
		WHERE id=?`,
		r.Name, r.TargetKind, r.TierMin, r.TierMax,
		r.RequiredApprovals,
		joinCSVInts(r.RequesterGroupIDs), joinCSVInts(r.ApproverGroupIDs),
		r.Priority, en, r.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("matrix rule not found")
	}
	return nil
}

// Delete removes a matrix rule.
func (m *MatrixService) Delete(ctx context.Context, id int64) error {
	res, err := m.DB.ExecContext(ctx, `DELETE FROM approval_matrix WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("matrix rule not found")
	}
	return nil
}

// FindRule returns the most-specific enabled rule for the given target kind/tier
// and requester's group memberships. Matches exact kind, then vendor family
// ("cisco-ios" -> "cisco"), then '*'. Skips rules whose requester_group_ids
// do not intersect the requester's groups (empty requester_group_ids = any).
// Returns (nil, nil) if no rule matches.
func (m *MatrixService) FindRule(ctx context.Context, targetKind string, tier int, requesterGroupIDs []int64) (*MatrixRule, error) {
	family := targetKind
	if i := strings.Index(targetKind, "-"); i > 0 {
		family = targetKind[:i]
	}
	rows, err := m.DB.QueryContext(ctx, `
		SELECT`+matrixSelectCols+`
		FROM approval_matrix
		WHERE enabled = 1
		  AND (target_kind = ? OR target_kind = ? OR target_kind = '*')
		  AND tier_min <= ? AND tier_max >= ?
		ORDER BY CASE
		           WHEN target_kind = ? THEN 0
		           WHEN target_kind = ? THEN 1
		           ELSE 2
		         END,
		         priority ASC, id ASC`, targetKind, family, tier, tier, targetKind, family)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		r, err := scanMatrixRule(rows)
		if err != nil {
			return nil, err
		}
		if len(r.RequesterGroupIDs) == 0 || anyIntersection(r.RequesterGroupIDs, requesterGroupIDs) {
			return &r, nil
		}
	}
	return nil, rows.Err()
}

func parseCSVInts(s string) []int64 {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]int64, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if n, err := strconv.ParseInt(p, 10, 64); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func joinCSVInts(ids []int64) string {
	if len(ids) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ",")
}
