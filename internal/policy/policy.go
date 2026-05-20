// Package policy is the authorization engine. The reference implementation
// is a pragmatic RBAC + tier model with a per-command allow/deny list. Swap
// for OPA by replacing Decide with an OPA query (rego/v1).
package policy

import (
	"context"
	"errors"
	"strings"

	"github.com/example/pam-platform/internal/db"
)

// Decision is the result of a policy evaluation.
type Decision struct {
	Allow           bool     `json:"allow"`
	RequireApproval bool     `json:"require_approval"`
	Reasons         []string `json:"reasons,omitempty"`
	AllowedCmds     []string `json:"allowed_cmds,omitempty"`
	DeniedCmds      []string `json:"denied_cmds,omitempty"`
}

// Engine evaluates policy from the policies table.
type Engine struct{ DB *db.DB }

// Input is everything the engine needs.
type Input struct {
	UserID     int64
	Role       string
	TargetID   int64
	TargetKind string
	TargetTier int // 0=critical ... 3=dev
	Action     string
}

// Decide evaluates the policy. The algorithm:
//   1. Find rows matching role + (target_kind OR '*'). Most-specific wins.
//   2. If no rule applies, deny.
//   3. Check tier_max >= target tier.
//   4. Surface allowed/denied command lists for downstream cmd filtering.
//   5. require_approval flag bubbles up unchanged.
func (e *Engine) Decide(ctx context.Context, in Input) (Decision, error) {
	rows, err := e.DB.QueryContext(ctx, `
		SELECT target_kind, tier_max, require_approval, allowed_commands, denied_commands
		FROM policies
		WHERE role = ? AND (target_kind = ? OR target_kind = '*')
		ORDER BY CASE WHEN target_kind = ? THEN 0 ELSE 1 END
		LIMIT 1`,
		in.Role, in.TargetKind, in.TargetKind)
	if err != nil {
		return Decision{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		return Decision{Allow: false, Reasons: []string{"no policy for role/kind"}}, nil
	}
	var (
		kind            string
		tierMax         int
		requireApproval int
		allowedCSV      string
		deniedCSV       string
	)
	if err := rows.Scan(&kind, &tierMax, &requireApproval, &allowedCSV, &deniedCSV); err != nil {
		return Decision{}, err
	}

	d := Decision{
		Allow:           true,
		RequireApproval: requireApproval != 0,
		AllowedCmds:     splitCSV(allowedCSV),
		DeniedCmds:      splitCSV(deniedCSV),
	}
	if in.TargetTier < tierMax {
		// Smaller tier number is *more* sensitive; tierMax is max reachable
		// where 0 is the highest sensitivity. So allow when target_tier >= tierMax.
		// We keep semantics: deny if user's tier_max excludes target.
		// Interpretation: tier_max is the most-sensitive tier this role may reach.
		// in.TargetTier < tier_max means too sensitive.
		d.Allow = false
		d.Reasons = append(d.Reasons, "tier exceeds role limit")
	}
	return d, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// CommandAllowed returns true if cmd passes the allow/deny lists.
// Deny wins over allow. Patterns are simple prefix matches for now;
// real OPA can do regex / glob.
func CommandAllowed(cmd string, allow, deny []string) bool {
	cmd = strings.TrimSpace(cmd)
	for _, d := range deny {
		if strings.HasPrefix(cmd, d) {
			return false
		}
	}
	if len(allow) == 0 {
		return true // permissive default if no allow list
	}
	for _, a := range allow {
		if strings.HasPrefix(cmd, a) {
			return true
		}
	}
	return false
}

// Rule is a row from the policies table.
type Rule struct {
	ID              int64  `json:"id"`
	Role            string `json:"role"`
	TargetKind      string `json:"target_kind"`
	TierMax         int    `json:"tier_max"`
	RequireApproval bool   `json:"require_approval"`
	AllowedCommands string `json:"allowed_commands"`
	DeniedCommands  string `json:"denied_commands"`
}

// ListRules returns all policy rules.
func (e *Engine) ListRules(ctx context.Context) ([]Rule, error) {
	rows, err := e.DB.QueryContext(ctx, `
		SELECT id, role, target_kind, tier_max, require_approval, allowed_commands, denied_commands
		FROM policies ORDER BY role, target_kind`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Rule
	for rows.Next() {
		var r Rule
		var appr int
		if err := rows.Scan(&r.ID, &r.Role, &r.TargetKind, &r.TierMax, &appr, &r.AllowedCommands, &r.DeniedCommands); err != nil {
			return nil, err
		}
		r.RequireApproval = appr != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateRule inserts a new policy rule.
func (e *Engine) CreateRule(ctx context.Context, r Rule) (int64, error) {
	if r.Role == "" || r.TargetKind == "" {
		return 0, errors.New("role and target_kind are required")
	}
	appr := 0
	if r.RequireApproval {
		appr = 1
	}
	res, err := e.DB.ExecContext(ctx, `
		INSERT INTO policies(role, target_kind, tier_max, require_approval, allowed_commands, denied_commands)
		VALUES(?,?,?,?,?,?)`,
		r.Role, r.TargetKind, r.TierMax, appr, r.AllowedCommands, r.DeniedCommands)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateRule modifies an existing policy rule.
func (e *Engine) UpdateRule(ctx context.Context, r Rule) error {
	if r.ID <= 0 {
		return errors.New("id required")
	}
	appr := 0
	if r.RequireApproval {
		appr = 1
	}
	res, err := e.DB.ExecContext(ctx, `
		UPDATE policies SET role=?, target_kind=?, tier_max=?, require_approval=?,
		  allowed_commands=?, denied_commands=? WHERE id=?`,
		r.Role, r.TargetKind, r.TierMax, appr, r.AllowedCommands, r.DeniedCommands, r.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("policy not found")
	}
	return nil
}

// DeleteRule removes a policy rule by ID.
func (e *Engine) DeleteRule(ctx context.Context, id int64) error {
	res, err := e.DB.ExecContext(ctx, `DELETE FROM policies WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("policy not found")
	}
	return nil
}
