// Package policy is the authorization engine. The reference implementation
// is a pragmatic RBAC + tier model with a per-command allow/deny list. Swap
// for OPA by replacing Decide with an OPA query (rego/v1).
package policy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// Input is everything the engine needs. Roles is the set of effective roles
// for the user (their own role + roles granted via group memberships). If left
// empty, the engine falls back to a single-element slice of {Role}.
type Input struct {
	UserID     int64    `json:"user_id"`
	Role       string   `json:"role"`
	Roles      []string `json:"roles,omitempty"`
	TargetID   int64    `json:"target_id"`
	TargetKind string   `json:"target_kind"`
	TargetTier int      `json:"target_tier"` // 0=critical ... 3=dev
	Action     string   `json:"action"`
}

// Decide evaluates policy. For each effective role we look up the most-specific
// rule (kind match wins over '*') and pick the most permissive overall:
//   - allow if any role's rule allows
//   - require_approval if any matching rule requires it
//   - union of allowed_commands and denied_commands
//   - deny wins ties on the per-command filter (see CommandAllowed)
func (e *Engine) Decide(ctx context.Context, in Input) (Decision, error) {
	roles := in.Roles
	if len(roles) == 0 && in.Role != "" {
		roles = []string{in.Role}
	}
	if len(roles) == 0 {
		return Decision{Reasons: []string{"no role"}}, nil
	}

	final := Decision{}
	allowSeen := false
	allowedSet := map[string]bool{}
	deniedSet := map[string]bool{}

	// Family is the vendor root of a kind: "cisco-ios" -> "cisco". OS kinds
	// like "ubuntu" also match policies written for "linux".
	exactKind := strings.ToLower(strings.TrimSpace(in.TargetKind))
	family := exactKind
	if i := strings.Index(exactKind, "-"); i > 0 {
		family = exactKind[:i]
	}
	matchKinds := policyMatchKinds(exactKind, family)

	for _, role := range roles {
		query := fmt.Sprintf(`
			SELECT target_kind, tier_max, require_approval, allowed_commands, denied_commands
			FROM policies
			WHERE role = ? AND target_kind IN (%s)
			ORDER BY CASE
			           WHEN target_kind = ? THEN 0
			           WHEN target_kind = ? THEN 1
			           WHEN target_kind = 'linux' THEN 2
			           ELSE 3
			         END
			LIMIT 1`, sqlPlaceholders(len(matchKinds)))
		args := make([]any, 0, 1+len(matchKinds)+2)
		args = append(args, role)
		for _, k := range matchKinds {
			args = append(args, k)
		}
		args = append(args, exactKind, family)
		row := e.DB.QueryRowContext(ctx, query, args...)
		var (
			kind            string
			tierMax         int
			requireApproval int
			allowedCSV      string
			deniedCSV       string
		)
		err := row.Scan(&kind, &tierMax, &requireApproval, &allowedCSV, &deniedCSV)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return Decision{}, err
		}
		// tier_max is the highest target tier number this role may reach
		// (T0=critical … T3=dev). Deny when the machine is more dev than allowed.
		if in.TargetTier > tierMax {
			continue
		}
		allowSeen = true
		if requireApproval != 0 {
			final.RequireApproval = true
		}
		for _, c := range splitCSV(allowedCSV) {
			allowedSet[c] = true
		}
		for _, c := range splitCSV(deniedCSV) {
			deniedSet[c] = true
		}
	}

	if !allowSeen {
		final.Allow = false
		final.Reasons = []string{"no matching policy for any effective role/tier"}
		return final, nil
	}
	final.Allow = true
	for c := range allowedSet {
		final.AllowedCmds = append(final.AllowedCmds, c)
	}
	for c := range deniedSet {
		final.DeniedCmds = append(final.DeniedCmds, c)
	}
	return final, nil
}

// policyMatchKinds returns the target_kind values that may match a machine kind.
func policyMatchKinds(exactKind, family string) []string {
	seen := map[string]bool{"*": true}
	add := func(k string) {
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "" {
			seen[k] = true
		}
	}
	add(exactKind)
	add(family)
	switch family {
	case "ubuntu", "debian", "rhel", "centos", "rocky", "alma", "suse", "linux":
		add("linux")
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func sqlPlaceholders(n int) string {
	if n <= 0 {
		return "''"
	}
	parts := make([]string, n)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
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
