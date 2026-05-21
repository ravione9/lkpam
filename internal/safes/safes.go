// Package safes implements the CyberArk "safe" concept — an organizational
// container that holds privileged accounts (managed credentials) together
// with the access policy governing who may use them.
//
// A safe has:
//   - a name + description
//   - CPM (Central Policy Manager) settings: whether passwords inside the
//     safe auto-rotate and the rotation cadence
//   - dual-control flag: whether checking out a credential needs an approval
//   - a member list mapping users or groups to permission levels
//     (owner | use | view)
package safes

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/example/pam-platform/internal/db"
)

// Permission levels on a safe.
const (
	PermOwner = "owner" // can manage members and accounts
	PermUse   = "use"   // can checkout / connect using accounts
	PermView  = "view"  // can see metadata, not credentials
)

// PrincipalType values for safe members.
const (
	PrincipalUser  = "user"
	PrincipalGroup = "group"
)

// Safe is a managed credential container.
type Safe struct {
	ID                 int64  `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	CPMEnabled         bool   `json:"cpm_enabled"`
	RotationDays       int    `json:"rotation_days"`
	RequireDualControl bool   `json:"require_dual_control"`
	CreatedAt          int64  `json:"created_at"`
	Accounts           int    `json:"accounts,omitempty"`
	Members            int    `json:"members,omitempty"`
}

// Member is a (user|group) → permission mapping.
type Member struct {
	SafeID        int64  `json:"safe_id"`
	PrincipalType string `json:"principal_type"`
	PrincipalID   int64  `json:"principal_id"`
	PrincipalName string `json:"principal_name,omitempty"`
	Permissions   string `json:"permissions"`
	AddedAt       int64  `json:"added_at"`
}

// Service is the safe CRUD facade.
type Service struct{ DB *db.DB }

// List returns all safes with account + member counts.
func (s *Service) List(ctx context.Context) ([]Safe, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT s.id, s.name, s.description, s.cpm_enabled, s.rotation_days,
		       s.require_dual_control, s.created_at,
		       (SELECT COUNT(*) FROM privileged_accounts a WHERE a.safe_id = s.id),
		       (SELECT COUNT(*) FROM safe_members m WHERE m.safe_id = s.id)
		FROM safes s ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Safe
	for rows.Next() {
		var sf Safe
		var cpm, dual int
		if err := rows.Scan(&sf.ID, &sf.Name, &sf.Description, &cpm, &sf.RotationDays,
			&dual, &sf.CreatedAt, &sf.Accounts, &sf.Members); err != nil {
			return nil, err
		}
		sf.CPMEnabled = cpm != 0
		sf.RequireDualControl = dual != 0
		out = append(out, sf)
	}
	return out, rows.Err()
}

// Get returns one safe by ID.
func (s *Service) Get(ctx context.Context, id int64) (*Safe, error) {
	var sf Safe
	var cpm, dual int
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, name, description, cpm_enabled, rotation_days,
		       require_dual_control, created_at
		FROM safes WHERE id = ?`, id).Scan(
		&sf.ID, &sf.Name, &sf.Description, &cpm, &sf.RotationDays,
		&dual, &sf.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.New("safe not found")
	}
	if err != nil {
		return nil, err
	}
	sf.CPMEnabled = cpm != 0
	sf.RequireDualControl = dual != 0
	return &sf, nil
}

// Create inserts a new safe.
func (s *Service) Create(ctx context.Context, sf Safe) (int64, error) {
	name := strings.TrimSpace(sf.Name)
	if name == "" {
		return 0, errors.New("safe name required")
	}
	if sf.RotationDays <= 0 {
		sf.RotationDays = 90
	}
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO safes(name, description, cpm_enabled, rotation_days,
		                  require_dual_control, created_at)
		VALUES(?,?,?,?,?,?)`,
		name, sf.Description, boolInt(sf.CPMEnabled), sf.RotationDays,
		boolInt(sf.RequireDualControl), db.Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Update modifies an existing safe.
func (s *Service) Update(ctx context.Context, sf Safe) error {
	if sf.ID <= 0 {
		return errors.New("id required")
	}
	if sf.RotationDays <= 0 {
		sf.RotationDays = 90
	}
	res, err := s.DB.ExecContext(ctx, `
		UPDATE safes SET description=?, cpm_enabled=?, rotation_days=?,
		                 require_dual_control=?
		WHERE id=?`,
		sf.Description, boolInt(sf.CPMEnabled), sf.RotationDays,
		boolInt(sf.RequireDualControl), sf.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("safe not found")
	}
	return nil
}

// Delete removes a safe. Accounts in the safe must be deleted first.
func (s *Service) Delete(ctx context.Context, id int64) error {
	var n int
	_ = s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM privileged_accounts WHERE safe_id=?`, id).Scan(&n)
	if n > 0 {
		return errors.New("safe still contains accounts")
	}
	res, err := s.DB.ExecContext(ctx, `DELETE FROM safes WHERE id=?`, id)
	if err != nil {
		return err
	}
	rn, _ := res.RowsAffected()
	if rn == 0 {
		return errors.New("safe not found")
	}
	return nil
}

// ListMembers returns members of a safe with principal name resolved.
func (s *Service) ListMembers(ctx context.Context, safeID int64) ([]Member, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT m.safe_id, m.principal_type, m.principal_id, m.permissions, m.added_at,
		       COALESCE(
		         CASE m.principal_type
		           WHEN 'user' THEN (SELECT username FROM users WHERE id = m.principal_id)
		           WHEN 'group' THEN (SELECT name FROM groups WHERE id = m.principal_id)
		         END, '')
		FROM safe_members m WHERE m.safe_id = ?
		ORDER BY m.principal_type, m.principal_id`, safeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.SafeID, &m.PrincipalType, &m.PrincipalID,
			&m.Permissions, &m.AddedAt, &m.PrincipalName); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AddMember grants permission on a safe to a user or group.
func (s *Service) AddMember(ctx context.Context, safeID int64, ptype string,
	principalID int64, perms string) error {
	if ptype != PrincipalUser && ptype != PrincipalGroup {
		return errors.New("principal_type must be 'user' or 'group'")
	}
	if perms == "" {
		perms = PermUse
	}
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO safe_members(safe_id, principal_type, principal_id, permissions, added_at)
		VALUES(?,?,?,?,?)
		ON CONFLICT(safe_id, principal_type, principal_id) DO UPDATE SET
		  permissions = excluded.permissions`,
		safeID, ptype, principalID, perms, db.Now())
	return err
}

// RemoveMember revokes a member.
func (s *Service) RemoveMember(ctx context.Context, safeID int64, ptype string, principalID int64) error {
	_, err := s.DB.ExecContext(ctx, `
		DELETE FROM safe_members
		WHERE safe_id=? AND principal_type=? AND principal_id=?`,
		safeID, ptype, principalID)
	return err
}

// UserPermission returns the highest permission a user has on a safe, computed
// from direct membership + group memberships. Returns "" if no access.
func (s *Service) UserPermission(ctx context.Context, safeID, userID int64) (string, error) {
	var perms []string
	rows, err := s.DB.QueryContext(ctx, `
		SELECT permissions FROM safe_members
		WHERE safe_id = ? AND principal_type = 'user' AND principal_id = ?
		UNION ALL
		SELECT m.permissions FROM safe_members m
		JOIN user_groups ug ON ug.group_id = m.principal_id
		WHERE m.safe_id = ? AND m.principal_type = 'group' AND ug.user_id = ?`,
		safeID, userID, safeID, userID)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return "", err
		}
		perms = append(perms, p)
	}
	return highestPerm(perms), nil
}

func highestPerm(ps []string) string {
	rank := map[string]int{PermView: 1, PermUse: 2, PermOwner: 3}
	best := ""
	bestRank := 0
	for _, p := range ps {
		if r := rank[p]; r > bestRank {
			best, bestRank = p, r
		}
	}
	return best
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
