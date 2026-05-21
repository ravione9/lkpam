// Package groups manages user groups and group memberships. Groups grant a
// role to all their members, which the policy engine consumes alongside the
// user's own role. This is how the platform models AD-style RBAC.
package groups

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/example/pam-platform/internal/db"
)

// Group is a named collection of users with an associated role.
type Group struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Role        string `json:"role"`
	LDAPDN      string `json:"ldap_dn,omitempty"`
	Source      string `json:"source"`
	CreatedAt   int64  `json:"created_at"`
	Members     int    `json:"members,omitempty"`
}

// Service provides group CRUD and membership operations.
type Service struct{ DB *db.DB }

// List returns all groups with member counts.
func (s *Service) List(ctx context.Context) ([]Group, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT g.id, g.name, g.description, g.role,
		       COALESCE(g.ldap_dn,''), g.source, g.created_at,
		       (SELECT COUNT(*) FROM user_groups ug WHERE ug.group_id = g.id) AS members
		FROM groups g ORDER BY g.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Role,
			&g.LDAPDN, &g.Source, &g.CreatedAt, &g.Members); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// Get returns a single group by ID.
func (s *Service) Get(ctx context.Context, id int64) (Group, error) {
	var g Group
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, name, description, role, COALESCE(ldap_dn,''), source, created_at
		FROM groups WHERE id = ?`, id).Scan(
		&g.ID, &g.Name, &g.Description, &g.Role, &g.LDAPDN, &g.Source, &g.CreatedAt)
	if err == sql.ErrNoRows {
		return g, errors.New("group not found")
	}
	return g, err
}

// Create inserts a new group.
func (s *Service) Create(ctx context.Context, g Group) (int64, error) {
	if g.Name == "" {
		return 0, errors.New("group name required")
	}
	if g.Role == "" {
		g.Role = "user"
	}
	if g.Source == "" {
		g.Source = "local"
	}
	var ldap any
	if g.LDAPDN != "" {
		ldap = g.LDAPDN
	}
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO groups(name, description, role, ldap_dn, source, created_at)
		VALUES(?,?,?,?,?,?)`,
		g.Name, g.Description, g.Role, ldap, g.Source, db.Now())
	if err != nil {
		return 0, fmt.Errorf("insert group: %w", err)
	}
	return res.LastInsertId()
}

// Update modifies an existing group's editable fields.
func (s *Service) Update(ctx context.Context, g Group) error {
	if g.ID <= 0 {
		return errors.New("id required")
	}
	if g.Role == "" {
		g.Role = "user"
	}
	var ldap any
	if g.LDAPDN != "" {
		ldap = g.LDAPDN
	}
	res, err := s.DB.ExecContext(ctx, `
		UPDATE groups SET description=?, role=?, ldap_dn=? WHERE id=?`,
		g.Description, g.Role, ldap, g.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("group not found")
	}
	return nil
}

// Delete removes a group and its memberships.
func (s *Service) Delete(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("group not found")
	}
	return nil
}

// AddMember inserts a user → group membership.
func (s *Service) AddMember(ctx context.Context, userID, groupID int64) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT OR IGNORE INTO user_groups(user_id, group_id, added_at)
		VALUES(?,?,?)`, userID, groupID, db.Now())
	return err
}

// RemoveMember deletes a user → group membership.
func (s *Service) RemoveMember(ctx context.Context, userID, groupID int64) error {
	_, err := s.DB.ExecContext(ctx,
		`DELETE FROM user_groups WHERE user_id=? AND group_id=?`, userID, groupID)
	return err
}

// Member is a user → group row enriched with the username.
type Member struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	AddedAt  int64  `json:"added_at"`
}

// ListMembers returns users in a group.
func (s *Service) ListMembers(ctx context.Context, groupID int64) ([]Member, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT u.id, u.username, COALESCE(u.email,''), ug.added_at
		FROM user_groups ug
		JOIN users u ON u.id = ug.user_id
		WHERE ug.group_id = ?
		ORDER BY u.username`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Username, &m.Email, &m.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// UserGroupIDs returns just the group IDs a user belongs to. Used by the
// approval matrix to check approver membership.
func (s *Service) UserGroupIDs(ctx context.Context, userID int64) ([]int64, error) {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT group_id FROM user_groups WHERE user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// UserGroups returns the groups a user belongs to.
func (s *Service) UserGroups(ctx context.Context, userID int64) ([]Group, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT g.id, g.name, g.description, g.role, COALESCE(g.ldap_dn,''),
		       g.source, g.created_at
		FROM user_groups ug
		JOIN groups g ON g.id = ug.group_id
		WHERE ug.user_id = ?
		ORDER BY g.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.Role,
			&g.LDAPDN, &g.Source, &g.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// EffectiveRoles returns the user's own role plus roles granted via group
// membership, sorted with most privileged first ("admin" wins).
func (s *Service) EffectiveRoles(ctx context.Context, userID int64, userRole string) ([]string, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT g.role FROM user_groups ug
		JOIN groups g ON g.id = ug.group_id
		WHERE ug.user_id = ?`, userID)
	if err != nil {
		return []string{userRole}, err
	}
	defer rows.Close()
	seen := map[string]bool{userRole: true}
	out := []string{userRole}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			continue
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// FindByLDAPDN returns the group with the given LDAP DN, if any.
func (s *Service) FindByLDAPDN(ctx context.Context, dn string) (*Group, error) {
	var g Group
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, name, description, role, COALESCE(ldap_dn,''), source, created_at
		FROM groups WHERE ldap_dn = ?`, dn).Scan(
		&g.ID, &g.Name, &g.Description, &g.Role, &g.LDAPDN, &g.Source, &g.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &g, nil
}

// ReplaceMemberships sets the user's groups to exactly the given list.
// Used during LDAP sync.
func (s *Service) ReplaceMemberships(ctx context.Context, userID int64, groupIDs []int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_groups WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, gid := range groupIDs {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO user_groups(user_id,group_id,added_at) VALUES(?,?,?)`,
			userID, gid, db.Now()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
