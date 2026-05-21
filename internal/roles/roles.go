// Package roles is the first-class role catalog. Roles used to be free-text
// strings sprinkled across the codebase — this package turns them into a
// managed resource so the admin UI can list, create, and delete them.
//
// Built-in roles are seeded on first run and cannot be deleted; custom roles
// are admin-defined and can be referenced from policies, groups, and users.
package roles

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/example/pam-platform/internal/db"
)

// Role is a named permission tier referenced by policies and groups.
type Role struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Builtin     bool   `json:"builtin"`
	CreatedAt   int64  `json:"created_at"`
	Users       int    `json:"users,omitempty"`
	Groups      int    `json:"groups,omitempty"`
	Policies    int    `json:"policies,omitempty"`
}

// Service provides CRUD over roles.
type Service struct{ DB *db.DB }

// Built-in role names (always present, cannot be deleted).
var builtinNames = []string{"admin", "netops", "secops", "sysadmin", "viewer", "user"}

// SeedBuiltins inserts the built-in roles if missing. Idempotent.
func (s *Service) SeedBuiltins(ctx context.Context) error {
	descs := map[string]string{
		"admin":    "Full administrative access to the PAM platform",
		"netops":   "Network operations — routers, switches, firewalls",
		"secops":   "Security operations — security appliances",
		"sysadmin": "Server administration — Linux/Windows hosts",
		"viewer":   "Read-only audit / compliance access",
		"user":     "Default low-privilege role",
	}
	for _, name := range builtinNames {
		_, err := s.DB.ExecContext(ctx, `
			INSERT INTO roles(name, description, builtin, created_at)
			VALUES(?,?,1,?)
			ON CONFLICT(name) DO UPDATE SET builtin=1`,
			name, descs[name], db.Now())
		if err != nil {
			return err
		}
	}
	return nil
}

// List returns all roles with usage counts.
func (s *Service) List(ctx context.Context) ([]Role, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT r.id, r.name, r.description, r.builtin, r.created_at,
		       (SELECT COUNT(*) FROM users    u WHERE u.role = r.name) AS users,
		       (SELECT COUNT(*) FROM groups   g WHERE g.role = r.name) AS groups_,
		       (SELECT COUNT(*) FROM policies p WHERE p.role = r.name) AS policies
		FROM roles r
		ORDER BY r.builtin DESC, r.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var r Role
		var bi int
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &bi, &r.CreatedAt,
			&r.Users, &r.Groups, &r.Policies); err != nil {
			return nil, err
		}
		r.Builtin = bi != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns a single role by name.
func (s *Service) Get(ctx context.Context, name string) (Role, error) {
	var r Role
	var bi int
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, name, description, builtin, created_at
		FROM roles WHERE name = ?`, name).Scan(
		&r.ID, &r.Name, &r.Description, &bi, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return r, errors.New("role not found")
	}
	r.Builtin = bi != 0
	return r, err
}

// Create inserts a new custom role.
func (s *Service) Create(ctx context.Context, r Role) (int64, error) {
	name := strings.TrimSpace(strings.ToLower(r.Name))
	if name == "" {
		return 0, errors.New("role name required")
	}
	if !validRoleName(name) {
		return 0, errors.New("role name must be lowercase alphanumeric / dashes / underscores")
	}
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO roles(name, description, builtin, created_at)
		VALUES(?,?,0,?)`, name, r.Description, db.Now())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Update changes a role's description (name is immutable).
func (s *Service) Update(ctx context.Context, id int64, description string) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE roles SET description=? WHERE id=?`, description, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("role not found")
	}
	return nil
}

// Delete removes a custom role. Built-in roles cannot be removed and roles
// still referenced by users/groups/policies are blocked.
func (s *Service) Delete(ctx context.Context, id int64) error {
	var name string
	var bi int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT name, builtin FROM roles WHERE id=?`, id).Scan(&name, &bi); err != nil {
		return errors.New("role not found")
	}
	if bi != 0 {
		return errors.New("built-in roles cannot be deleted")
	}
	var refs int
	if err := s.DB.QueryRowContext(ctx, `
		SELECT (SELECT COUNT(*) FROM users    WHERE role=?)
		     + (SELECT COUNT(*) FROM groups   WHERE role=?)
		     + (SELECT COUNT(*) FROM policies WHERE role=?)`,
		name, name, name).Scan(&refs); err != nil {
		return err
	}
	if refs > 0 {
		return errors.New("role still referenced by users, groups, or policies")
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM roles WHERE id=?`, id)
	return err
}

func validRoleName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}
