// Package settings is a key-value store for system configuration that doesn't
// fit cleanly into a strongly-typed table — LDAP server URL, MFA enforcement
// mode, system banner, etc. Sensitive values (e.g. LDAP bind password) are
// stored in the vault under reserved secret names, not here.
package settings

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/example/pam-platform/internal/db"
)

// Store is the settings persistence layer.
type Store struct{ DB *db.DB }

// Get returns the value for key, or "" if unset.
func (s *Store) Get(ctx context.Context, key string) (string, error) {
	var v string
	err := s.DB.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// Set upserts a key/value pair.
func (s *Store) Set(ctx context.Context, key, value string) error {
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO settings(key, value, updated_at) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, db.Now())
	return err
}

// GetJSON decodes the stored JSON value into v. Returns nil with v untouched
// if the key is unset.
func (s *Store) GetJSON(ctx context.Context, key string, v any) error {
	raw, err := s.Get(ctx, key)
	if err != nil || raw == "" {
		return err
	}
	return json.Unmarshal([]byte(raw), v)
}

// SetJSON marshals v as JSON and stores it under key.
func (s *Store) SetJSON(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Set(ctx, key, string(b))
}

// All returns every setting (for the admin UI).
func (s *Store) All(ctx context.Context) (map[string]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}
