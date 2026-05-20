// Package inventory manages privileged targets (servers, network devices).
package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/example/pam-platform/internal/db"
)

// Target is a managed asset users connect to via the SSH proxy.
type Target struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
	Kind string `json:"kind"`
	Host string `json:"host"`
	Port int    `json:"port"`
	Tier int    `json:"tier"`
	Tags string `json:"tags"`
}

// Service provides target CRUD.
type Service struct{ DB *db.DB }

// List returns all targets ordered by name.
func (s *Service) List(ctx context.Context) ([]Target, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, name, kind, host, port, tier, tags
		FROM targets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.Name, &t.Kind, &t.Host, &t.Port, &t.Tier, &t.Tags); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Get returns a single target by ID.
func (s *Service) Get(ctx context.Context, id int64) (Target, error) {
	var t Target
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, name, kind, host, port, tier, tags
		FROM targets WHERE id = ?`, id).Scan(
		&t.ID, &t.Name, &t.Kind, &t.Host, &t.Port, &t.Tier, &t.Tags)
	if err == sql.ErrNoRows {
		return t, errors.New("target not found")
	}
	return t, err
}

// Create inserts a new target.
func (s *Service) Create(ctx context.Context, t Target) (int64, error) {
	if t.Name == "" || t.Host == "" || t.Kind == "" {
		return 0, errors.New("name, kind, and host are required")
	}
	if t.Port <= 0 {
		t.Port = 22
	}
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO targets(name, kind, host, port, tier, tags)
		VALUES(?,?,?,?,?,?)`,
		t.Name, t.Kind, t.Host, t.Port, t.Tier, t.Tags)
	if err != nil {
		return 0, fmt.Errorf("insert target: %w", err)
	}
	return res.LastInsertId()
}

// Update modifies an existing target.
func (s *Service) Update(ctx context.Context, t Target) error {
	if t.ID <= 0 {
		return errors.New("id required")
	}
	res, err := s.DB.ExecContext(ctx, `
		UPDATE targets SET name=?, kind=?, host=?, port=?, tier=?, tags=?
		WHERE id=?`,
		t.Name, t.Kind, t.Host, t.Port, t.Tier, t.Tags, t.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("target not found")
	}
	return nil
}

// Delete removes a target by ID.
func (s *Service) Delete(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM targets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("target not found")
	}
	return nil
}
