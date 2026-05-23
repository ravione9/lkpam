package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"


)

// Location is a site / plant / datacenter used to group managed machines.
type Location struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	SortOrder   int    `json:"sort_order"`
}

// ListLocations returns all locations ordered for display.
func (s *Service) ListLocations(ctx context.Context) ([]Location, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, name, COALESCE(description,''), sort_order
		FROM locations
		ORDER BY sort_order ASC, name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Location
	for rows.Next() {
		var loc Location
		if err := rows.Scan(&loc.ID, &loc.Name, &loc.Description, &loc.SortOrder); err != nil {
			return nil, err
		}
		out = append(out, loc)
	}
	return out, rows.Err()
}

// GetLocation returns one location by ID.
func (s *Service) GetLocation(ctx context.Context, id int64) (Location, error) {
	var loc Location
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, name, COALESCE(description,''), sort_order
		FROM locations WHERE id = ?`, id).Scan(
		&loc.ID, &loc.Name, &loc.Description, &loc.SortOrder)
	if err == sql.ErrNoRows {
		return loc, errors.New("location not found")
	}
	return loc, err
}

// CreateLocation inserts a new location.
func (s *Service) CreateLocation(ctx context.Context, loc Location) (int64, error) {
	if loc.Name == "" {
		return 0, errors.New("name is required")
	}
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO locations(name, description, sort_order, created_at)
		VALUES(?,?,?,?)`,
		loc.Name, loc.Description, loc.SortOrder, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("insert location: %w", err)
	}
	return res.LastInsertId()
}

// UpdateLocation modifies an existing location.
func (s *Service) UpdateLocation(ctx context.Context, loc Location) error {
	if loc.ID <= 0 {
		return errors.New("id required")
	}
	if loc.Name == "" {
		return errors.New("name is required")
	}
	res, err := s.DB.ExecContext(ctx, `
		UPDATE locations SET name=?, description=?, sort_order=?
		WHERE id=?`,
		loc.Name, loc.Description, loc.SortOrder, loc.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("location not found")
	}
	return nil
}

// DeleteLocation removes a location; machines are unassigned (location_id cleared).
func (s *Service) DeleteLocation(ctx context.Context, id int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE targets SET location_id = NULL WHERE location_id = ?`, id); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM locations WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("location not found")
	}
	return tx.Commit()
}

// LocationDeviceCount returns how many targets are assigned to each location.
func (s *Service) LocationDeviceCount(ctx context.Context) (map[int64]int, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT location_id, COUNT(*) FROM targets
		WHERE location_id IS NOT NULL
		GROUP BY location_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[int64]int)
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
