// Package inventory manages privileged targets (servers, network devices,
// firewalls, hypervisors, databases, web management consoles, etc.).
//
// A target is identified by:
//   - kind        — vendor + product family (e.g. "cisco-ios", "fortinet-fortigate")
//   - connection  — protocol the proxy / client uses to reach it
//                   (ssh | rdp | web | telnet | https-api)
//   - host/port   — for ssh/rdp/telnet
//   - web_url     — for web / https-api connections (full URL of the admin GUI)
package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/example/pam-platform/internal/db"
)

// Connection types.
const (
	ConnSSH    = "ssh"
	ConnRDP    = "rdp"
	ConnWeb    = "web"
	ConnTelnet = "telnet"
	ConnAPI    = "https-api"
)

// Target is a managed asset users connect to via the SSH proxy / launcher.
type Target struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Kind           string `json:"kind"`            // platform identifier, e.g. "cisco-ios"
	Vendor         string `json:"vendor"`          // free-form vendor label
	OSVersion      string `json:"os_version"`      // optional version (e.g. "IOS 16.9")
	ConnectionType string `json:"connection_type"` // ssh | rdp | web | telnet | https-api
	Host           string `json:"host"`            // for ssh/rdp/telnet
	Port           int    `json:"port"`            // for ssh/rdp/telnet
	WebURL         string `json:"web_url"`         // for web / https-api
	Tier           int    `json:"tier"`
	Tags           string `json:"tags"`
}

// Service provides target CRUD.
type Service struct{ DB *db.DB }

// List returns all targets ordered by name.
func (s *Service) List(ctx context.Context) ([]Target, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, name, kind, COALESCE(vendor,''), COALESCE(os_version,''),
		       COALESCE(connection_type,'ssh'), host, port,
		       COALESCE(web_url,''), tier, tags
		FROM targets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Target
	for rows.Next() {
		var t Target
		if err := rows.Scan(&t.ID, &t.Name, &t.Kind, &t.Vendor, &t.OSVersion,
			&t.ConnectionType, &t.Host, &t.Port, &t.WebURL, &t.Tier, &t.Tags); err != nil {
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
		SELECT id, name, kind, COALESCE(vendor,''), COALESCE(os_version,''),
		       COALESCE(connection_type,'ssh'), host, port,
		       COALESCE(web_url,''), tier, tags
		FROM targets WHERE id = ?`, id).Scan(
		&t.ID, &t.Name, &t.Kind, &t.Vendor, &t.OSVersion,
		&t.ConnectionType, &t.Host, &t.Port, &t.WebURL, &t.Tier, &t.Tags)
	if err == sql.ErrNoRows {
		return t, errors.New("target not found")
	}
	return t, err
}

// Create inserts a new target.
func (s *Service) Create(ctx context.Context, t Target) (int64, error) {
	if t.Name == "" || t.Kind == "" {
		return 0, errors.New("name and kind are required")
	}
	if t.ConnectionType == "" {
		t.ConnectionType = ConnSSH
	}
	if err := validateConnection(t); err != nil {
		return 0, err
	}
	if t.Port <= 0 {
		t.Port = defaultPort(t.ConnectionType)
	}
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO targets(name, kind, vendor, os_version, connection_type,
		                    host, port, web_url, tier, tags)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		t.Name, t.Kind, t.Vendor, t.OSVersion, t.ConnectionType,
		t.Host, t.Port, t.WebURL, t.Tier, t.Tags)
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
	if t.ConnectionType == "" {
		t.ConnectionType = ConnSSH
	}
	if err := validateConnection(t); err != nil {
		return err
	}
	if t.Port <= 0 {
		t.Port = defaultPort(t.ConnectionType)
	}
	res, err := s.DB.ExecContext(ctx, `
		UPDATE targets SET name=?, kind=?, vendor=?, os_version=?,
		  connection_type=?, host=?, port=?, web_url=?, tier=?, tags=?
		WHERE id=?`,
		t.Name, t.Kind, t.Vendor, t.OSVersion, t.ConnectionType,
		t.Host, t.Port, t.WebURL, t.Tier, t.Tags, t.ID)
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

// validateConnection enforces the right addressing for each protocol.
func validateConnection(t Target) error {
	switch t.ConnectionType {
	case ConnSSH, ConnRDP, ConnTelnet:
		if t.Host == "" {
			return errors.New("host is required for ssh/rdp/telnet connections")
		}
	case ConnWeb, ConnAPI:
		if t.WebURL == "" {
			return errors.New("web_url is required for web / https-api connections")
		}
	default:
		return errors.New("unknown connection_type")
	}
	return nil
}

// defaultPort returns the conventional port for a connection type.
func defaultPort(connType string) int {
	switch connType {
	case ConnRDP:
		return 3389
	case ConnTelnet:
		return 23
	case ConnWeb, ConnAPI:
		return 443
	default:
		return 22
	}
}
