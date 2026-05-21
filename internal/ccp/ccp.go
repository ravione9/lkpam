// Package ccp is the Central Credential Provider — the REST API that
// applications (CI runners, batch jobs, etc.) use to fetch privileged
// credentials at runtime without ever embedding them in code.
//
// Auth model:
//   - Each application has an `app_credentials` row with a unique API key
//     (stored hashed) and an optional CIDR allowlist.
//   - The app calls GET /ccp/accounts?app=<name>&account=<account>
//     with the header `X-API-Key: <plaintext>`.
//   - We hash the header value, look up the row, check allowlists, then
//     decrypt and return the password.
//
// In CyberArk this is "AAM / Conjur" with significantly more features
// (rotation hooks, policy languages, sidecar injection). The reference
// implementation here is intentionally simple but production-shaped.
package ccp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/example/pam-platform/internal/db"
)

// App is one application credential row.
type App struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	SafeID          *int64 `json:"safe_id,omitempty"`
	SafeName        string `json:"safe_name,omitempty"`
	AllowedAccounts string `json:"allowed_accounts"` // CSV or "*"
	ClientIPAllow   string `json:"client_ip_allow"`  // CSV of CIDRs
	Enabled         bool   `json:"enabled"`
	LastUsed        *int64 `json:"last_used,omitempty"`
	CreatedAt       int64  `json:"created_at"`
}

// CreateResult includes the plaintext API key — shown only at creation time.
type CreateResult struct {
	ID     int64  `json:"id"`
	APIKey string `json:"api_key"`
}

// Service is the CCP CRUD + lookup facade.
type Service struct{ DB *db.DB }

// List returns all app credentials.
func (s *Service) List(ctx context.Context) ([]App, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT a.id, a.name, a.safe_id, COALESCE(sf.name,''),
		       a.allowed_accounts, a.client_ip_allow, a.enabled,
		       a.last_used, a.created_at
		FROM app_credentials a
		LEFT JOIN safes sf ON sf.id = a.safe_id
		ORDER BY a.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []App
	for rows.Next() {
		var a App
		var sid, last sql.NullInt64
		var en int
		if err := rows.Scan(&a.ID, &a.Name, &sid, &a.SafeName,
			&a.AllowedAccounts, &a.ClientIPAllow, &en, &last, &a.CreatedAt); err != nil {
			return nil, err
		}
		if sid.Valid {
			a.SafeID = &sid.Int64
		}
		if last.Valid {
			a.LastUsed = &last.Int64
		}
		a.Enabled = en != 0
		out = append(out, a)
	}
	return out, rows.Err()
}

// Create inserts a new application with a freshly-generated API key.
// The plaintext is returned ONCE and never stored.
func (s *Service) Create(ctx context.Context, a App) (*CreateResult, error) {
	name := strings.TrimSpace(a.Name)
	if name == "" {
		return nil, errors.New("application name required")
	}
	plain, hash := newAPIKey()
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO app_credentials(name, api_key_hash, safe_id, allowed_accounts,
		  client_ip_allow, enabled, created_at)
		VALUES(?,?,?,?,?,?,?)`,
		name, hash, nullableInt(a.SafeID), a.AllowedAccounts,
		a.ClientIPAllow, boolInt(a.Enabled), db.Now())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &CreateResult{ID: id, APIKey: plain}, nil
}

// Update modifies a credential (cannot change the key — rotate to do that).
func (s *Service) Update(ctx context.Context, a App) error {
	if a.ID <= 0 {
		return errors.New("id required")
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE app_credentials SET safe_id=?, allowed_accounts=?,
		  client_ip_allow=?, enabled=?
		WHERE id=?`,
		nullableInt(a.SafeID), a.AllowedAccounts, a.ClientIPAllow,
		boolInt(a.Enabled), a.ID)
	return err
}

// Rotate generates a new API key and returns the plaintext once.
func (s *Service) Rotate(ctx context.Context, id int64) (*CreateResult, error) {
	plain, hash := newAPIKey()
	res, err := s.DB.ExecContext(ctx,
		`UPDATE app_credentials SET api_key_hash=? WHERE id=?`, hash, id)
	if err != nil {
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, errors.New("app not found")
	}
	return &CreateResult{ID: id, APIKey: plain}, nil
}

// Delete removes an application.
func (s *Service) Delete(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM app_credentials WHERE id=?`, id)
	return err
}

// Authenticate validates an API key (plaintext) + caller IP and returns the
// row. On success it updates last_used.
func (s *Service) Authenticate(ctx context.Context, apiKey, clientIP string) (*App, error) {
	if apiKey == "" {
		return nil, errors.New("missing X-API-Key header")
	}
	hash := hashAPIKey(apiKey)
	var a App
	var sid, last sql.NullInt64
	var en int
	err := s.DB.QueryRowContext(ctx, `
		SELECT a.id, a.name, a.safe_id, COALESCE(sf.name,''),
		       a.allowed_accounts, a.client_ip_allow, a.enabled,
		       a.last_used, a.created_at
		FROM app_credentials a
		LEFT JOIN safes sf ON sf.id = a.safe_id
		WHERE a.api_key_hash = ?`, hash).Scan(
		&a.ID, &a.Name, &sid, &a.SafeName,
		&a.AllowedAccounts, &a.ClientIPAllow, &en, &last, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, errors.New("invalid api key")
	}
	if err != nil {
		return nil, err
	}
	a.Enabled = en != 0
	if !a.Enabled {
		return nil, errors.New("application disabled")
	}
	if sid.Valid {
		a.SafeID = &sid.Int64
	}
	if last.Valid {
		a.LastUsed = &last.Int64
	}
	if a.ClientIPAllow != "" && !ipAllowed(clientIP, a.ClientIPAllow) {
		return nil, errors.New("client IP not allowed")
	}
	_, _ = s.DB.ExecContext(ctx, `UPDATE app_credentials SET last_used=? WHERE id=?`, db.Now(), a.ID)
	return &a, nil
}

// AccountAllowed reports whether the given account id (or name) is permitted
// by this app's allowed_accounts list.
func (a *App) AccountAllowed(accountID int64, accountName string) bool {
	if a.AllowedAccounts == "" || a.AllowedAccounts == "*" {
		return true
	}
	idStr := strconv.FormatInt(accountID, 10)
	for _, p := range strings.Split(a.AllowedAccounts, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == idStr || strings.EqualFold(p, accountName) {
			return true
		}
	}
	return false
}

// --- helpers ---

func newAPIKey() (plaintext, hash string) {
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	plaintext = "pam_" + base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(buf)
	hash = hashAPIKey(plaintext)
	return
}

func hashAPIKey(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

func ipAllowed(client, csv string) bool {
	if client == "" {
		return false
	}
	host := client
	if h, _, err := net.SplitHostPort(client); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, p := range strings.Split(csv, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			if ip.String() == p {
				return true
			}
			continue
		}
		_, cidr, err := net.ParseCIDR(p)
		if err == nil && cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableInt(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
