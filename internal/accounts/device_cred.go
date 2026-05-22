package accounts

import (
	"context"
	"database/sql"
	"strings"
)

// DevicePasswordForHost returns the privileged-account password for a target
// identified by NAS/host IP (used for Cisco enable and TACACS enable auth).
func (s *Service) DevicePasswordForHost(ctx context.Context, hostOrAddr string) (string, error) {
	host := hostOrAddr
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", sql.ErrNoRows
	}
	var secretRef string
	err := s.DB.QueryRowContext(ctx, `
		SELECT a.secret_ref
		FROM privileged_accounts a
		JOIN targets t ON t.id = a.target_id
		WHERE (t.host = ? OR t.host = ?)
		  AND LOWER(a.platform) NOT IN ('windows','rdp')
		ORDER BY a.id
		LIMIT 1`, host, hostOrAddr).Scan(&secretRef)
	if err != nil {
		return "", err
	}
	if s.Vault == nil {
		return "", sql.ErrNoRows
	}
	pw, err := s.Vault.GetSecret(ctx, secretRef)
	if err != nil || len(pw) == 0 {
		return "", err
	}
	return string(pw), nil
}
