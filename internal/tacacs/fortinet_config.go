package tacacs

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"strings"

	"github.com/example/pam-platform/internal/db"
)

const fortinetSettingsKey = "tacacs_fortinet"

// FortinetConfig holds FortiGate TACACS+ VSA mappings.
type FortinetConfig struct {
	RoleProfiles    map[string]string `json:"role_profiles"`
	RoleMemberof    map[string]string `json:"role_memberof"`
	DefaultMemberof string            `json:"default_memberof"`
}

// LoadFortinetConfigFromDB reads portal settings, then falls back to env vars.
func LoadFortinetConfigFromDB(d *db.DB) FortinetConfig {
	ctx := context.Background()
	var raw string
	_ = d.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, fortinetSettingsKey).Scan(&raw)
	if raw != "" {
		var cfg FortinetConfig
		if err := json.Unmarshal([]byte(raw), &cfg); err == nil {
			if cfg.DefaultMemberof == "" {
				cfg.DefaultMemberof = envFortinetMemberof()
			}
			return cfg
		}
		log.Printf("tacacs: could not parse %s from DB: falling back to env vars", fortinetSettingsKey)
	}
	return FortinetConfig{
		DefaultMemberof: envFortinetMemberof(),
		RoleProfiles:    ParseRoleMap(os.Getenv("PAM_TACACS_FORTINET_PROFILES")),
		RoleMemberof:    ParseRoleMap(os.Getenv("PAM_TACACS_FORTINET_MEMBEROF_MAP")),
	}
}

func envFortinetMemberof() string {
	if v := strings.TrimSpace(os.Getenv("PAM_TACACS_FORTINET_MEMBEROF")); v != "" {
		return v
	}
	return "PAM-Admins"
}

func (s *Server) applyFortinetConfig(cfg FortinetConfig) {
	s.FortinetMemberOf = cfg.DefaultMemberof
	s.FortinetRoleProfileMap = cfg.RoleProfiles
	s.FortinetRoleMemberofMap = cfg.RoleMemberof
}

// refreshFortinetConfig reloads mappings from the DB on every FortiGate author
// so portal Settings changes apply without restarting pam-tacacs.
func (s *Server) refreshFortinetConfig() {
	if s.DB == nil {
		return
	}
	s.applyFortinetConfig(LoadFortinetConfigFromDB(s.DB))
}
