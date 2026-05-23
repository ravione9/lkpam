// tacacs-service is the TACACS+ AAA server that network devices point at.
//
// Cisco IOS sample config:
//
//	aaa new-model
//	aaa group server tacacs+ PAM
//	 server-private 10.20.30.40 key STRONG-SECRET
//	aaa authentication login LOCAL-TACACS-BOTH local group PAM
//	aaa authentication enable LOCAL-TACACS-BOTH local group PAM enable
//	aaa authorization commands 15 default group PAM none
//	aaa accounting commands 15 default start-stop group PAM
package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/pam-platform/internal/authclient"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/settings"
	"github.com/example/pam-platform/internal/tacacs"
	"github.com/example/pam-platform/internal/vault"
)

// tacacsFortinetConfig mirrors the struct in auth-service for reading from the DB.
type tacacsFortinetConfig struct {
	RoleProfiles    map[string]string `json:"role_profiles"`
	RoleMemberof    map[string]string `json:"role_memberof"`
	DefaultMemberof string            `json:"default_memberof"`
}

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("tacacs: db: %v", err)
	}
	defer d.Close()

	v, err := vault.New(d, config.Get("PAM_MASTER_KEY", ""))
	if err != nil {
		log.Fatalf("tacacs: vault: %v", err)
	}

	secret := []byte(config.Get("PAM_TACACS_SECRET", "change-me"))
	if string(secret) == "change-me" {
		log.Printf("WARNING: using default TACACS+ shared secret; set PAM_TACACS_SECRET")
	}

	// Load FortiGate role mappings from the DB (configured via UI).
	// Fall back to env vars when the DB entry is absent (upgrade path / headless deploys).
	store := &settings.Store{DB: d}
	forti := loadFortinetConfig(store, d)

	srv := &tacacs.Server{
		Addr:             config.Get("PAM_TACACS_ADDR", ":49"),
		Secret:           secret,
		DB:               d,
		Policy:           &policy.Engine{DB: d},
		Groups:           &groups.Service{DB: d},
		Bus:              events.NewForwarder(events.New(), config.Get("PAM_AUDIT_URL", "http://audit:8085")),
		Auth:             authclient.New(config.Get("PAM_AUTH_URL", "http://auth:8081")),
		Vault:            v,
		UnknownUserDefer:    tacacs.ParseUnknownUserDefer(config.Get("PAM_TACACS_UNKNOWN_USER", "error")),
		FortinetMemberOf:    forti.DefaultMemberof,
		FortinetRoleProfileMap:  forti.RoleProfiles,
		FortinetRoleMemberofMap: forti.RoleMemberof,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sigCh; cancel() }()

	if err := srv.Run(ctx); err != nil {
		log.Fatal(err)
	}
}

// loadFortinetConfig reads the FortiGate TACACS+ profile map from the DB settings.
// When the DB entry is absent or empty, it falls back to the legacy env vars so
// existing deployments keep working without any UI changes.
func loadFortinetConfig(store *settings.Store, d *db.DB) tacacsFortinetConfig {
	ctx := context.Background()

	// Try DB first (set via Settings → TACACS+ in the portal).
	var raw string
	_ = d.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = 'tacacs_fortinet'`).Scan(&raw)
	if raw != "" {
		var cfg tacacsFortinetConfig
		if err := json.Unmarshal([]byte(raw), &cfg); err == nil {
			// Ensure DefaultMemberof has a sensible value.
			if cfg.DefaultMemberof == "" {
				cfg.DefaultMemberof = config.Get("PAM_TACACS_FORTINET_MEMBEROF", "PAM-Admins")
			}
			log.Printf("tacacs: loaded FortiGate profile map from DB (%d roles)", len(cfg.RoleProfiles))
			return cfg
		}
		log.Printf("tacacs: could not parse tacacs_fortinet settings from DB: falling back to env vars")
	}

	// Fallback: build from env vars (legacy behaviour).
	cfg := tacacsFortinetConfig{
		DefaultMemberof: config.Get("PAM_TACACS_FORTINET_MEMBEROF", "PAM-Admins"),
		RoleProfiles:    tacacs.ParseRoleMap(config.Get("PAM_TACACS_FORTINET_PROFILES", "")),
		RoleMemberof:    tacacs.ParseRoleMap(config.Get("PAM_TACACS_FORTINET_MEMBEROF_MAP", "")),
	}
	if len(cfg.RoleProfiles) > 0 {
		log.Printf("tacacs: loaded FortiGate profile map from env vars (%d roles)", len(cfg.RoleProfiles))
	}
	return cfg
}
