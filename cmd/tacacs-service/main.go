// tacacs-service is the TACACS+ AAA server that network devices point at.
//
// Cisco IOS sample config:
//
//   aaa new-model
//   aaa group server tacacs+ PAM
//    server-private 10.20.30.40 key STRONG-SECRET
//   aaa authentication login LOCAL-TACACS-BOTH local group PAM
//   aaa authentication enable LOCAL-TACACS-BOTH local group PAM enable
//   aaa authorization commands 15 default group PAM none
//   aaa accounting commands 15 default start-stop group PAM
package main

import (
	"context"
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
	"github.com/example/pam-platform/internal/tacacs"
	"github.com/example/pam-platform/internal/vault"
)

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

	srv := &tacacs.Server{
		Addr:             config.Get("PAM_TACACS_ADDR", ":49"),
		Secret:           secret,
		DB:               d,
		Policy:           &policy.Engine{DB: d},
		Groups:           &groups.Service{DB: d},
		Bus:              events.NewForwarder(events.New(), config.Get("PAM_AUDIT_URL", "http://audit:8085")),
		Auth:             authclient.New(config.Get("PAM_AUTH_URL", "http://auth:8081")),
		Vault:            v,
		UnknownUserDefer:        tacacs.ParseUnknownUserDefer(config.Get("PAM_TACACS_UNKNOWN_USER", "error")),
		FortinetMemberOf:        config.Get("PAM_TACACS_FORTINET_MEMBEROF", "PAM-Admins"),
		// Per-role FortiGate admin profile mapping.
		// Format: "pam_role=fortinet_profile,pam_role2=profile2"
		// Example: "admin=super_admin,secops=read_write,netops=prof_admin,user=no_access,viewer=no_access"
		// Roles not listed fall back to built-in defaults (admin/secops=super_admin, else=prof_admin).
		FortinetRoleProfileMap:  tacacs.ParseRoleMap(config.Get("PAM_TACACS_FORTINET_PROFILES", "")),
		// Per-role FortiGate memberof group mapping.
		// Format: "pam_role=FortiGate-Group-Name,..."
		// Example: "admin=PAM-SuperAdmins,secops=PAM-SecOps,netops=PAM-NetAdmins,user=PAM-ReadOnly"
		// Falls back to PAM_TACACS_FORTINET_MEMBEROF when a role is not listed.
		FortinetRoleMemberofMap: tacacs.ParseRoleMap(config.Get("PAM_TACACS_FORTINET_MEMBEROF_MAP", "")),
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
