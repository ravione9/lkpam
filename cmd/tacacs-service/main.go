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

	// Load FortiGate role mappings from the DB (configured via UI).
	// Also reloaded on each FortiGate authorization request.
	forti := tacacs.LoadFortinetConfigFromDB(d)
	if len(forti.RoleProfiles) > 0 {
		log.Printf("tacacs: loaded FortiGate profile map (%d roles)", len(forti.RoleProfiles))
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
