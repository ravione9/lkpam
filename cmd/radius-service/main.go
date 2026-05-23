// radius-service is the RADIUS AAA server for devices that don't speak
// TACACS+: HP / Aruba switches (ProCurve, CX), MikroTik, F5, Palo Alto admin
// login, older Cisco AAA, Juniper Junos, Huawei VRP, VPN concentrators, and
// WiFi controllers.
//
// Listens on UDP/1812 (authentication) and UDP/1813 (accounting) by default.
//
// Per-device shared secrets live in the radius_clients table — manage them
// from the portal Settings page. The PAM_RADIUS_SECRET env var is the global
// fallback used when no row matches the NAS-IP.
//
// HP/Aruba ProCurve example (CLI):
//
//	radius-server host 10.20.30.40 key STRONG-SECRET
//	aaa authentication ssh login radius local
//	aaa authentication console enable radius local
//	aaa authorization commands radius
//	aaa accounting commands start-stop radius
//	aaa authentication login privilege-mode
//
// Palo Alto admin login (panorama / firewall):
//
//	Device > Server Profiles > RADIUS: add PAM (10.20.30.40, secret, 1812)
//	Device > Authentication Profile: tie Type=RADIUS, Server Profile=PAM
//	Device > Admin Roles: ensure "superuser" exists (it's the default)
//	Device > Administrators: set Authentication Profile = the new one
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/example/pam-platform/internal/authclient"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/radius"
	"github.com/example/pam-platform/internal/vault"
)

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("radius: db: %v", err)
	}
	defer d.Close()

	v, err := vault.New(d, config.Get("PAM_MASTER_KEY", ""))
	if err != nil {
		log.Fatalf("radius: vault: %v", err)
	}

	secret := []byte(config.Get("PAM_RADIUS_SECRET", "change-me"))
	if string(secret) == "change-me" {
		log.Printf("WARNING: using default RADIUS shared secret; set PAM_RADIUS_SECRET")
	}

	clients := radius.NewClientStore(d, secret)

	srv := &radius.Server{
		AuthAddr:        config.Get("PAM_RADIUS_AUTH_ADDR", ":1812"),
		AcctAddr:        config.Get("PAM_RADIUS_ACCT_ADDR", ":1813"),
		Clients:         clients,
		DB:              d,
		Auth:            authclient.New(config.Get("PAM_AUTH_URL", "http://auth:8081")),
		Vault:           v,
		Policy:          &policy.Engine{DB: d},
		Groups:          &groups.Service{DB: d},
		Bus:             events.NewForwarder(events.New(), config.Get("PAM_AUDIT_URL", "http://audit:8085")),
		UnknownUserDrop: strings.EqualFold(config.Get("PAM_RADIUS_UNKNOWN_USER", "reject"), "drop"),
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
