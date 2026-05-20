// tacacs-service is the TACACS+ AAA server that network devices point at.
//
// Cisco IOS sample config:
//
//   aaa new-model
//   aaa group server tacacs+ PAM
//    server-private 10.20.30.40 key STRONG-SECRET
//   aaa authentication login default group PAM local
//   aaa authorization commands 15 default group PAM if-authenticated
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
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/tacacs"
)

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("tacacs: db: %v", err)
	}
	defer d.Close()

	secret := []byte(config.Get("PAM_TACACS_SECRET", "change-me"))
	if string(secret) == "change-me" {
		log.Printf("WARNING: using default TACACS+ shared secret; set PAM_TACACS_SECRET")
	}

	srv := &tacacs.Server{
		Addr:   config.Get("PAM_TACACS_ADDR", ":49"),
		Secret: secret,
		DB:     d,
		Policy: &policy.Engine{DB: d},
		Bus:    events.New(),
		Auth:   authclient.New(config.Get("PAM_AUTH_URL", "http://auth:8081")),
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
