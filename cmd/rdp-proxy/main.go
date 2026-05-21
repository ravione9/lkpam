// rdp-proxy is the RDP data-plane. Browser clients connect via the Guacamole
// WebSocket protocol; this service tunnels to guacd which connects to the
// target Windows host and writes a .guac session recording.
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
	"github.com/example/pam-platform/internal/rdpproxy"
	"github.com/example/pam-platform/internal/vault"
)

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("rdp-proxy: db: %v", err)
	}
	defer d.Close()

	v, err := vault.New(d, config.Get("PAM_MASTER_KEY", ""))
	if err != nil {
		log.Fatalf("rdp-proxy: vault: %v", err)
	}

	srv := &rdpproxy.Server{
		DB:           d,
		Vault:        v,
		Auth:         authclient.New(config.Get("PAM_AUTH_URL", "http://auth:8081")),
		GuacdAddr:    config.Get("PAM_GUACD_ADDR", "guacd:4822"),
		RecordingDir: config.Get("PAM_REC_DIR", "/recordings"),
		ListenAddr:   config.Get("PAM_RDP_PROXY_ADDR", ":8086"),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("shutting down rdp-proxy")
		cancel()
	}()

	if err := srv.Run(ctx); err != nil {
		log.Fatalf("rdp-proxy: %v", err)
	}
}
