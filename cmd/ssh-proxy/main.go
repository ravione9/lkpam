// ssh-proxy is the SSH data plane. Privileged users connect here; the
// proxy then opens an outbound SSH session to the requested target using a
// vault-issued short-lived certificate.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/example/pam-platform/internal/authclient"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/sshproxy"
	"github.com/example/pam-platform/internal/vault"

	"golang.org/x/crypto/ssh"
)

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("ssh-proxy: db: %v", err)
	}
	defer d.Close()

	v, err := vault.New(d, config.Get("PAM_MASTER_KEY", ""))
	if err != nil {
		log.Fatalf("ssh-proxy: vault: %v", err)
	}

	hostSigner, err := loadOrCreateHostKey(v)
	if err != nil {
		log.Fatalf("ssh-proxy: host key: %v", err)
	}

	srv := &sshproxy.Server{
		Vault:        v,
		DB:           d,
		Policy:       &policy.Engine{DB: d},
		Bus:          events.New(),
		HostKey:      hostSigner,
		RecordingDir: config.Get("PAM_REC_DIR", "./recordings"),
		ListenAddr:   config.Get("PAM_SSH_PROXY_ADDR", ":2222"),
		Auth:         authclient.New(config.Get("PAM_AUTH_URL", "http://auth:8081")),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Printf("shutting down ssh-proxy")
		cancel()
	}()

	if err := srv.Run(ctx); err != nil {
		log.Fatalf("ssh-proxy: run: %v", err)
	}
}

// loadOrCreateHostKey reads the proxy's persistent SSH host key from the
// vault (creating one if absent). Keeping the host key stable means clients
// don't see "host key changed" warnings across restarts.
func loadOrCreateHostKey(v *vault.Vault) (ssh.Signer, error) {
	ctx := context.Background()
	if pemBytes, err := v.GetSecret(ctx, "_ssh_proxy_hostkey"); err == nil {
		return ssh.ParsePrivateKey(pemBytes)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "pam-ssh-proxy-host")
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := v.PutSecret(ctx, "_ssh_proxy_hostkey", pemBytes, nil); err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(pemBytes)
}
