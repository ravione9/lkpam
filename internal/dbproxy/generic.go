package dbproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/dblaunch"
)

// serveGeneric handles non-Postgres engines with a simple line-based pre-auth
// handshake (PAMAUTH) then raw TCP relay. Clients can use pam-cli db connect
// or native drivers via PAM tunnel wrappers.
func (s *Server) serveGeneric(ctx context.Context, engine string, client net.Conn) error {
	_ = client.SetDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 4096)
	n, err := client.Read(buf)
	if err != nil {
		return err
	}
	line := string(buf[:n])
	if !strings.HasPrefix(line, "PAMAUTH\n") {
		return errors.New("expected PAMAUTH handshake — use pam-cli or the portal connection string")
	}
	parts := strings.Split(strings.TrimSpace(line), "\n")
	if len(parts) < 3 {
		return errors.New("bad PAMAUTH frame")
	}
	sessionID := strings.TrimSpace(parts[1])
	token := strings.TrimSpace(parts[2])
	creds, err := dblaunch.LoadSessionCreds(ctx, s.Vault, sessionID)
	if err != nil {
		return err
	}
	if creds.BrokerToken != token {
		return errors.New("invalid broker token")
	}
	if creds.Engine != engine {
		return fmt.Errorf("engine mismatch: session=%s listener=%s", creds.Engine, engine)
	}
	rest := buf[n:]
	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(creds.Host, itoa(creds.Port)), 10*time.Second)
	if err != nil {
		return err
	}
	defer upstream.Close()
	if len(rest) > 0 {
		if _, err := upstream.Write(rest); err != nil {
			return err
		}
	}
	_ = client.SetDeadline(time.Time{})
	log.Printf("db-proxy: %s relay session=%s upstream=%s:%d", engine, sessionID, creds.Host, creds.Port)
	return relayBidirectional(client, upstream)
}

// WritePAMAuthHandshake builds the generic pre-auth frame for mysql/redis/etc.
func WritePAMAuthHandshake(sessionID, token string) []byte {
	return []byte(fmt.Sprintf("PAMAUTH\n%s\n%s\n", sessionID, token))
}

// GenericHandshakeHint returns CLI instructions for generic engines.
func GenericHandshakeHint(engine string) string {
	return fmt.Sprintf("For %s, prepend PAMAUTH handshake or use pam-cli db connect (engine=%s).", engine, engine)
}

// DrainReader discards unread bytes (for tests).
func DrainReader(r io.Reader) { _, _ = io.Copy(io.Discard, r) }
