// Package sshproxy is the SSH data-plane. It exposes an SSH server to
// privileged users; once authenticated, it opens a downstream SSH connection
// to the requested target using a short-lived certificate issued by the
// vault, and tees the entire byte stream to a recording file.
//
// In production this would also:
//   - perform per-command policy checks (inspect each \n-terminated line),
//   - allow SOC operators to live-view / terminate sessions,
//   - stream events to Kafka in real time.
package sshproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/vault"

	"golang.org/x/crypto/ssh"
)

// Server is the public listener.
type Server struct {
	Vault       *vault.Vault
	DB          *db.DB
	Policy      *policy.Engine
	Bus         events.Publisher
	HostKey     ssh.Signer
	RecordingDir string
	ListenAddr  string
}

// Run starts the proxy. Blocks until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	if err := os.MkdirAll(s.RecordingDir, 0o700); err != nil {
		return fmt.Errorf("sshproxy: mkdir recordings: %w", err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback: s.passwordAuth,
	}
	cfg.AddHostKey(s.HostKey)

	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("sshproxy: listen: %w", err)
	}
	log.Printf("ssh-proxy listening on %s", s.ListenAddr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("accept: %v", err)
			continue
		}
		go s.handle(ctx, nc, cfg)
	}
}

// passwordAuth verifies "user@target" syntax against the DB.
// In production this is replaced with public-key cert auth where the cert
// itself is the gate; password mode is for the reference impl + lab.
func (s *Server) passwordAuth(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
	user, target, ok := splitUserTarget(c.User())
	if !ok {
		return nil, errors.New("login must be user@target")
	}

	// Look up user
	var (
		uid     int64
		uHash   string
		uRole   string
	)
	err := s.DB.QueryRow(`SELECT id, password_hash, role FROM users WHERE username = ?`, user).
		Scan(&uid, &uHash, &uRole)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	// Re-use cryptox verify via the auth package would be cleaner; inline keeps deps tight.
	if !verifyPwd(string(pw), uHash) {
		return nil, errors.New("invalid credentials")
	}

	// Look up target
	var (
		tid  int64
		kind string
		host string
		port int
		tier int
	)
	err = s.DB.QueryRow(`SELECT id, kind, host, port, tier FROM targets WHERE name = ?`, target).
		Scan(&tid, &kind, &host, &port, &tier)
	if err != nil {
		return nil, errors.New("target not found")
	}

	// Evaluate policy
	dec, err := s.Policy.Decide(context.Background(), policy.Input{
		UserID: uid, Role: uRole, TargetID: tid, TargetKind: kind,
		TargetTier: tier, Action: "ssh",
	})
	if err != nil {
		return nil, err
	}
	if !dec.Allow {
		return nil, fmt.Errorf("denied by policy: %v", dec.Reasons)
	}

	// Stash routing info in the connection's Permissions
	perms := &ssh.Permissions{
		Extensions: map[string]string{
			"user-id":    fmt.Sprintf("%d", uid),
			"role":       uRole,
			"target-id":  fmt.Sprintf("%d", tid),
			"target":     target,
			"kind":       kind,
			"host":       host,
			"port":       fmt.Sprintf("%d", port),
			"allow-csv":  joinCSV(dec.AllowedCmds),
			"deny-csv":   joinCSV(dec.DeniedCmds),
		},
	}
	return perms, nil
}

func (s *Server) handle(ctx context.Context, nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		log.Printf("handshake: %v", err)
		return
	}
	defer sconn.Close()

	go ssh.DiscardRequests(reqs)

	host := sconn.Permissions.Extensions["host"]
	port := sconn.Permissions.Extensions["port"]
	targetName := sconn.Permissions.Extensions["target"]
	user := sconn.User()
	sessionID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), targetName)

	s.Bus.Publish(events.Event{
		Source: "ssh-proxy", Kind: "session.open", Severity: "info",
		Actor: user, Target: targetName,
		Detail: map[string]string{"session_id": sessionID, "client": nc.RemoteAddr().String()},
	})
	defer s.Bus.Publish(events.Event{
		Source: "ssh-proxy", Kind: "session.close", Severity: "info",
		Actor: user, Target: targetName,
		Detail: map[string]string{"session_id": sessionID},
	})

	// Issue ephemeral SSH cert for downstream connection. The principals
	// declare *who* the bearer claims to be on the target; the target's
	// AuthorizedPrincipalsFile (or vendor equivalent) maps these to local
	// users / roles.
	principals := []string{sconn.Permissions.Extensions["role"], "pam-user"}
	upPriv, upCertAuth, err := s.Vault.IssueSSHCert(principals, 30*time.Minute)
	if err != nil {
		log.Printf("issue cert: %v", err)
		return
	}
	upSigner, err := buildCertSigner(upPriv, upCertAuth)
	if err != nil {
		log.Printf("build cert signer: %v", err)
		return
	}

	// Connect downstream
	target := fmt.Sprintf("%s:%s", host, port)
	upClient, err := ssh.Dial("tcp", target, &ssh.ClientConfig{
		User:            "pam-user", // expected to match a principal trusted on the target
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(upSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // dev mode; replace with HostKeys table in prod
		Timeout:         10 * time.Second,
	})
	if err != nil {
		log.Printf("dial target %s: %v", target, err)
		return
	}
	defer upClient.Close()

	// Open recording file
	recPath := filepath.Join(s.RecordingDir, sessionID+".log")
	rec, err := os.OpenFile(recPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Printf("open recording: %v", err)
		return
	}
	defer rec.Close()

	// Persist session row
	if _, err := s.DB.Exec(`
		INSERT INTO sessions(id, user_id, target_id, started_at, recording_path, client_ip)
		VALUES(?, ?, ?, ?, ?, ?)`,
		sessionID,
		mustAtoi(sconn.Permissions.Extensions["user-id"]),
		mustAtoi(sconn.Permissions.Extensions["target-id"]),
		time.Now().Unix(), recPath, nc.RemoteAddr().String()); err != nil {
		log.Printf("insert session: %v", err)
	}

	// Each downstream channel from the user is mirrored to the target.
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "only session channels supported")
			continue
		}
		go s.pipeSession(newChan, upClient, rec, sessionID, user, targetName)
	}

	// Mark session closed
	_, _ = s.DB.Exec(`UPDATE sessions SET ended_at = ? WHERE id = ?`, time.Now().Unix(), sessionID)
}

func (s *Server) pipeSession(newChan ssh.NewChannel, upClient *ssh.Client, rec *os.File, sessionID, user, target string) {
	downCh, downReqs, err := newChan.Accept()
	if err != nil {
		log.Printf("accept down chan: %v", err)
		return
	}
	defer downCh.Close()

	upCh, upReqs, err := upClient.OpenChannel("session", nil)
	if err != nil {
		log.Printf("open up chan: %v", err)
		return
	}
	defer upCh.Close()

	// Forward channel requests both ways (pty-req, shell, env, exec, window-change).
	go forwardRequests(downReqs, upCh, "->up")
	go forwardRequests(upReqs, downCh, "->down")

	// Tee user input → upstream, and log it as the keystroke stream.
	var wg sync.WaitGroup
	wg.Add(2)

	// downstream (user)  ───►   recorder (input)  ───►   upstream (target)
	go func() {
		defer wg.Done()
		tee := io.MultiWriter(upCh, &prefixedWriter{w: rec, prefix: "IN  "})
		_, _ = io.Copy(tee, downCh)
		upCh.CloseWrite()
	}()
	// upstream (target)  ───►   recorder (output) ───►   downstream (user)
	go func() {
		defer wg.Done()
		tee := io.MultiWriter(downCh, &prefixedWriter{w: rec, prefix: "OUT "})
		_, _ = io.Copy(tee, upCh)
		downCh.CloseWrite()
	}()

	wg.Wait()

	s.Bus.Publish(events.Event{
		Source: "ssh-proxy", Kind: "session.io_finished", Severity: "info",
		Actor: user, Target: target,
		Detail: map[string]string{"session_id": sessionID},
	})
}

// forwardRequests forwards out-of-band ssh requests between sides.
func forwardRequests(in <-chan *ssh.Request, dst ssh.Channel, dir string) {
	for req := range in {
		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			log.Printf("forward req (%s): %v", dir, err)
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}

// prefixedWriter prepends a timestamp + direction tag to each chunk written to
// the recording file. Good enough for forensic replay; production should use
// the asciinema cast v2 format.
type prefixedWriter struct {
	w      io.Writer
	prefix string
}

func (p *prefixedWriter) Write(b []byte) (int, error) {
	header := fmt.Sprintf("[%s %s] ", time.Now().UTC().Format(time.RFC3339Nano), p.prefix)
	if _, err := p.w.Write([]byte(header)); err != nil {
		return 0, err
	}
	if _, err := p.w.Write(b); err != nil {
		return 0, err
	}
	if _, err := p.w.Write([]byte{'\n'}); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ---- small helpers ----

func splitUserTarget(s string) (user, target string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '@' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func joinCSV(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func mustAtoi(s string) int64 {
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int64(r-'0')
	}
	return n
}

// buildCertSigner wraps a fresh user privkey + signed cert into an ssh.Signer
// suitable for outbound auth.
func buildCertSigner(privPEM, certAuth []byte) (ssh.Signer, error) {
	priv, err := ssh.ParsePrivateKey(privPEM)
	if err != nil {
		return nil, fmt.Errorf("parse user priv: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certAuth)
	if err != nil {
		return nil, fmt.Errorf("parse user cert: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("expected ssh certificate")
	}
	cs, err := ssh.NewCertSigner(cert, priv)
	if err != nil {
		return nil, fmt.Errorf("new cert signer: %w", err)
	}
	return cs, nil
}

// verifyPwd re-implements the cryptox.VerifyPassword check here so this
// package doesn't import auth. Calls the cryptox API directly.
func verifyPwd(pw, encoded string) bool {
	return cryptoxVerify(pw, encoded)
}
