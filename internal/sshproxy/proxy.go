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
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/pam-platform/internal/authclient"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/sshlaunch"
	"github.com/example/pam-platform/internal/vault"

	"golang.org/x/crypto/ssh"
)

// Server is the public listener.
type Server struct {
	Vault        *vault.Vault
	DB           *db.DB
	Policy       *policy.Engine
	Bus          events.Publisher
	HostKey      ssh.Signer
	RecordingDir string
	ListenAddr   string
	// Auth delegates credential checks to auth-service so AD/LDAP users and
	// TOTP-enrolled users get the same authentication flow they have in the
	// portal. If nil, falls back to the legacy local-DB password check.
	Auth *authclient.Client
}

// Run starts the proxy. Blocks until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	if err := os.MkdirAll(s.RecordingDir, 0o700); err != nil {
		return fmt.Errorf("sshproxy: mkdir recordings: %w", err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback:            s.passwordAuth,
		KeyboardInteractiveCallback: s.keyboardInteractiveAuth,
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

// passwordAuth verifies "user@target" SSH login. It first delegates the
// credential check to auth-service (so AD/LDAP users authenticate the same way
// they do in the portal). If auth-service signals that MFA is required, this
// path fails with a hint — the SSH client retries via keyboard-interactive,
// which prompts for the OTP.
func (s *Server) passwordAuth(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
	user, target, ok := splitUserTarget(c.User())
	if !ok {
		return nil, errors.New("login must be user@target")
	}
	if perms, err := s.tryBrowserToken(user, target, string(pw)); err == nil {
		return perms, nil
	}
	authedUser, err := s.authenticate(user, string(pw), "")
	if err != nil {
		if errors.Is(err, errMFANeeded) {
			return nil, errors.New("MFA required — retry with keyboard-interactive")
		}
		return nil, err
	}
	return s.authorizeAndStash(authedUser, target)
}

// keyboardInteractiveAuth is the SSH fallback that lets us prompt for an MFA
// code over the SSH session itself: "Password:" then "MFA code:".
func (s *Server) keyboardInteractiveAuth(c ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	user, target, ok := splitUserTarget(c.User())
	if !ok {
		return nil, errors.New("login must be user@target")
	}
	answers, err := ch(user, "Authenticating to PAM Platform — AD or local credentials accepted.",
		[]string{"Password: ", "MFA code (blank if not enrolled): "},
		[]bool{false, true})
	if err != nil {
		return nil, err
	}
	if len(answers) < 1 {
		return nil, errors.New("no password provided")
	}
	pw := answers[0]
	otp := ""
	if len(answers) > 1 {
		otp = answers[1]
	}
	authedUser, err := s.authenticate(user, pw, otp)
	if err != nil {
		return nil, err
	}
	return s.authorizeAndStash(authedUser, target)
}

// errMFANeeded is returned by authenticate when the user has TOTP enrolled and
// we got an HTTP 202 from auth-service.
var errMFANeeded = errors.New("mfa required")

// authedUser is what authenticate returns to authorizeAndStash.
type authedUser struct {
	ID    int64
	Role  string
	Email string
}

// authenticate prefers auth-service (local + LDAP + MFA) and falls back to the
// legacy local-DB hash check if no client is configured.
func (s *Server) authenticate(username, password, otp string) (*authedUser, error) {
	if s.Auth != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		res, err := s.Auth.Login(ctx, username, password, otp)
		if err != nil {
			return nil, err
		}
		if res.MFARequired && otp == "" {
			return nil, errMFANeeded
		}
		if res.User == nil {
			return nil, errors.New("invalid credentials")
		}
		return &authedUser{ID: res.User.ID, Role: res.User.Role, Email: res.User.Email}, nil
	}
	// Legacy local-only fallback.
	var (
		uid   int64
		uHash string
		uRole string
	)
	err := s.DB.QueryRow(`SELECT id, password_hash, role FROM users WHERE username = ?`, username).
		Scan(&uid, &uHash, &uRole)
	if err != nil || !verifyPwd(password, uHash) {
		return nil, errors.New("invalid credentials")
	}
	return &authedUser{ID: uid, Role: uRole}, nil
}

// resolveTarget looks up a target by numeric ref (#42 / id:42) or by display name.
// ID refs avoid SSH parsing issues when machine names contain spaces or @.
func (s *Server) resolveTarget(targetRef string) (tid int64, name, kind, host string, port, tier int, err error) {
	ref := strings.TrimSpace(targetRef)
	if ref == "" {
		return 0, "", "", "", 0, 0, errors.New("target not found")
	}
	if strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "id:") {
		idStr := strings.TrimPrefix(strings.TrimPrefix(ref, "id:"), "#")
		var id int64
		id, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil || id <= 0 {
			return 0, "", "", "", 0, 0, errors.New("target not found")
		}
		err = s.DB.QueryRow(`SELECT id, name, kind, host, port, tier FROM targets WHERE id = ?`, id).
			Scan(&tid, &name, &kind, &host, &port, &tier)
		if err != nil {
			return 0, "", "", "", 0, 0, errors.New("target not found")
		}
		return tid, name, kind, host, port, tier, nil
	}
	err = s.DB.QueryRow(`SELECT id, name, kind, host, port, tier FROM targets WHERE name = ?`, ref).
		Scan(&tid, &name, &kind, &host, &port, &tier)
	if err != nil {
		return 0, "", "", "", 0, 0, errors.New("target not found")
	}
	return tid, name, kind, host, port, tier, nil
}

// tryBrowserToken validates a one-time token issued for recorded browser SSH
// (guacd → ssh-proxy → target). Skips portal password auth when the token matches.
func (s *Server) tryBrowserToken(loginUser, targetRef, token string) (*ssh.Permissions, error) {
	if token == "" {
		return nil, errors.New("no token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := s.Vault.GetSecret(ctx, sshlaunch.BrowserTokenVaultKey(token))
	if err != nil {
		return nil, errors.New("invalid token")
	}
	creds, err := sshlaunch.ParseSessionCreds(raw)
	if err != nil || creds.Mode != "browser" {
		return nil, errors.New("invalid token")
	}
	if creds.PortalUser != loginUser || creds.TargetRef != targetRef {
		return nil, errors.New("token mismatch")
	}

	tid, name, kind, host, port, tier, err := s.resolveTarget(targetRef)
	if err != nil {
		return nil, err
	}
	if tid != creds.TargetID {
		return nil, errors.New("target mismatch")
	}

	var role string
	if err := s.DB.QueryRow(`SELECT role FROM users WHERE id = ?`, creds.UserID).Scan(&role); err != nil {
		return nil, errors.New("user not found")
	}
	dec, err := s.Policy.Decide(ctx, policy.Input{
		UserID: creds.UserID, Role: role, TargetID: tid, TargetKind: kind,
		TargetTier: tier, Action: "ssh",
	})
	if err != nil {
		return nil, err
	}
	if !dec.Allow {
		return nil, fmt.Errorf("denied by policy: %v", dec.Reasons)
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			"user-id":            fmt.Sprintf("%d", creds.UserID),
			"role":               role,
			"target-id":          fmt.Sprintf("%d", tid),
			"target":             name,
			"kind":               kind,
			"host":               host,
			"port":               fmt.Sprintf("%d", port),
			"allow-csv":          joinCSV(dec.AllowedCmds),
			"deny-csv":           joinCSV(dec.DeniedCmds),
			"browser-session-id": creds.SessionID,
		},
	}, nil
}

// authorizeAndStash looks up the target, evaluates policy with the user's
// effective roles, and packages routing info into ssh.Permissions for the
// connection handler to consume.
func (s *Server) authorizeAndStash(u *authedUser, target string) (*ssh.Permissions, error) {
	tid, name, kind, host, port, tier, err := s.resolveTarget(target)
	if err != nil {
		return nil, err
	}

	dec, err := s.Policy.Decide(context.Background(), policy.Input{
		UserID: u.ID, Role: u.Role, TargetID: tid, TargetKind: kind,
		TargetTier: tier, Action: "ssh",
	})
	if err != nil {
		return nil, err
	}
	if !dec.Allow {
		return nil, fmt.Errorf("denied by policy: %v", dec.Reasons)
	}
	return &ssh.Permissions{
		Extensions: map[string]string{
			"user-id":   fmt.Sprintf("%d", u.ID),
			"role":      u.Role,
			"target-id": fmt.Sprintf("%d", tid),
			"target":    name,
			"kind":      kind,
			"host":      host,
			"port":      fmt.Sprintf("%d", port),
			"allow-csv": joinCSV(dec.AllowedCmds),
			"deny-csv":  joinCSV(dec.DeniedCmds),
		},
	}, nil
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
	browserSess := sconn.Permissions.Extensions["browser-session-id"]
	sessionID := browserSess
	if sessionID == "" {
		sessionID = fmt.Sprintf("%d-%s", time.Now().UnixNano(), targetName)
	}

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

	// Open recording file (browser sessions are recorded by guacd; skip duplicate tee).
	var rec *os.File
	if browserSess == "" {
		recPath := filepath.Join(s.RecordingDir, sessionID+".log")
		rec, err = os.OpenFile(recPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Printf("open recording: %v", err)
			return
		}
		defer rec.Close()

		if _, err := s.DB.Exec(`
		INSERT INTO sessions(id, user_id, target_id, started_at, recording_path, client_ip)
		VALUES(?, ?, ?, ?, ?, ?)`,
			sessionID,
			mustAtoi(sconn.Permissions.Extensions["user-id"]),
			mustAtoi(sconn.Permissions.Extensions["target-id"]),
			time.Now().Unix(), recPath, nc.RemoteAddr().String()); err != nil {
			log.Printf("insert session: %v", err)
		}
	} else {
		rec, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if rec != nil {
			defer rec.Close()
		}
	}

	// Background watcher: poll session_terminations every 5s and tear down
	// this connection if an admin requested termination.
	termCtx, termCancel := context.WithCancel(context.Background())
	defer termCancel()
	go s.watchTermination(termCtx, sessionID, sconn, upClient)

	// Each downstream channel from the user is mirrored to the target.
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "only session channels supported")
			continue
		}
		go s.pipeSession(newChan, upClient, rec, sessionID, user, targetName)
	}

	// Mark session closed (browser sessions are ended by rdp-proxy when guacd disconnects).
	if browserSess == "" {
		_, _ = s.DB.Exec(`UPDATE sessions SET ended_at = ?, ended_reason = COALESCE(ended_reason, 'closed') WHERE id = ?`,
			time.Now().Unix(), sessionID)
	}
}

// watchTermination polls the session_terminations table for a kill order
// against this session and, on hit, closes the user-side connection.
func (s *Server) watchTermination(ctx context.Context, sessionID string,
	sconn *ssh.ServerConn, upClient *ssh.Client) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var ack sql.NullInt64
			var reason string
			err := s.DB.QueryRow(
				`SELECT acknowledged_at, COALESCE(reason,'') FROM session_terminations WHERE session_id = ?`,
				sessionID).Scan(&ack, &reason)
			if err != nil {
				continue
			}
			if ack.Valid {
				continue
			}
			log.Printf("ssh-proxy: terminating session %s by admin order (%s)", sessionID, reason)
			_, _ = s.DB.Exec(
				`UPDATE sessions SET ended_at=?, ended_reason='terminated' WHERE id=?`,
				time.Now().Unix(), sessionID)
			_, _ = s.DB.Exec(
				`UPDATE session_terminations SET acknowledged_at=? WHERE session_id=?`,
				time.Now().Unix(), sessionID)
			_ = upClient.Close()
			_ = sconn.Close()
			return
		}
	}
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
