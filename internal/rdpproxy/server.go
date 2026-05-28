// Package rdpproxy terminates RDP in the browser via Apache Guacamole (guacd)
// and records every session to disk — CyberArk PSM-style.
package rdpproxy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/pam-platform/internal/authclient"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/rdp"
	"github.com/example/pam-platform/internal/sshlaunch"
	"github.com/example/pam-platform/internal/vault"

	"github.com/wwt/guac"
)

// Server bridges browser WebSocket clients to guacd with session recording.
type Server struct {
	DB           *db.DB
	Vault        *vault.Vault
	Auth         *authclient.Client
	GuacdAddr    string
	SSHProxyAddr string // dial address for browser SSH via ssh-proxy (e.g. ssh-proxy:2222)
	RecordingDir string
	ListenAddr   string
	// guacdSSHHost/Port is the address passed to guacd for browser SSH (discovered at startup).
	guacdSSHHost string
	guacdSSHPort int

	mu      sync.Mutex
	tunnels map[string]guac.Tunnel
}

// Run starts the HTTP server (Guacamole websocket tunnel + health).
func (s *Server) Run(ctx context.Context) error {
	if s.GuacdAddr == "" {
		s.GuacdAddr = "guacd:4822"
	}
	if s.RecordingDir == "" {
		s.RecordingDir = "/recordings"
	}
	if err := os.MkdirAll(filepath.Join(s.RecordingDir, "rdp"), 0o777); err != nil {
		return fmt.Errorf("rdpproxy: mkdir recordings: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(s.RecordingDir, "ssh"), 0o777); err != nil {
		return fmt.Errorf("rdpproxy: mkdir ssh recordings: %w", err)
	}
	_ = os.Chmod(filepath.Join(s.RecordingDir, "rdp"), 0o777)
	_ = os.Chmod(filepath.Join(s.RecordingDir, "ssh"), 0o777)
	s.tunnels = make(map[string]guac.Tunnel)
	s.guacdSSHHost, s.guacdSSHPort = discoverSSHProxyAddr(s.SSHProxyAddr)

	ws := guac.NewWebsocketServer(s.doConnect)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /health/deps", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		gh, gp := splitHostPort(s.GuacdAddr, 4822)
		guacdOK := tcpOpen(gh, gp)
		sshOK := tcpOpen(s.guacdSSHHost, s.guacdSSHPort)
		_, _ = fmt.Fprintf(w, `{"guacd_tcp":%t,"ssh_proxy_tcp":%t,"guacd_ssh_host":%q,"guacd_ssh_port":%d}`,
			guacdOK, sshOK, s.guacdSSHHost, s.guacdSSHPort)
	})
	mux.Handle("/websocket-tunnel", ws)
	mux.Handle("/websocket-tunnel/", ws)

	srv := &http.Server{
		Addr:         s.ListenAddr,
		Handler:      mux,
		ReadTimeout:  guac.SocketTimeout,
		WriteTimeout: guac.SocketTimeout,
	}

	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	sshMode := "direct-then-proxy-fallback"
	if browserSSHViaProxy() {
		sshMode = "ssh-proxy"
	} else if browserSSHForceDirect() {
		sshMode = "direct-only"
	}
	log.Printf("rdp-proxy listening on %s (guacd=%s, browser-ssh=%s, ssh-proxy-probe=%s:%d)",
		s.ListenAddr, s.GuacdAddr, sshMode, s.guacdSSHHost, s.guacdSSHPort)
	err := srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type sessionParams struct {
	SessionID string
	Protocol  string
	Host      string
	Port      int
	Username  string
	Password  string
	PrivateKey []byte
	RecDir    string
	route     string // browser SSH: direct-target | ssh-proxy | ssh-proxy-fallback
	// Clipboard permissions for browser SSH (default allow).
	ClipboardCopyAllowed  bool
	ClipboardPasteAllowed bool
}

type recordingTunnel struct {
	guac.Tunnel
	srv       *Server
	sessionID string
}

func (t *recordingTunnel) Close() error {
	err := t.Tunnel.Close()
	t.srv.closeSession(context.Background(), t.sessionID)
	return err
}

func (s *Server) doConnect(r *http.Request) (guac.Tunnel, error) {
	q := r.URL.Query()
	sessionID := q.Get("session")
	token := q.Get("token")
	log.Printf("rdp-proxy: websocket connect session=%s remote=%s", sessionID, r.RemoteAddr)
	if sessionID == "" || token == "" {
		return nil, fmt.Errorf("session and token required on websocket URL (got query %q)", r.URL.RawQuery)
	}
	var uid int64
	if s.Auth != nil {
		claims, err := s.Auth.Verify(r.Context(), token)
		if err != nil {
			return nil, fmt.Errorf("unauthorized: %w", err)
		}
		uid = claims.UID
	}
	params, err := s.loadSession(r.Context(), sessionID, uid)
	if err != nil {
		return nil, err
	}
	failConnect := func(format string, args ...any) (guac.Tunnel, error) {
		err := fmt.Errorf(format, args...)
		// Do not end the session or delete vault tokens here — the user may retry
		// from the viewer; failSession would block reconnects.
		log.Printf("rdp-proxy: session %s connect failed: %v", sessionID, err)
		return nil, err
	}

	config := guac.NewGuacamoleConfiguration()
	if params.Protocol == "ssh" {
		config.Protocol = "ssh"
		config.Parameters = map[string]string{
			"hostname":               params.Host,
			"port":                   strconv.Itoa(params.Port),
			"username":               params.Username,
			"typescript-path":        params.RecDir,
			"typescript-name":        params.SessionID,
			"create-typescript-path": "true",
			"recording-path":         params.RecDir,
			"recording-name":         params.SessionID,
			"create-recording-path":  "true",
			"font-size":              "12",
			"color-scheme":           "gray-black",
			"terminal-type":          "vt100",
			"scrollback":             "1000",
			"server-alive-interval":  "30",
			"timeout":                "120",
			"backspace":              "127",
			"disable-copy":           strconv.FormatBool(!params.ClipboardCopyAllowed),
			"disable-paste":          strconv.FormatBool(!params.ClipboardPasteAllowed),
		}
		if len(params.PrivateKey) > 0 {
			config.Parameters["private-key"] = string(params.PrivateKey)
		}
		if params.Password != "" {
			config.Parameters["password"] = params.Password
		}
	} else {
		dialHost := resolveRDPReachableHost(params.Host)
		dialPort := normalizeRDPPort(params.Port)
		if dialHost != params.Host {
			log.Printf("rdp-proxy: session %s map target host %q → %q (guacd reachability)", sessionID, params.Host, dialHost)
		}
		config.Protocol = "rdp"
		config.Parameters = rdpGuacParams(dialHost, dialPort, params.Username, params.Password, params.RecDir, params.SessionID, true)
		config.OptimalScreenWidth = 1280
		config.OptimalScreenHeight = 800
		config.AudioMimetypes = []string{"audio/L16", "rate=44100", "channels=2"}
	}

	addr, err := net.ResolveTCPAddr("tcp", s.GuacdAddr)
	if err != nil {
		return failConnect("resolve guacd: %w", err)
	}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return failConnect("dial guacd %s: %w", s.GuacdAddr, err)
	}
	stream := guac.NewStream(conn, guac.SocketTimeout)
	if err := stream.Handshake(config); err != nil && config.Protocol == "rdp" {
		// Retry without session recording (shared-volume permission issues).
		conn.Close()
		conn, err = net.DialTCP("tcp", nil, addr)
		if err != nil {
			return failConnect("dial guacd %s (retry): %w", s.GuacdAddr, err)
		}
		stream = guac.NewStream(conn, guac.SocketTimeout)
		retry := guac.NewGuacamoleConfiguration()
		retry.Protocol = "rdp"
		retryPort, _ := strconv.Atoi(config.Parameters["port"])
		retry.Parameters = rdpGuacParams(
			config.Parameters["hostname"],
			normalizeRDPPort(retryPort),
			params.Username, params.Password, params.RecDir, params.SessionID, false,
		)
		retry.OptimalScreenWidth = config.OptimalScreenWidth
		retry.OptimalScreenHeight = config.OptimalScreenHeight
		retry.AudioMimetypes = config.AudioMimetypes
		if err2 := stream.Handshake(retry); err2 != nil {
			conn.Close()
			return failConnect("guacd RDP to %s:%s failed (%v); without recording (%v) — check RDP enabled, firewall, and use LAN IP not localhost (Docker: host.docker.internal)",
				config.Parameters["hostname"], config.Parameters["port"], err, err2)
		}
		config = retry
		log.Printf("rdp-proxy: session %s connected without recording (recording handshake failed: %v)", sessionID, err)
	} else if err != nil {
		conn.Close()
		return failConnect("guacd handshake: %w", err)
	}
	base := guac.NewSimpleTunnel(stream)
	rt := &recordingTunnel{Tunnel: base, srv: s, sessionID: sessionID}

	s.mu.Lock()
	if old, ok := s.tunnels[sessionID]; ok {
		old.Close()
	}
	s.tunnels[sessionID] = rt
	s.mu.Unlock()

	go s.pollTermination(sessionID, rt)

	route := params.route
	if route == "" {
		route = params.Protocol
	}
	log.Printf("rdp-proxy: session %s started (%s route=%s) → %s:%d as %s (recording %s)",
		sessionID, params.Protocol, route, params.Host, params.Port, params.Username, params.RecDir)
	if params.Protocol == "rdp" && params.Username != "" {
		if strings.Contains(strings.ToLower(params.Username), "administraor") {
			log.Printf("rdp-proxy: WARNING session %s username %q looks misspelled (Administrator?)", sessionID, params.Username)
		}
	}
	return rt, nil
}

func (s *Server) loadSession(ctx context.Context, sessionID string, callerUID int64) (*sessionParams, error) {
	var userID, targetID int64
	var host string
	var port int
	var protocol string
	var username sql.NullString
	var ended sql.NullInt64
	err := s.DB.QueryRowContext(ctx, `
		SELECT s.user_id, s.target_id, t.host, t.port, COALESCE(s.protocol,'ssh'),
		       COALESCE(pa.username,''), s.ended_at
		FROM sessions s
		JOIN targets t ON t.id = s.target_id
		LEFT JOIN privileged_accounts pa ON pa.id = s.account_id
		WHERE s.id = ?`, sessionID).
		Scan(&userID, &targetID, &host, &port, &protocol, &username, &ended)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("session not found")
		}
		return nil, err
	}
	if callerUID > 0 && userID != callerUID {
		return nil, errors.New("session belongs to another user")
	}
	if ended.Valid {
		return nil, errors.New("session already ended")
	}

	params := &sessionParams{
		SessionID: sessionID,
		Protocol:  protocol,
		Host:      host,
		Port:      port,
		ClipboardCopyAllowed:  true,
		ClipboardPasteAllowed: true,
	}

	switch protocol {
	case "ssh":
		key, err := s.Vault.GetSecret(ctx, sshlaunch.SessionSecretName(sessionID))
		if err != nil {
			return nil, fmt.Errorf("session credentials expired or missing")
		}
		if creds, perr := sshlaunch.ParseSessionCreds(key); perr == nil && creds.Mode == "browser" {
			route, err := s.fillBrowserSSHSession(ctx, params, creds, targetID, host, port)
			if err != nil {
				return nil, err
			}
			params.route = route
			params.ClipboardCopyAllowed = creds.ClipboardCopyAllowed()
			params.ClipboardPasteAllowed = creds.ClipboardPasteAllowed()
		} else {
			if port <= 0 {
				port = 22
				params.Port = 22
			}
			params.Username = "pam-user"
			params.PrivateKey = key
		}
		params.RecDir = sshlaunch.RecordingDirForSession(s.RecordingDir, sessionID)
	default: // rdp
		if port <= 0 {
			port = 3389
			params.Port = 3389
		}
		pw, err := s.Vault.GetSecret(ctx, rdp.SessionSecretName(sessionID))
		if err != nil {
			return nil, fmt.Errorf("session credentials expired or missing")
		}
		params.Username = username.String
		if params.Username == "" {
			params.Username = "Administrator"
		}
		params.Password = string(pw)
		params.RecDir = rdp.RecordingDirForSession(s.RecordingDir, sessionID)
	}

	if err := os.MkdirAll(params.RecDir, 0o777); err != nil {
		return nil, err
	}
	_ = os.Chmod(params.RecDir, 0o777)
	return params, nil
}

func (s *Server) pollTermination(sessionID string, tunnel guac.Tunnel) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		_, alive := s.tunnels[sessionID]
		s.mu.Unlock()
		if !alive {
			return
		}
		var ack sql.NullInt64
		err := s.DB.QueryRow(`
			SELECT acknowledged_at FROM session_terminations WHERE session_id = ?`, sessionID).Scan(&ack)
		if err != nil {
			continue // no termination row
		}
		if ack.Valid {
			continue // already processed
		}
		log.Printf("rdp-proxy: admin terminate requested for %s", sessionID)
		tunnel.Close()
		return
	}
}

func (s *Server) closeSession(ctx context.Context, sessionID string) {
	s.mu.Lock()
	if _, ok := s.tunnels[sessionID]; ok {
		delete(s.tunnels, sessionID)
	}
	s.mu.Unlock()

	recPath := s.findRecording(sessionID)
	var protocol string
	err := s.DB.QueryRowContext(ctx, `
		SELECT COALESCE(protocol,'') FROM sessions WHERE id = ?`, sessionID).Scan(&protocol)
	if err != nil {
		protocol = ""
	}

	// RDP upstream can drop before a desktop appears (519). Keep vault creds and the
	// session row open so the viewer can retry without a new Launch.
	if protocol == "rdp" && recPath == "" {
		log.Printf("rdp-proxy: session %s upstream closed before desktop (no recording); credentials kept — retry from viewer or Launch again", sessionID)
		return
	}

	_, _ = s.DB.ExecContext(ctx, `
		UPDATE sessions SET ended_at = ?, ended_reason = COALESCE(ended_reason, 'closed'),
		  recording_path = CASE WHEN ? != '' THEN ? ELSE recording_path END
		WHERE id = ? AND ended_at IS NULL`,
		db.Now(), recPath, recPath, sessionID)

	_ = s.Vault.DeleteSecret(ctx, rdp.SessionSecretName(sessionID))
	if raw, err := s.Vault.GetSecret(ctx, sshlaunch.SessionSecretName(sessionID)); err == nil {
		if creds, perr := sshlaunch.ParseSessionCreds(raw); perr == nil && creds.Token != "" {
			_ = s.Vault.DeleteSecret(ctx, sshlaunch.BrowserTokenVaultKey(creds.Token))
		}
	}
	_ = s.Vault.DeleteSecret(ctx, sshlaunch.SessionSecretName(sessionID))
	_, _ = s.DB.ExecContext(ctx, `
		UPDATE session_terminations SET acknowledged_at=?
		WHERE session_id=? AND acknowledged_at IS NULL`, db.Now(), sessionID)
	if recPath != "" {
		log.Printf("rdp-proxy: session %s closed, recording saved: %s", sessionID, recPath)
	} else {
		log.Printf("rdp-proxy: session %s closed", sessionID)
	}
}

func (s *Server) failSession(ctx context.Context, sessionID, reason, detail string) {
	s.mu.Lock()
	if _, ok := s.tunnels[sessionID]; ok {
		delete(s.tunnels, sessionID)
	}
	s.mu.Unlock()

	_, _ = s.DB.ExecContext(ctx, `
		UPDATE sessions
		   SET ended_at = ?, ended_reason = ?
		 WHERE id = ? AND ended_at IS NULL`,
		db.Now(), reason, sessionID)
	_, _ = s.DB.ExecContext(ctx, `
		INSERT INTO audit_events(ts, actor, kind, target, detail, severity)
		VALUES(?,?,?,?,?,?)`,
		db.Now(), "rdp-proxy", "session.connect.failed", sessionID, detail, "warn")

	_ = s.Vault.DeleteSecret(ctx, rdp.SessionSecretName(sessionID))
	if raw, err := s.Vault.GetSecret(ctx, sshlaunch.SessionSecretName(sessionID)); err == nil {
		if creds, perr := sshlaunch.ParseSessionCreds(raw); perr == nil && creds.Token != "" {
			_ = s.Vault.DeleteSecret(ctx, sshlaunch.BrowserTokenVaultKey(creds.Token))
		}
	}
	_ = s.Vault.DeleteSecret(ctx, sshlaunch.SessionSecretName(sessionID))
	log.Printf("rdp-proxy: session %s failed before connect: %s", sessionID, detail)
}

func (s *Server) findRecording(sessionID string) string {
	for _, sub := range []string{"rdp", "ssh"} {
		dir := filepath.Join(s.RecordingDir, sub, sessionID)
		if path := findGuacInDir(dir); path != "" {
			return path
		}
	}
	return ""
}

func splitHostPort(addr string, defaultPort int) (string, int) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "ssh-proxy", defaultPort
	}
	if !strings.Contains(addr, ":") {
		return addr, defaultPort
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return strings.TrimPrefix(addr, ":"), defaultPort
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 {
		port = defaultPort
	}
	return host, port
}

// sshProxyAddrForGuacd is deprecated; discoverSSHProxyAddr handles dial addresses.
func sshProxyAddrForGuacd(configured string) (string, int) {
	host, port := splitHostPort(configured, 2222)
	if host == "" {
		return "127.0.0.1", port
	}
	return host, port
}

func findGuacInDir(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var best string
	var bestMod time.Time
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext == ".log" || strings.HasSuffix(e.Name(), ".timing") {
			continue
		}
		if ext != ".guac" && ext != "" {
			continue
		}
		info, err := e.Info()
		if err != nil || info.Size() == 0 {
			continue
		}
		if info.ModTime().After(bestMod) {
			bestMod = info.ModTime()
			best = filepath.Join(dir, e.Name())
		}
	}
	return best
}
