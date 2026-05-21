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
	"github.com/example/pam-platform/internal/vault"

	"github.com/wwt/guac"
)

// Server bridges browser WebSocket clients to guacd with session recording.
type Server struct {
	DB           *db.DB
	Vault        *vault.Vault
	Auth         *authclient.Client
	GuacdAddr    string
	RecordingDir string
	ListenAddr   string

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
	if err := os.MkdirAll(filepath.Join(s.RecordingDir, "rdp"), 0o700); err != nil {
		return fmt.Errorf("rdpproxy: mkdir recordings: %w", err)
	}
	s.tunnels = make(map[string]guac.Tunnel)

	ws := guac.NewWebsocketServer(s.doConnect)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
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

	log.Printf("rdp-proxy listening on %s (guacd=%s)", s.ListenAddr, s.GuacdAddr)
	err := srv.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

type sessionParams struct {
	SessionID string
	Host      string
	Port      int
	Username  string
	Password  string
	RecDir    string
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
	if sessionID == "" || token == "" {
		return nil, errors.New("session and token query parameters required")
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

	config := guac.NewGuacamoleConfiguration()
	config.Protocol = "rdp"
	config.Parameters = map[string]string{
		"hostname":                params.Host,
		"port":                    strconv.Itoa(params.Port),
		"username":                params.Username,
		"password":                params.Password,
		"ignore-cert":             "true",
		"security":                "any",
		"resize-method":           "display-update",
		"enable-wallpaper":        "false",
		"enable-theming":          "false",
		"enable-font-smoothing":   "true",
		"enable-full-window-drag": "false",
		"recording-path":          params.RecDir,
		"recording-name":          params.SessionID,
		"create-recording-path":   "true",
	}
	config.OptimalScreenWidth = 1280
	config.OptimalScreenHeight = 800
	config.AudioMimetypes = []string{"audio/L16", "rate=44100", "channels=2"}

	addr, err := net.ResolveTCPAddr("tcp", s.GuacdAddr)
	if err != nil {
		return nil, fmt.Errorf("resolve guacd: %w", err)
	}
	conn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("dial guacd: %w", err)
	}
	stream := guac.NewStream(conn, guac.SocketTimeout)
	if err := stream.Handshake(config); err != nil {
		conn.Close()
		return nil, fmt.Errorf("guacd handshake: %w", err)
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

	log.Printf("rdp-proxy: session %s started → %s:%d as %s (recording %s)",
		sessionID, params.Host, params.Port, params.Username, params.RecDir)
	return rt, nil
}

func (s *Server) loadSession(ctx context.Context, sessionID string, callerUID int64) (*sessionParams, error) {
	var userID, targetID int64
	var host string
	var port int
	var username sql.NullString
	var ended sql.NullInt64
	err := s.DB.QueryRowContext(ctx, `
		SELECT s.user_id, s.target_id, t.host, t.port, COALESCE(pa.username,''), s.ended_at
		FROM sessions s
		JOIN targets t ON t.id = s.target_id
		LEFT JOIN privileged_accounts pa ON pa.id = s.account_id
		WHERE s.id = ? AND s.protocol = 'rdp'`, sessionID).
		Scan(&userID, &targetID, &host, &port, &username, &ended)
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
	pw, err := s.Vault.GetSecret(ctx, rdp.SessionSecretName(sessionID))
	if err != nil {
		return nil, fmt.Errorf("session credentials expired or missing")
	}
	user := username.String
	if user == "" {
		user = "Administrator"
	}
	recDir := rdp.RecordingDirForSession(s.RecordingDir, sessionID)
	if err := os.MkdirAll(recDir, 0o700); err != nil {
		return nil, err
	}
	return &sessionParams{
		SessionID: sessionID,
		Host:      host,
		Port:      port,
		Username:  user,
		Password:  string(pw),
		RecDir:    recDir,
	}, nil
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
	_, _ = s.DB.ExecContext(ctx, `
		UPDATE sessions SET ended_at = ?, ended_reason = COALESCE(ended_reason, 'closed'),
		  recording_path = CASE WHEN ? != '' THEN ? ELSE recording_path END
		WHERE id = ? AND ended_at IS NULL`,
		db.Now(), recPath, recPath, sessionID)

	_ = s.Vault.DeleteSecret(ctx, rdp.SessionSecretName(sessionID))
	_, _ = s.DB.ExecContext(ctx, `
		UPDATE session_terminations SET acknowledged_at=?
		WHERE session_id=? AND acknowledged_at IS NULL`, db.Now(), sessionID)
	if recPath != "" {
		log.Printf("rdp-proxy: session %s closed, recording saved: %s", sessionID, recPath)
	} else {
		log.Printf("rdp-proxy: session %s closed", sessionID)
	}
}

func (s *Server) findRecording(sessionID string) string {
	dir := rdp.RecordingDirForSession(s.RecordingDir, sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var best string
	var bestMod time.Time
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".guac") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(bestMod) {
			bestMod = info.ModTime()
			best = filepath.Join(dir, e.Name())
		}
	}
	return best
}
