package rdpproxy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/sshlaunch"
)

// browserSSHViaProxy forces guacd → ssh-proxy → target (same path as PuTTY/Terminal).
func browserSSHViaProxy() bool {
	v := strings.TrimSpace(strings.ToLower(config.Get("PAM_BROWSER_SSH_VIA_PROXY", "")))
	return v == "1" || v == "true" || v == "yes"
}

func browserSSHForceDirect() bool {
	v := strings.TrimSpace(strings.ToLower(config.Get("PAM_BROWSER_SSH_DIRECT_ONLY", "")))
	return v == "1" || v == "true" || v == "yes"
}

func (s *Server) fillBrowserSSHViaProxy(params *sessionParams, creds sshlaunch.SessionCreds) {
	params.Host = s.guacdSSHHost
	params.Port = s.guacdSSHPort
	params.Username = creds.PortalUser + "@" + creds.TargetRef
	params.Password = creds.Token
	params.PrivateKey = nil
}

func (s *Server) fillBrowserSSHSession(ctx context.Context, params *sessionParams, creds sshlaunch.SessionCreds, targetID int64, host string, port int) (route string, err error) {
	if browserSSHViaProxy() {
		s.fillBrowserSSHViaProxy(params, creds)
		return "ssh-proxy", nil
	}
	if !browserSSHForceDirect() {
		if err := s.fillBrowserSSHDirect(ctx, params, targetID, host, port); err == nil {
			return "direct-target", nil
		} else if !isBrowserSSHDirectFallback(err) {
			return "", err
		}
		// No privileged vault creds — use ssh-proxy (same as PuTTY) instead of failing in browser.
		s.fillBrowserSSHViaProxy(params, creds)
		return "ssh-proxy-fallback", nil
	}
	if err := s.fillBrowserSSHDirect(ctx, params, targetID, host, port); err != nil {
		return "", err
	}
	return "direct-target", nil
}

func isBrowserSSHDirectFallback(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "no privileged account") ||
		strings.Contains(msg, "password not available in vault")
}

func (s *Server) fillBrowserSSHDirect(ctx context.Context, params *sessionParams, targetID int64, host string, port int) error {
	if port <= 0 {
		port = 22
	}
	params.Port = port
	params.Host = host

	var username, secretRef string
	err := s.DB.QueryRowContext(ctx, `
		SELECT username, secret_ref
		FROM privileged_accounts
		WHERE target_id = ?
		ORDER BY id LIMIT 1`, targetID).Scan(&username, &secretRef)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("no privileged account linked to this target — add one in Privileged Accounts for browser SSH")
	}
	if err != nil {
		return err
	}
	pw, err := s.Vault.GetSecret(ctx, secretRef)
	if err != nil || len(pw) == 0 {
		return fmt.Errorf("privileged account password not available in vault: %w", err)
	}
	params.Username = username
	params.Password = string(pw)
	params.PrivateKey = nil
	return nil
}
