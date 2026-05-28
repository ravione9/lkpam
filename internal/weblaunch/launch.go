// Package weblaunch handles policy-checked, recorded web-console sessions.
// When a user launches a Web GUI target PAM:
//  1. Checks policy (and JIT approval if required).
//  2. Checks out the linked privileged account credentials from the vault.
//  3. Creates a session row so the session appears in the Sessions tab.
//  4. Returns the session ID, a short-lived token, and the proxied viewer URL.
//
// The api-gateway then forwards all browser traffic for that session through
// /web/{sessionID}/* to the target, injecting the stored credentials so the
// user never sees or types the device password.
package weblaunch

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/approval"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/sessions"
	"github.com/example/pam-platform/internal/vault"
)

var (
	ErrTargetNotFound   = errors.New("target not found")
	ErrNotWeb           = errors.New("target is not a web target")
	ErrPolicyDenied     = errors.New("access denied by policy")
	ErrApprovalRequired = errors.New("approved access request required — submit a request and wait for approval")
)

// LaunchResult is returned to the portal when a user starts a web session.
type LaunchResult struct {
	SessionID   string `json:"session_id"`
	TargetName  string `json:"target_name"`
	WebURL      string `json:"web_url"`      // raw target URL (for display)
	ViewerURL   string `json:"viewer_url"`   // PAM-proxied viewer URL to open
	Username    string `json:"username,omitempty"`
	HasAccount  bool   `json:"has_account"`
	Recorded    bool   `json:"recorded"`
	Instructions string `json:"instructions"`
}

// Service wires policy, approval, and session audit for web targets.
type Service struct {
	DB       *db.DB
	Policy   *policy.Engine
	Approval *approval.Service
	Groups   *groups.Service
	Vault    *vault.Vault
	// BrowserBase is the public portal root used to build viewer URLs.
	BrowserBase string
}

// SessionSecretName returns the vault key for a web session's credentials.
func SessionSecretName(sessionID string) string {
	return sessions.WebVaultSecretName(sessionID)
}

// SessionCreds is the vault payload for a web session.
type SessionCreds struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	TargetURL       string `json:"target_url"`
	TargetKind      string `json:"target_kind,omitempty"`
	PortalUsername  string `json:"portal_username,omitempty"`
	PortalPassword  string `json:"portal_password,omitempty"` // cached portal password (append MFA for FortiGate)
}

// AuthHint returns user-facing login guidance for the web viewer.
func AuthHint(c SessionCreds, hasAccount bool) string {
	if isFortinetKind(c.TargetKind) {
		if hasAccount {
			return "FortiGate: PAM logs in with the linked privileged account automatically (form login, not TACACS)."
		}
		if c.PortalUsername != "" {
			if c.PortalPassword != "" {
				return "FortiGate uses TACACS to PAM. Username is prefilled. Enter your 6-digit MFA above and click Apply password (do not type the password manually — FortiOS encrypts it on submit). Then click Login in the form. TACACS must have authorization enable and PAP auth type."
			}
			return "FortiGate uses TACACS to PAM. Username is prefilled. Password = your portal password + 6-digit MFA (no space). FortiGate TACACS must have authorization enable and PAP auth type."
		}
		return "FortiGate uses TACACS to PAM for GUI login. Use your PAM portal username; password + MFA appended with no space."
	}
	if hasAccount {
		return "Credentials are injected automatically."
	}
	return "Log in manually or link a privileged account in PAM for auto-login."
}

func isFortinetKind(kind string) bool {
	k := strings.ToLower(strings.TrimSpace(kind))
	return strings.Contains(k, "forti")
}

// Launch authorises the caller and creates a recorded web session.
func (s *Service) Launch(ctx context.Context, targetID, userID int64, userRole, portalUsername, reason, clientIP string) (*LaunchResult, error) {
	var (
		name    string
		kind    string
		webURL  string
		tier    int
		connType string
	)
	err := s.DB.QueryRowContext(ctx, `
		SELECT name, kind, COALESCE(web_url,''), tier, COALESCE(connection_type,'web')
		FROM targets WHERE id = ?`, targetID).
		Scan(&name, &kind, &webURL, &tier, &connType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTargetNotFound
		}
		return nil, err
	}
	if connType != "web" && connType != "https-api" {
		return nil, ErrNotWeb
	}
	if webURL == "" {
		return nil, errors.New("no web URL configured for this target — edit it in Machines and add the URL")
	}

	roles, err := s.Groups.EffectiveRoles(ctx, userID, userRole)
	if err != nil {
		return nil, err
	}
	dec, err := s.Policy.Decide(ctx, policy.Input{
		UserID: userID, Role: userRole, Roles: roles,
		TargetID: targetID, TargetKind: kind, TargetTier: tier, Action: "ssh",
	})
	if err != nil {
		return nil, err
	}
	if !dec.Allow {
		return nil, fmt.Errorf("%w: %v", ErrPolicyDenied, dec.Reasons)
	}
	if dec.RequireApproval {
		ok, err := s.Approval.IsApproved(ctx, userID, targetID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrApprovalRequired
		}
	}

	// Close any prior active web sessions for this user+target so the Sessions tab
	// does not accumulate stale rows when users re-launch or close tabs without End.
	_ = sessions.EndActiveForUserTarget(ctx, s.DB, s.Vault, userID, targetID, "web", "superseded")

	// Look up the privileged account linked to this target.
	sessionID := fmt.Sprintf("web-%d-%d", time.Now().UnixNano(), targetID)
	username, password, hasAccount := s.lookupAccount(ctx, targetID)

	portalPassword := ""
	if userID > 0 && s.Vault != nil {
		if pw, err := s.Vault.GetSecret(ctx, vault.UserPassthroughKey(userID)); err == nil && len(pw) > 0 {
			portalPassword = string(pw)
		}
	}

	// Store credentials in vault so the proxy can retrieve them.
	creds := SessionCreds{
		Username:       username,
		Password:       password,
		TargetURL:      webURL,
		TargetKind:     kind,
		PortalUsername: strings.TrimSpace(portalUsername),
		PortalPassword: portalPassword,
	}
	if err := storeSessionCreds(ctx, s.Vault, sessionID, creds); err != nil {
		return nil, fmt.Errorf("store web session credentials: %w", err)
	}

	// Create session row.
	if reason == "" {
		reason = "Web console session via PAM"
	}
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO sessions(id, user_id, target_id, started_at, client_ip, protocol)
		VALUES(?,?,?,?,?,'web')`,
		sessionID, userID, targetID, db.Now(), clientIP)
	if err != nil {
		_ = s.Vault.DeleteSecret(ctx, SessionSecretName(sessionID))
		return nil, err
	}

	base := trimSlash(s.BrowserBase)
	viewerURL := fmt.Sprintf("%s/web-viewer.html?session=%s", base, sessionID)

	instructions := AuthHint(creds, hasAccount)
	if !hasAccount && strings.Contains(strings.ToLower(kind), "forti") {
		instructions += " Link a privileged account on this machine for passwordless auto-login instead of TACACS."
	}

	return &LaunchResult{
		SessionID:    sessionID,
		TargetName:   name,
		WebURL:       webURL,
		ViewerURL:    viewerURL,
		Username:     username,
		HasAccount:   hasAccount,
		Recorded:     true,
		Instructions: instructions,
	}, nil
}

func (s *Service) lookupAccount(ctx context.Context, targetID int64) (username, password string, ok bool) {
	var secretRef string
	err := s.DB.QueryRowContext(ctx, `
		SELECT a.username, a.secret_ref
		FROM privileged_accounts a
		WHERE a.target_id = ?
		ORDER BY a.id LIMIT 1`, targetID).Scan(&username, &secretRef)
	if err != nil {
		return "", "", false
	}
	pw, err := s.Vault.GetSecret(ctx, secretRef)
	if err != nil || len(pw) == 0 {
		return username, "", false
	}
	return username, string(pw), true
}

func storeSessionCreds(ctx context.Context, v *vault.Vault, sessionID string, c SessionCreds) error {
	payload := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		c.Username, c.Password, c.TargetURL, c.TargetKind, c.PortalUsername, c.PortalPassword)
	return v.PutSecret(ctx, SessionSecretName(sessionID), []byte(payload), nil)
}

// LoadSessionCreds retrieves session credentials from the vault.
func LoadSessionCreds(ctx context.Context, v *vault.Vault, sessionID string) (SessionCreds, error) {
	raw, err := v.GetSecret(ctx, SessionSecretName(sessionID))
	if err != nil {
		return SessionCreds{}, err
	}
	parts := strings.SplitN(string(raw), "\n", 6)
	c := SessionCreds{}
	if len(parts) > 0 {
		c.Username = parts[0]
	}
	if len(parts) > 1 {
		c.Password = parts[1]
	}
	if len(parts) > 2 {
		c.TargetURL = parts[2]
	}
	if len(parts) > 3 {
		c.TargetKind = parts[3]
	}
	if len(parts) > 4 {
		c.PortalUsername = parts[4]
	}
	if len(parts) > 5 {
		c.PortalPassword = parts[5]
	}
	return c, nil
}

func trimSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

