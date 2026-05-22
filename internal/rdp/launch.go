// Launch orchestrates CyberArk-style RDP access: policy check, JIT approval,
// privileged-account checkout, session audit, and launch artifact generation.
package rdp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/example/pam-platform/internal/accounts"
	"github.com/example/pam-platform/internal/approval"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/sessions"
)

// LaunchResult is returned to the portal when a user starts an RDP session.
// Passwords are never included — browser sessions use the PAM proxy (guacd).
type LaunchResult struct {
	SessionID    string `json:"session_id"`
	CheckoutID   int64  `json:"checkout_id"`
	AccountID    int64  `json:"account_id"`
	AccountName  string `json:"account_name"`
	Username     string `json:"username"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	ViewerURL    string `json:"viewer_url"`
	BrowserURL   string `json:"browser_url,omitempty"` // deprecated alias for viewer_url
	Recorded     bool   `json:"recorded"`
	Instructions string `json:"instructions"`
}

// Service wires policy, approval, accounts, and session audit for RDP.
type Service struct {
	DB           *db.DB
	Policy       *policy.Engine
	Approval     *approval.Service
	Accounts     *accounts.Service
	Groups       *groups.Service
	Vault        SessionVault
	RecordingDir string
	// BrowserBase is the public portal root, e.g. https://pam.corp.local
	BrowserBase string
}

var (
	ErrTargetNotFound   = errors.New("target not found")
	ErrNotRDP           = errors.New("target is not an RDP machine")
	ErrPolicyDenied     = errors.New("access denied by policy")
	ErrApprovalRequired = errors.New("approved access request required — submit a request and wait for approval")
	ErrDualControl      = errors.New("safe requires dual control — submit and obtain an approved access request first")
)

// Launch authorizes the caller and returns RDP launch artifacts.
func (s *Service) Launch(ctx context.Context, targetID, userID int64, userRole, reason, clientIP string) (*LaunchResult, error) {
	var (
		name           string
		kind           string
		host           string
		port           int
		tier           int
		connectionType string
	)
	err := s.DB.QueryRowContext(ctx, `
		SELECT name, kind, host, port, tier, connection_type
		FROM targets WHERE id = ?`, targetID).
		Scan(&name, &kind, &host, &port, &tier, &connectionType)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTargetNotFound
		}
		return nil, err
	}
	if connectionType != "rdp" {
		return nil, ErrNotRDP
	}

	roles, err := s.Groups.EffectiveRoles(ctx, userID, userRole)
	if err != nil {
		return nil, err
	}
	dec, err := s.Policy.Decide(ctx, policy.Input{
		UserID: userID, Role: userRole, Roles: roles,
		TargetID: targetID, TargetKind: kind, TargetTier: tier, Action: "rdp",
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

	acct, dualControl, err := s.Accounts.FindPrimaryForTarget(ctx, targetID)
	if err != nil {
		return nil, err
	}
	if dualControl {
		ok, err := s.Approval.IsApproved(ctx, userID, targetID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrDualControl
		}
	}
	// End stale browser RDP sessions for this user+target (re-launch without orphan rows).
	if s.Vault != nil {
		va, ok := s.Vault.(*VaultAdapter)
		if ok && va.V != nil {
			_ = sessions.EndActiveForUserTarget(ctx, s.DB, va.V, userID, targetID, "rdp", "superseded")
		}
	}

	if reason == "" {
		reason = "RDP session via PAM"
	}
	co, err := s.Accounts.Checkout(ctx, acct.ID, userID, reason, false)
	if err != nil {
		return nil, err
	}

	sessionID := fmt.Sprintf("rdp-%d-%d", time.Now().UnixNano(), targetID)
	recDir := RecordingDirForSession(s.RecordingDir, sessionID)
	if s.Vault != nil {
		if err := s.Vault.PutSessionSecret(SessionSecretName(sessionID), []byte(co.Password)); err != nil {
			return nil, fmt.Errorf("store session credentials: %w", err)
		}
	}
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO sessions(id, user_id, target_id, started_at, client_ip, protocol, account_id, recording_path)
		VALUES(?,?,?,?,?,?,?,?)`,
		sessionID, userID, targetID, db.Now(), clientIP, "rdp", acct.ID, recDir)
	if err != nil {
		if s.Vault != nil {
			_ = s.Vault.DeleteSessionSecret(SessionSecretName(sessionID))
		}
		return nil, err
	}

	viewerURL := "/rdp-viewer.html?session=" + sessionID
	if s.BrowserBase != "" {
		viewerURL = fmt.Sprintf("%s/rdp-viewer.html?session=%s", stringsTrimRightSlash(s.BrowserBase), sessionID)
	}

	return &LaunchResult{
		SessionID:   sessionID,
		CheckoutID:  co.CheckoutID,
		AccountID:   acct.ID,
		AccountName: acct.Name,
		Username:    acct.Username,
		Host:        host,
		Port:        port,
		ViewerURL:   viewerURL,
		BrowserURL:  viewerURL,
		Recorded:    true,
		Instructions: "Opening a recorded RDP session in your browser. PAM injects privileged credentials through the gateway — you do not see or type the vault password. " +
			"Optional: use Advanced → native Remote Desktop (.rdp) from the launch dialog (not recorded).",
	}, nil
}

func stringsTrimRightSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
