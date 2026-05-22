// Package sshlaunch authorizes browser SSH sessions via guacd (recorded terminal).
package sshlaunch

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
	"github.com/example/pam-platform/internal/vault"
)

// LaunchResult is returned when a user starts a browser SSH session.
type LaunchResult struct {
	SessionID    string `json:"session_id"`
	TargetName   string `json:"target_name"`
	Host         string `json:"host"`
	Port         int    `json:"port"`
	Username     string `json:"username"`
	BrowserURL   string `json:"browser_url"`
	Recorded     bool   `json:"recorded"`
	Instructions string `json:"instructions"`
}

// Service wires policy, approval, cert issuance, and session audit for SSH.
type Service struct {
	DB           *db.DB
	Policy       *policy.Engine
	Approval     *approval.Service
	Groups       *groups.Service
	Vault        *vault.Vault
	RecordingDir string
	BrowserBase  string
}

var (
	ErrTargetNotFound   = errors.New("target not found")
	ErrNotSSH           = errors.New("target is not an SSH machine")
	ErrPolicyDenied     = errors.New("access denied by policy")
	ErrApprovalRequired = errors.New("approved access request required — submit a request and wait for approval")
)

const downstreamUser = "pam-user"

// Launch authorizes the caller and prepares a recorded browser SSH session.
// portalPassword is optional: same password you enter at the PuTTY/ssh proxy prompt
// for passthrough device login when no privileged account is linked.
func (s *Service) Launch(ctx context.Context, targetID, userID int64, userRole, reason, clientIP, portalPassword string) (*LaunchResult, error) {
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
	ct := connectionType
	if ct == "" {
		ct = "ssh"
	}
	if ct != "ssh" {
		return nil, ErrNotSSH
	}
	if port <= 0 {
		port = 22
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

	principals := []string{userRole, downstreamUser}
	_ = principals // reserved for future direct-to-target cert auth

	var portalUser string
	_ = s.DB.QueryRowContext(ctx, `SELECT username FROM users WHERE id=?`, userID).Scan(&portalUser)
	if portalUser == "" {
		return nil, errors.New("portal user not found")
	}

	token, err := NewBrowserToken()
	if err != nil {
		return nil, fmt.Errorf("browser token: %w", err)
	}
	targetRef := TargetSSHRef(host, name, targetID)
	sessionID := fmt.Sprintf("ssh-%d-%d", time.Now().UnixNano(), targetID)
	creds, err := MarshalSessionCreds(SessionCreds{
		Mode: "browser", Token: token,
		PortalUser: portalUser, TargetRef: targetRef,
		UserID: userID, TargetID: targetID,
		SessionID: sessionID,
		PassthroughPW: strings.TrimSpace(portalPassword),
	})
	if err != nil {
		return nil, err
	}

	recDir := RecordingDirForSession(s.RecordingDir, sessionID)
	if err := s.Vault.PutSecret(ctx, SessionSecretName(sessionID), creds, nil); err != nil {
		return nil, fmt.Errorf("store session credentials: %w", err)
	}
	if err := s.Vault.PutSecret(ctx, BrowserTokenVaultKey(token), creds, nil); err != nil {
		_ = s.Vault.DeleteSecret(ctx, SessionSecretName(sessionID))
		return nil, fmt.Errorf("store browser token: %w", err)
	}

	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO sessions(id, user_id, target_id, started_at, client_ip, protocol, recording_path)
		VALUES(?,?,?,?,?,?,?)`,
		sessionID, userID, targetID, db.Now(), clientIP, "ssh", recDir)
	if err != nil {
		_ = s.Vault.DeleteSecret(ctx, BrowserTokenVaultKey(token))
		_ = s.Vault.DeleteSecret(ctx, SessionSecretName(sessionID))
		return nil, err
	}

	browserURL := ""
	if s.BrowserBase != "" {
		browserURL = fmt.Sprintf("%s/ssh-viewer.html?session=%s", trimSlash(s.BrowserBase), sessionID)
	}

	return &LaunchResult{
		SessionID:  sessionID,
		TargetName: name,
		Host:       host,
		Port:       port,
		Username:   downstreamUser,
		BrowserURL: browserURL,
		Recorded:   true,
		Instructions: "Browser session opens a recorded terminal in your browser (guacd). " +
			"Use the same @target as PuTTY (host or machine name). Provide your portal password at launch for switches without a privileged account.",
	}, nil
}

func trimSlash(s string) string {
	return strings.TrimRight(s, "/")
}
