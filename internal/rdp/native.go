package rdp

import (
	"context"
	"database/sql"
	"errors"
)

// NativeArtifacts holds optional native mstsc launch files (password embedded in script).
type NativeArtifacts struct {
	RDPFilename  string `json:"rdp_filename"`
	RDPFile      string `json:"rdp_file"`
	LaunchScript string `json:"launch_script"`
}

// NativeArtifactsForSession returns .rdp + PowerShell launcher for an active RDP session
// owned by the caller. Credentials are read from the ephemeral session vault entry.
func (s *Service) NativeArtifactsForSession(ctx context.Context, sessionID string, userID int64) (*NativeArtifacts, error) {
	var (
		ownerID int64
		host    string
		port    int
		name    string
		ended   sql.NullInt64
	)
	err := s.DB.QueryRowContext(ctx, `
		SELECT s.user_id, t.host, t.port, t.name, s.ended_at
		FROM sessions s
		JOIN targets t ON t.id = s.target_id
		WHERE s.id = ? AND COALESCE(s.protocol,'') = 'rdp'`, sessionID).
		Scan(&ownerID, &host, &port, &name, &ended)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("session not found")
		}
		return nil, err
	}
	if ownerID != userID {
		return nil, errors.New("session belongs to another user")
	}
	if ended.Valid {
		return nil, errors.New("session already ended")
	}
	var username string
	_ = s.DB.QueryRowContext(ctx, `
		SELECT COALESCE(pa.username,'')
		FROM sessions s
		LEFT JOIN privileged_accounts pa ON pa.id = s.account_id
		WHERE s.id = ?`, sessionID).Scan(&username)

	if s.Vault == nil {
		return nil, errors.New("session credentials unavailable")
	}
	pw, err := s.Vault.GetSessionSecret(SessionSecretName(sessionID))
	if err != nil || len(pw) == 0 {
		return nil, errors.New("session credentials expired or missing")
	}
	params := LaunchParams{Host: host, Port: port, Username: username, Name: name}
	rdpFilename := name + ".rdp"
	if rdpFilename == ".rdp" {
		rdpFilename = host + ".rdp"
	}
	return &NativeArtifacts{
		RDPFilename:  rdpFilename,
		RDPFile:      string(BuildRDPFile(params)),
		LaunchScript: BuildLaunchScript(params, string(pw), rdpFilename),
	}, nil
}
