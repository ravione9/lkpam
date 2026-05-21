package rdp

import "fmt"

// SessionSecretName is the vault key for a short-lived RDP session password.
func SessionSecretName(sessionID string) string {
	return "_rdp_session_" + sessionID
}

// RecordingDirForSession returns the directory guacd should write recordings into.
func RecordingDirForSession(baseDir, sessionID string) string {
	return fmt.Sprintf("%s/rdp/%s", baseDir, sessionID)
}

// SessionVault stores ephemeral checkout passwords for browser RDP sessions.
type SessionVault interface {
	PutSessionSecret(name string, plaintext []byte) error
	GetSessionSecret(name string) ([]byte, error)
	DeleteSessionSecret(name string) error
}
