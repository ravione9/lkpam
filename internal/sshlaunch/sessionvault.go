package sshlaunch

import "fmt"

// SessionSecretName is the vault key for a short-lived SSH private key.
func SessionSecretName(sessionID string) string {
	return "_ssh_session_" + sessionID
}

// RecordingDirForSession returns the directory guacd should write SSH recordings into.
func RecordingDirForSession(baseDir, sessionID string) string {
	return fmt.Sprintf("%s/ssh/%s", baseDir, sessionID)
}
