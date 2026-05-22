package sshlaunch

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
)

// SessionCreds is stored in the vault for a browser SSH session.
type SessionCreds struct {
	Mode       string `json:"mode"` // browser
	Token      string `json:"token"`
	PortalUser string `json:"portal_user"`
	TargetRef      string `json:"target_ref"` // host/name slug or #id (same as PuTTY -l)
	UserID         int64  `json:"user_id"`
	TargetID       int64  `json:"target_id"`
	SessionID      string `json:"session_id"`
	PassthroughPW  string `json:"passthrough_pw,omitempty"` // optional portal password for device login
}

// BrowserTokenVaultKey is the vault lookup key for ssh-proxy one-time auth.
func BrowserTokenVaultKey(token string) string {
	return "_ssh_browser_token_" + token
}

// NewBrowserToken returns a one-time token for guacd → ssh-proxy auth.
func NewBrowserToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// MarshalSessionCreds encodes credentials for vault storage.
func MarshalSessionCreds(c SessionCreds) ([]byte, error) {
	return json.Marshal(c)
}

// ParseSessionCreds decodes vault payload.
func ParseSessionCreds(raw []byte) (SessionCreds, error) {
	var c SessionCreds
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, err
	}
	return c, nil
}

// TargetRef returns the ssh-proxy machine identifier for a target ID.
func TargetRef(targetID int64) string {
	return "#" + formatInt(targetID)
}

func formatInt(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
