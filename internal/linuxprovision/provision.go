// Package linuxprovision ensures a dedicated Linux account exists per portal user.
// A bootstrap account (e.g. pam-svc) is used only for provisioning — not the session.
package linuxprovision

import (
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// LinuxUsername maps a portal login to a safe local account name.
func LinuxUsername(portal string) string {
	u := strings.TrimSpace(portal)
	if i := strings.Index(u, "@"); i > 0 {
		u = u[:i]
	}
	u = strings.ToLower(u)
	var b strings.Builder
	for _, r := range u {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		out = "pamuser"
	}
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

// EnsureUser creates or updates the portal user's Linux account and optional sudo access.
// privilege is none | sudo | root (root grants passwordless sudo).
func EnsureUser(client *ssh.Client, portalUser, password, privilege string) error {
	user := LinuxUsername(portalUser)
	privilege = strings.ToLower(strings.TrimSpace(privilege))
	if privilege != "sudo" && privilege != "root" {
		privilege = "none"
	}
	pwB64 := base64.StdEncoding.EncodeToString([]byte(password))
	script := fmt.Sprintf(`set -e
U=%q
PW=$(printf %%s %q | base64 -d)
PRIV=%q
if ! id -u "$U" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$U"
fi
printf '%%s:%%s\n' "$U" "$PW" | chpasswd
if [ "$PRIV" = "sudo" ] || [ "$PRIV" = "root" ]; then
  if getent group sudo >/dev/null 2>&1; then
    usermod -aG sudo "$U" 2>/dev/null || true
  fi
  if getent group wheel >/dev/null 2>&1; then
    usermod -aG wheel "$U" 2>/dev/null || true
  fi
  f="/etc/sudoers.d/pam-${U}"
  printf '%%s ALL=(ALL) NOPASSWD: ALL\n' "$U" > "$f"
  chmod 0440 "$f"
fi
`, user, pwB64, privilege)

	sess, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("provision session: %w", err)
	}
	defer sess.Close()
	if err := sess.Run(script); err != nil {
		return fmt.Errorf("provision %q: %w", user, err)
	}
	return nil
}
