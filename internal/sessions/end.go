// Package sessions provides shared session lifecycle helpers (end, cleanup).
package sessions

import (
	"context"
	"strings"

	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/vault"
)

// WebVaultSecretName is the vault key for browser-proxied web console credentials.
func WebVaultSecretName(sessionID string) string {
	return "_web_session_" + sessionID
}

// End marks a session ended in the database and removes web vault credentials when applicable.
// Returns true if the session was active and is now ended.
func End(ctx context.Context, d *db.DB, v *vault.Vault, sessionID, reason string) (bool, error) {
	if reason == "" {
		reason = "closed"
	}
	res, err := d.ExecContext(ctx, `
		UPDATE sessions
		   SET ended_at = ?, ended_reason = ?
		 WHERE id = ? AND ended_at IS NULL`,
		db.Now(), reason, sessionID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	if v != nil && strings.HasPrefix(sessionID, "web-") {
		_ = v.DeleteSecret(ctx, WebVaultSecretName(sessionID))
	}
	return true, nil
}

// EndActiveForUserTarget ends all still-open sessions for a user on a target (optionally filtered by protocol).
func EndActiveForUserTarget(ctx context.Context, d *db.DB, v *vault.Vault, userID, targetID int64, protocol, reason string) error {
	q := `
		SELECT id FROM sessions
		 WHERE user_id = ? AND target_id = ? AND ended_at IS NULL`
	args := []any{userID, targetID}
	if protocol != "" {
		q += ` AND COALESCE(protocol, '') = ?`
		args = append(args, protocol)
	}
	rows, err := d.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			continue
		}
		ids = append(ids, id)
	}
	for _, id := range ids {
		_, _ = End(ctx, d, v, id, reason)
	}
	return nil
}
