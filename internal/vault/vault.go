// Package vault is the credential store. Plaintext secrets never leave this
// package's address space — callers receive ephemeral artifacts (SSH certs)
// instead of raw passwords wherever possible.
//
// The master key is loaded from PAM_MASTER_KEY (base64). In production this
// key is unwrapped from an HSM via PKCS#11 at startup and held only in
// mlocked memory.
package vault

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/cryptox"
	"github.com/example/pam-platform/internal/db"

	"golang.org/x/crypto/ssh"
)

// Vault wraps the secret store.
type Vault struct {
	DB        *db.DB
	MasterKey []byte // 32 bytes
	CAPriv    []byte // PEM SSH CA private key (in-memory; on disk it's encrypted)
}

// New loads (or creates) the master key and SSH CA.
func New(d *db.DB, masterKeyB64 string) (*Vault, error) {
	var key []byte
	if masterKeyB64 == "" {
		k, err := cryptox.NewMasterKey()
		if err != nil {
			return nil, err
		}
		key = k
	} else {
		k, err := base64.StdEncoding.DecodeString(masterKeyB64)
		if err != nil {
			return nil, fmt.Errorf("vault: decode master key: %w", err)
		}
		if len(k) != cryptox.MasterKeyLen {
			return nil, errors.New("vault: master key must be 32 bytes")
		}
		key = k
	}

	v := &Vault{DB: d, MasterKey: key}
	if err := v.ensureCA(); err != nil {
		return nil, err
	}
	return v, nil
}

// ensureCA generates a CA if none exists in the secrets table and persists
// the encrypted private key. The public key is exposed via PublicCAKey().
func (v *Vault) ensureCA() error {
	ctx := context.Background()
	row := v.DB.QueryRowContext(ctx, `SELECT ciphertext FROM secrets WHERE name = ?`, "_ssh_ca")
	var ct string
	err := row.Scan(&ct)
	if err == sql.ErrNoRows {
		priv, pub, err := cryptox.NewSSHCA()
		if err != nil {
			return err
		}
		enc, err := cryptox.Encrypt(v.MasterKey, priv)
		if err != nil {
			return err
		}
		if _, err := v.DB.ExecContext(ctx,
			`INSERT INTO secrets(name, ciphertext, updated_at) VALUES(?,?,?)`,
			"_ssh_ca", enc, db.Now()); err != nil {
			return err
		}
		if _, err := v.DB.ExecContext(ctx,
			`INSERT INTO secrets(name, ciphertext, updated_at) VALUES(?,?,?)`,
			"_ssh_ca_pub", string(pub), db.Now()); err != nil {
			return err
		}
		v.CAPriv = priv
		return nil
	}
	if err != nil {
		return err
	}
	plain, err := cryptox.Decrypt(v.MasterKey, ct)
	if err != nil {
		return fmt.Errorf("vault: decrypt CA: %w", err)
	}
	v.CAPriv = plain
	return nil
}

// PublicCAKey returns the SSH CA public key in authorized_keys format.
// Targets should be configured to trust this key.
func (v *Vault) PublicCAKey(ctx context.Context) ([]byte, error) {
	var pub string
	err := v.DB.QueryRowContext(ctx,
		`SELECT ciphertext FROM secrets WHERE name = ?`, "_ssh_ca_pub").Scan(&pub)
	return []byte(pub), err
}

// PutSecret stores plaintext under name, encrypted with the master key.
func (v *Vault) PutSecret(ctx context.Context, name string, plaintext []byte, rotationDue *time.Time) error {
	enc, err := cryptox.Encrypt(v.MasterKey, plaintext)
	if err != nil {
		return err
	}
	var dueUnix any
	if rotationDue != nil {
		dueUnix = rotationDue.Unix()
	}
	_, err = v.DB.ExecContext(ctx, `
		INSERT INTO secrets(name, ciphertext, rotation_due, updated_at)
		VALUES(?,?,?,?)
		ON CONFLICT(name) DO UPDATE SET
		  ciphertext = excluded.ciphertext,
		  rotation_due = excluded.rotation_due,
		  updated_at = excluded.updated_at`,
		name, enc, dueUnix, db.Now())
	return err
}

// GetSecret retrieves and decrypts the plaintext value. CAUTION: should only
// be exposed to internal callers that need the raw value (e.g. for credential
// injection by the proxy); never via the user-facing API.
func (v *Vault) GetSecret(ctx context.Context, name string) ([]byte, error) {
	var ct string
	err := v.DB.QueryRowContext(ctx, `SELECT ciphertext FROM secrets WHERE name = ?`, name).Scan(&ct)
	if err == sql.ErrNoRows {
		return nil, errors.New("secret not found")
	}
	if err != nil {
		return nil, err
	}
	return cryptox.Decrypt(v.MasterKey, ct)
}

// SecretMeta is secret metadata safe to expose in the admin UI.
type SecretMeta struct {
	Name       string `json:"name"`
	TargetID   *int64 `json:"target_id,omitempty"`
	UpdatedAt  int64  `json:"updated_at"`
	RotationDue *int64 `json:"rotation_due,omitempty"`
}

// ListSecrets returns metadata for user-managed secrets (CA keys excluded).
func (v *Vault) ListSecrets(ctx context.Context) ([]SecretMeta, error) {
	rows, err := v.DB.QueryContext(ctx, `
		SELECT name, target_id, updated_at, rotation_due
		FROM secrets
		WHERE name NOT IN ('_ssh_ca', '_ssh_ca_pub')
		ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretMeta
	for rows.Next() {
		var m SecretMeta
		var targetID sql.NullInt64
		var rotDue sql.NullInt64
		if err := rows.Scan(&m.Name, &targetID, &m.UpdatedAt, &rotDue); err != nil {
			return nil, err
		}
		if targetID.Valid {
			m.TargetID = &targetID.Int64
		}
		if rotDue.Valid {
			m.RotationDue = &rotDue.Int64
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// DeleteSecret removes a secret by name (CA keys cannot be deleted).
func (v *Vault) DeleteSecret(ctx context.Context, name string) error {
	if strings.HasPrefix(name, "_ssh_ca") {
		return errors.New("cannot delete CA keys")
	}
	res, err := v.DB.ExecContext(ctx, `DELETE FROM secrets WHERE name = ?`, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("secret not found")
	}
	return nil
}

// IssueSSHCert generates an ephemeral Ed25519 keypair and signs a user cert
// with the vault's CA. Returns the private key (for the proxy to use
// immediately) and the marshaled certificate. Both must be discarded
// immediately after the session opens.
func (v *Vault) IssueSSHCert(principals []string, ttl time.Duration) (privPEM []byte, certAuth []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: gen ed25519: %w", err)
	}

	pemBlock, err := ssh.MarshalPrivateKey(priv, "pam-ephemeral")
	if err != nil {
		return nil, nil, fmt.Errorf("vault: marshal user priv: %w", err)
	}
	privPEM = pem.EncodeToMemory(pemBlock)

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("vault: marshal user pub: %w", err)
	}

	cert, err := cryptox.IssueUserCert(v.CAPriv, sshPub, principals, ttl)
	if err != nil {
		return nil, nil, err
	}
	certAuth = ssh.MarshalAuthorizedKey(cert)
	return privPEM, certAuth, nil
}
