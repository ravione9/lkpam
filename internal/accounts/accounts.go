// Package accounts manages privileged accounts — the central CyberArk-style
// object representing a credential (typically a password) on a target system.
// Accounts live inside safes (see internal/safes) which provide the access
// policy.
//
// Each account has:
//   - a human-readable name (e.g. "root@db01")
//   - the actual username on the target
//   - a target reference (optional — applications without a target still work)
//   - a platform tag (linux / windows / cisco / ...) controlling rotation
//   - a secret_ref pointing into the vault (encrypted at rest)
//   - rotation metadata (last/next, status, error)
//
// Password rotation is delegated to the CPM (Central Policy Manager) worker
// in cmd/vault-service: it scans for accounts with next_rotation <= now and
// invokes platform-specific rotators.
package accounts

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/db"
)

// PrivilegedAccount is one managed credential.
type PrivilegedAccount struct {
	ID             int64  `json:"id"`
	SafeID         int64  `json:"safe_id"`
	SafeName       string `json:"safe_name,omitempty"`
	Name           string `json:"name"`
	Username       string `json:"username"`
	TargetID       *int64 `json:"target_id,omitempty"`
	TargetName     string `json:"target_name,omitempty"`
	Platform       string `json:"platform"`
	SecretRef      string `json:"secret_ref"`
	LastRotated    *int64 `json:"last_rotated,omitempty"`
	NextRotation   *int64 `json:"next_rotation,omitempty"`
	RotationStatus string `json:"rotation_status"`
	RotationError  string `json:"rotation_error,omitempty"`
	Notes          string `json:"notes"`
	CreatedAt      int64  `json:"created_at"`
}

// RotationLog is one entry in the rotation history.
type RotationLog struct {
	ID        int64  `json:"id"`
	AccountID int64  `json:"account_id"`
	TS        int64  `json:"ts"`
	Status    string `json:"status"`
	Actor     string `json:"actor"`
	Detail    string `json:"detail,omitempty"`
}

// Checkout is one credential pull (audit).
type Checkout struct {
	ID            int64  `json:"id"`
	AccountID     int64  `json:"account_id"`
	AccountName   string `json:"account_name,omitempty"`
	UserID        int64  `json:"user_id"`
	Username      string `json:"username,omitempty"`
	CheckedOutAt  int64  `json:"checked_out_at"`
	ReturnedAt    *int64 `json:"returned_at,omitempty"`
	Reason        string `json:"reason,omitempty"`
	BreakGlass    bool   `json:"break_glass"`
}

// SecretWriter is the minimal interface the accounts package needs to store
// passwords. internal/vault.Vault satisfies this.
type SecretWriter interface {
	PutSecret(ctx context.Context, name string, plaintext []byte, rotationDue *time.Time) error
	GetSecret(ctx context.Context, name string) ([]byte, error)
}

// Service manages accounts, rotation history, and credential checkouts.
type Service struct {
	DB    *db.DB
	Vault SecretWriter
}

// List returns all accounts (optionally filtered by safe).
func (s *Service) List(ctx context.Context, safeID int64) ([]PrivilegedAccount, error) {
	q := `
		SELECT a.id, a.safe_id, sf.name, a.name, a.username,
		       a.target_id, COALESCE(t.name,''), a.platform, a.secret_ref,
		       a.last_rotated, a.next_rotation, a.rotation_status, a.rotation_error,
		       a.notes, a.created_at
		FROM privileged_accounts a
		JOIN safes sf ON sf.id = a.safe_id
		LEFT JOIN targets t ON t.id = a.target_id`
	var rows *sql.Rows
	var err error
	if safeID > 0 {
		rows, err = s.DB.QueryContext(ctx, q+` WHERE a.safe_id = ? ORDER BY a.name`, safeID)
	} else {
		rows, err = s.DB.QueryContext(ctx, q+` ORDER BY sf.name, a.name`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAccounts(rows)
}

// FindPrimaryForTarget returns the privileged account linked to a machine for
// RDP/Windows access. When the account's safe has dual control enabled, the
// second return value is true (caller must verify JIT approval).
func (s *Service) FindPrimaryForTarget(ctx context.Context, targetID int64) (*PrivilegedAccount, bool, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT a.id, a.safe_id, sf.name, a.name, a.username,
		       a.target_id, COALESCE(t.name,''), a.platform, a.secret_ref,
		       a.last_rotated, a.next_rotation, a.rotation_status, a.rotation_error,
		       a.notes, a.created_at, sf.require_dual_control
		FROM privileged_accounts a
		JOIN safes sf ON sf.id = a.safe_id
		LEFT JOIN targets t ON t.id = a.target_id
		WHERE a.target_id = ?
		  AND (a.platform = 'windows' OR a.platform = 'rdp')
		ORDER BY a.id
		LIMIT 1`, targetID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, false, ErrNoAccountForTarget
	}
	var a PrivilegedAccount
	var tid sql.NullInt64
	var lastRot, nextRot sql.NullInt64
	var dual int
	if err := rows.Scan(&a.ID, &a.SafeID, &a.SafeName, &a.Name, &a.Username,
		&tid, &a.TargetName, &a.Platform, &a.SecretRef,
		&lastRot, &nextRot, &a.RotationStatus, &a.RotationError,
		&a.Notes, &a.CreatedAt, &dual); err != nil {
		return nil, false, err
	}
	if tid.Valid {
		a.TargetID = &tid.Int64
	}
	if lastRot.Valid {
		a.LastRotated = &lastRot.Int64
	}
	if nextRot.Valid {
		a.NextRotation = &nextRot.Int64
	}
	return &a, dual != 0, rows.Err()
}

var ErrNoAccountForTarget = errors.New("no privileged account linked to target")

// Get returns a single account by ID.
func (s *Service) Get(ctx context.Context, id int64) (*PrivilegedAccount, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT a.id, a.safe_id, sf.name, a.name, a.username,
		       a.target_id, COALESCE(t.name,''), a.platform, a.secret_ref,
		       a.last_rotated, a.next_rotation, a.rotation_status, a.rotation_error,
		       a.notes, a.created_at
		FROM privileged_accounts a
		JOIN safes sf ON sf.id = a.safe_id
		LEFT JOIN targets t ON t.id = a.target_id
		WHERE a.id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out, err := scanAccounts(rows)
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("account not found")
	}
	return &out[0], nil
}

func scanAccounts(rows *sql.Rows) ([]PrivilegedAccount, error) {
	var out []PrivilegedAccount
	for rows.Next() {
		var a PrivilegedAccount
		var tgt, lr, nr sql.NullInt64
		if err := rows.Scan(&a.ID, &a.SafeID, &a.SafeName, &a.Name, &a.Username,
			&tgt, &a.TargetName, &a.Platform, &a.SecretRef,
			&lr, &nr, &a.RotationStatus, &a.RotationError,
			&a.Notes, &a.CreatedAt); err != nil {
			return nil, err
		}
		if tgt.Valid {
			a.TargetID = &tgt.Int64
		}
		if lr.Valid {
			a.LastRotated = &lr.Int64
		}
		if nr.Valid {
			a.NextRotation = &nr.Int64
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateInput captures what the UI/API supplies on account creation.
type CreateInput struct {
	SafeID    int64  `json:"safe_id"`
	Name      string `json:"name"`
	Username  string `json:"username"`
	TargetID  *int64 `json:"target_id,omitempty"`
	Platform  string `json:"platform"`
	Password  string `json:"password"`   // initial password
	Notes     string `json:"notes"`
}

// Create inserts a new account and stores its initial password in the vault.
func (s *Service) Create(ctx context.Context, in CreateInput) (int64, error) {
	if in.SafeID <= 0 || in.Name == "" || in.Username == "" {
		return 0, errors.New("safe_id, name, and username are required")
	}
	if in.Platform == "" {
		in.Platform = "linux"
	}
	// Lookup safe rotation policy.
	var rotDays, cpm int
	if err := s.DB.QueryRowContext(ctx,
		`SELECT rotation_days, cpm_enabled FROM safes WHERE id = ?`, in.SafeID).
		Scan(&rotDays, &cpm); err != nil {
		return 0, errors.New("safe not found")
	}

	secretRef := "acct/" + safeName(in.Name)
	if in.Password == "" {
		in.Password = generatePassword(28)
	}
	if err := s.Vault.PutSecret(ctx, secretRef, []byte(in.Password), nil); err != nil {
		return 0, err
	}

	now := db.Now()
	var nextRot any
	if cpm != 0 {
		nextRot = now + int64(rotDays)*86400
	}
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO privileged_accounts(safe_id, name, username, target_id, platform,
		  secret_ref, last_rotated, next_rotation, rotation_status, notes, created_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?)`,
		in.SafeID, in.Name, in.Username, in.TargetID, in.Platform,
		secretRef, now, nextRot, "ok", in.Notes, now)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	s.recordRotation(ctx, id, "created", "system", "Initial password stored")
	return id, nil
}

// Update changes mutable fields on an account.
func (s *Service) Update(ctx context.Context, a PrivilegedAccount) error {
	if a.ID <= 0 {
		return errors.New("id required")
	}
	_, err := s.DB.ExecContext(ctx, `
		UPDATE privileged_accounts
		SET username=?, target_id=?, platform=?, notes=?
		WHERE id=?`,
		a.Username, a.TargetID, a.Platform, a.Notes, a.ID)
	return err
}

// Delete removes an account and its vault secret.
func (s *Service) Delete(ctx context.Context, id int64) error {
	acct, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx,
		`DELETE FROM privileged_accounts WHERE id=?`, id); err != nil {
		return err
	}
	if _, err := s.DB.ExecContext(ctx,
		`DELETE FROM secrets WHERE name=?`, acct.SecretRef); err != nil {
		return err
	}
	return nil
}

// Rotate replaces an account's password with a freshly generated one. The
// rotator is responsible for actually pushing the password to the target;
// here we focus on the vault side. Target-side rotators live in the CPM
// worker (cmd/vault-service).
func (s *Service) Rotate(ctx context.Context, id int64, actor string) error {
	acct, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	newPW := generatePassword(28)
	if err := s.Vault.PutSecret(ctx, acct.SecretRef, []byte(newPW), nil); err != nil {
		s.markRotationFailed(ctx, id, actor, err.Error())
		return err
	}
	now := db.Now()
	// Lookup safe rotation_days to schedule next rotation.
	var rotDays int
	_ = s.DB.QueryRowContext(ctx,
		`SELECT rotation_days FROM safes WHERE id = ?`, acct.SafeID).Scan(&rotDays)
	if rotDays <= 0 {
		rotDays = 90
	}
	next := now + int64(rotDays)*86400
	if _, err := s.DB.ExecContext(ctx, `
		UPDATE privileged_accounts
		SET last_rotated=?, next_rotation=?, rotation_status='ok', rotation_error=''
		WHERE id=?`, now, next, id); err != nil {
		return err
	}
	s.recordRotation(ctx, id, "ok", actor, "Password rotated and vaulted")
	return nil
}

func (s *Service) markRotationFailed(ctx context.Context, id int64, actor, detail string) {
	_, _ = s.DB.ExecContext(ctx, `
		UPDATE privileged_accounts SET rotation_status='failed', rotation_error=?
		WHERE id=?`, detail, id)
	s.recordRotation(ctx, id, "failed", actor, detail)
}

func (s *Service) recordRotation(ctx context.Context, id int64, status, actor, detail string) {
	_, _ = s.DB.ExecContext(ctx, `
		INSERT INTO rotation_history(account_id, ts, status, actor, detail)
		VALUES(?,?,?,?,?)`, id, db.Now(), status, actor, detail)
}

// History returns rotation events for an account (newest first).
func (s *Service) History(ctx context.Context, accountID int64, limit int) ([]RotationLog, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, account_id, ts, status, actor, detail
		FROM rotation_history WHERE account_id=?
		ORDER BY ts DESC LIMIT ?`, accountID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RotationLog
	for rows.Next() {
		var l RotationLog
		if err := rows.Scan(&l.ID, &l.AccountID, &l.TS, &l.Status, &l.Actor, &l.Detail); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// CheckoutResult is returned from a checkout call.
type CheckoutResult struct {
	Password    string `json:"password"`
	CheckoutID  int64  `json:"checkout_id"`
	BreakGlass  bool   `json:"break_glass"`
}

// Checkout reveals the account password to a user and records the event.
// BreakGlass forces audit elevation regardless of safe policy.
func (s *Service) Checkout(ctx context.Context, accountID, userID int64,
	reason string, breakGlass bool) (*CheckoutResult, error) {
	acct, err := s.Get(ctx, accountID)
	if err != nil {
		return nil, err
	}
	pw, err := s.Vault.GetSecret(ctx, acct.SecretRef)
	if err != nil {
		return nil, err
	}
	res, err := s.DB.ExecContext(ctx, `
		INSERT INTO credential_checkouts(account_id, user_id, checked_out_at,
		  reason, break_glass)
		VALUES(?,?,?,?,?)`,
		accountID, userID, db.Now(), reason, boolInt(breakGlass))
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &CheckoutResult{Password: string(pw), CheckoutID: id, BreakGlass: breakGlass}, nil
}

// Return marks a checkout as completed (the credential is no longer in use).
func (s *Service) Return(ctx context.Context, checkoutID int64) error {
	_, err := s.DB.ExecContext(ctx, `
		UPDATE credential_checkouts SET returned_at=?
		WHERE id=? AND returned_at IS NULL`, db.Now(), checkoutID)
	return err
}

// ListCheckouts returns recent checkouts (optionally for a single user).
func (s *Service) ListCheckouts(ctx context.Context, userID int64, limit int) ([]Checkout, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `
		SELECT c.id, c.account_id, a.name, c.user_id, u.username,
		       c.checked_out_at, c.returned_at, c.reason, c.break_glass
		FROM credential_checkouts c
		JOIN privileged_accounts a ON a.id = c.account_id
		JOIN users u ON u.id = c.user_id`
	var rows *sql.Rows
	var err error
	if userID > 0 {
		rows, err = s.DB.QueryContext(ctx, q+` WHERE c.user_id = ? ORDER BY c.checked_out_at DESC LIMIT ?`, userID, limit)
	} else {
		rows, err = s.DB.QueryContext(ctx, q+` ORDER BY c.checked_out_at DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Checkout
	for rows.Next() {
		var c Checkout
		var ret sql.NullInt64
		var bg int
		if err := rows.Scan(&c.ID, &c.AccountID, &c.AccountName, &c.UserID, &c.Username,
			&c.CheckedOutAt, &ret, &c.Reason, &bg); err != nil {
			return nil, err
		}
		if ret.Valid {
			c.ReturnedAt = &ret.Int64
		}
		c.BreakGlass = bg != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// Due returns accounts whose next_rotation has passed. The CPM worker
// drains this list.
func (s *Service) Due(ctx context.Context) ([]PrivilegedAccount, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT a.id, a.safe_id, sf.name, a.name, a.username,
		       a.target_id, COALESCE(t.name,''), a.platform, a.secret_ref,
		       a.last_rotated, a.next_rotation, a.rotation_status, a.rotation_error,
		       a.notes, a.created_at
		FROM privileged_accounts a
		JOIN safes sf ON sf.id = a.safe_id
		LEFT JOIN targets t ON t.id = a.target_id
		WHERE sf.cpm_enabled = 1
		  AND a.next_rotation IS NOT NULL
		  AND a.next_rotation <= ?
		ORDER BY a.next_rotation`, db.Now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAccounts(rows)
}

// safeName returns a secret-safe name for the vault key.
func safeName(s string) string {
	// Collapse non-alphanum to underscore; vault keys are arbitrary strings
	// but we keep them tidy.
	b := strings.Builder{}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9',
			r == '-', r == '_', r == '.', r == '@':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// generatePassword returns a cryptographically random URL-safe password of
// roughly the requested length.
func generatePassword(n int) string {
	buf := make([]byte, n)
	_, _ = rand.Read(buf)
	pw := base64.URLEncoding.EncodeToString(buf)
	if len(pw) > n {
		pw = pw[:n]
	}
	return pw
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
