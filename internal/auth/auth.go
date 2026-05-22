// Package auth handles user authentication, JWT issuance/verification, and
// the (stub) MFA layer. In production, MFA hands off to the IdP — here we
// implement a simple TOTP check so the flow is real.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/cryptox"
	"github.com/example/pam-platform/internal/db"

	"github.com/golang-jwt/jwt/v5"
)

// User is the canonical user record.
type User struct {
	ID         int64  `json:"id"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	Disabled   bool   `json:"disabled"`
	Source     string `json:"source"`
	MFAEnabled bool   `json:"mfa_enabled"`
	MFAExempt  bool   `json:"mfa_exempt"`
	RoleLocked bool   `json:"role_locked"`
	LastLogin  int64  `json:"last_login,omitempty"`
}

// Service is the auth service core.
type Service struct {
	DB         *db.DB
	JWTSecret  []byte
	JWTTTL     time.Duration
	JWTIssuer  string
	JWTAudience string
}

// Claims is the JWT claim set we issue.
type Claims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"u"`
	Role     string `json:"r"`
	Scope    string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

// EffectiveMFAPolicy returns the active MFA policy; empty/unset defaults to required.
func EffectiveMFAPolicy(policy string) string {
	switch policy {
	case "off", "optional", "required":
		return policy
	default:
		return "required"
	}
}

// MFALoginDecision describes MFA handling during login.
type MFALoginDecision struct {
	RequireOTP        bool
	RequireEnrollment bool
}

// LoginMFADecision decides whether OTP or enrollment is needed for a user.
func LoginMFADecision(u *User, policy string) MFALoginDecision {
	if u.MFAExempt {
		return MFALoginDecision{}
	}
	switch EffectiveMFAPolicy(policy) {
	case "required":
		if !u.MFAEnabled {
			return MFALoginDecision{RequireEnrollment: true}
		}
		return MFALoginDecision{RequireOTP: true}
	case "optional":
		if u.MFAEnabled {
			return MFALoginDecision{RequireOTP: true}
		}
	}
	return MFALoginDecision{}
}

// LoginMFADecisionForUser applies policy and verifies a TOTP secret exists when OTP is required.
func (s *Service) LoginMFADecisionForUser(ctx context.Context, u *User, policy string) (MFALoginDecision, error) {
	dec := LoginMFADecision(u, policy)
	if !dec.RequireOTP {
		return dec, nil
	}
	secret, err := s.GetMFASecret(ctx, u.ID)
	if err != nil {
		return dec, err
	}
	if secret != "" {
		return dec, nil
	}
	// Enrolled flag set but secret missing — treat as needs setup.
	if EffectiveMFAPolicy(policy) == "required" && !u.MFAExempt {
		return MFALoginDecision{RequireEnrollment: true}, nil
	}
	return MFALoginDecision{}, nil
}

// LoginMFADecisionForDevice applies MFA on SSH/TACACS only when the user has
// completed TOTP enrollment. Unenrolled users may access devices with password
// alone; portal login still drives MFA setup when policy is required.
func (s *Service) LoginMFADecisionForDevice(ctx context.Context, u *User) (MFALoginDecision, error) {
	if u.MFAExempt || !u.MFAEnabled {
		return MFALoginDecision{}, nil
	}
	secret, err := s.GetMFASecret(ctx, u.ID)
	if err != nil {
		return MFALoginDecision{}, err
	}
	if secret == "" {
		return MFALoginDecision{}, nil
	}
	return MFALoginDecision{RequireOTP: true}, nil
}

func (s *Service) CreateUser(ctx context.Context, username, email, password, role string) (int64, error) {
	if role == "" {
		role = "user"
	}
	hash, err := cryptox.PasswordHash(password)
	if err != nil {
		return 0, fmt.Errorf("auth: hash: %w", err)
	}
	res, err := s.DB.ExecContext(ctx,
		`INSERT INTO users(username,email,password_hash,role,created_at) VALUES(?,?,?,?,?)`,
		username, email, hash, role, db.Now())
	if err != nil {
		return 0, fmt.Errorf("auth: insert user: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// Authenticate verifies username/password against the local store and returns
// the User. LDAP authentication lives in the auth-service main, which calls
// FindByUsername / RecordLogin and skips this method for ldap-sourced users.
func (s *Service) Authenticate(ctx context.Context, username, password string) (*User, error) {
	u, pwHash, err := s.loadUser(ctx, username)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	if u.Disabled {
		return nil, errors.New("account disabled")
	}
	if u.Source != "local" {
		return nil, errors.New("invalid credentials") // LDAP users use the LDAP flow
	}
	if !cryptox.VerifyPassword(password, pwHash) {
		return nil, errors.New("invalid credentials")
	}
	return u, nil
}

// AuthenticateByLoginID accepts username or email and verifies a local account password.
func (s *Service) AuthenticateByLoginID(ctx context.Context, loginID, password string) (*User, error) {
	u, err := s.FindByLoginID(ctx, loginID)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	if u.Source != "local" {
		return nil, errors.New("invalid credentials")
	}
	return s.Authenticate(ctx, u.Username, password)
}

// FindByUsername returns a user record without performing a password check.
// Used by the LDAP login flow once the LDAP bind has succeeded.
func (s *Service) FindByUsername(ctx context.Context, username string) (*User, error) {
	u, _, err := s.loadUser(ctx, username)
	return u, err
}

// FindByLoginID resolves a portal login identifier (username or email) to a user.
// When multiple records share an email, LDAP/SSO accounts take precedence over
// disabled local duplicates created by mistake in the admin UI.
func (s *Service) FindByLoginID(ctx context.Context, loginID string) (*User, error) {
	loginID = strings.TrimSpace(loginID)
	if loginID == "" {
		return nil, sql.ErrNoRows
	}
	if u, err := s.FindByUsername(ctx, loginID); err == nil {
		return u, nil
	}
	row := s.DB.QueryRowContext(ctx, `
		SELECT id, username, COALESCE(email,''), role, disabled,
		       COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(mfa_exempt,0),
		       COALESCE(last_login,0), COALESCE(role_locked,0)
		FROM users WHERE lower(username)=lower(?)`, loginID)
	if u, err := scanUserRow(row); err == nil {
		return u, nil
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	// Prefer active directory-backed accounts when email is reused.
	row = s.DB.QueryRowContext(ctx, `
		SELECT id, username, COALESCE(email,''), role, disabled,
		       COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(mfa_exempt,0),
		       COALESCE(last_login,0), COALESCE(role_locked,0)
		FROM users
		WHERE lower(email)=lower(?) AND source IN ('ldap','saml') AND disabled=0
		ORDER BY id LIMIT 1`, loginID)
	if u, err := scanUserRow(row); err == nil {
		return u, nil
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	row = s.DB.QueryRowContext(ctx, `
		SELECT id, username, COALESCE(email,''), role, disabled,
		       COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(mfa_exempt,0),
		       COALESCE(last_login,0), COALESCE(role_locked,0)
		FROM users WHERE lower(email)=lower(?)
		ORDER BY id LIMIT 1`, loginID)
	return scanUserRow(row)
}

func scanUserRow(row *sql.Row) (*User, error) {
	var u User
	var disabled, mfa, exempt, roleLocked int
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &disabled,
		&u.Source, &mfa, &exempt, &u.LastLogin, &roleLocked); err != nil {
		return nil, err
	}
	u.Disabled = disabled != 0
	u.MFAEnabled = mfa != 0
	u.MFAExempt = exempt != 0
	u.RoleLocked = roleLocked != 0
	return &u, nil
}

func (s *Service) loadUser(ctx context.Context, username string) (*User, string, error) {
	row := s.DB.QueryRowContext(ctx, `
		SELECT id, username, COALESCE(email,''), password_hash, role, disabled,
		       COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(mfa_exempt,0),
		       COALESCE(last_login,0), COALESCE(role_locked,0)
		FROM users WHERE username = ?`, username)
	var u User
	var pwHash string
	var disabled, mfa, exempt, roleLocked int
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &pwHash, &u.Role, &disabled,
		&u.Source, &mfa, &exempt, &u.LastLogin, &roleLocked); err != nil {
		return nil, "", err
	}
	u.Disabled = disabled != 0
	u.MFAEnabled = mfa != 0
	u.MFAExempt = exempt != 0
	u.RoleLocked = roleLocked != 0
	return &u, pwHash, nil
}

// RecordLogin updates the user's last_login timestamp.
func (s *Service) RecordLogin(ctx context.Context, userID int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET last_login=? WHERE id=?`, db.Now(), userID)
	return err
}

// UpsertLDAPUser creates or updates a local user record sourced from LDAP.
// The password hash stays empty — these users can only log in via LDAP bind.
func (s *Service) UpsertLDAPUser(ctx context.Context, username, email, role, dn string) (*User, error) {
	return s.upsertExternalUser(ctx, "ldap", username, email, role, dn)
}

// UpsertSAMLUser creates or updates a local user record sourced from a SAML IdP.
func (s *Service) UpsertSAMLUser(ctx context.Context, username, email, role, nameID string) (*User, error) {
	return s.upsertExternalUser(ctx, "saml", username, email, role, nameID)
}

func (s *Service) upsertExternalUser(ctx context.Context, source, username, email, role, externalID string) (*User, error) {
	if role == "" {
		role = "user"
	}
	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO users(username, email, password_hash, role, source, external_dn, created_at)
		VALUES(?,?,?,?,?,?,?)
		ON CONFLICT(username) DO UPDATE SET
		  email=CASE WHEN users.source='local' THEN users.email ELSE excluded.email END,
		  role=CASE
		    WHEN COALESCE(users.role_locked,0)=1 THEN users.role
		    WHEN users.source='local' THEN users.role
		    ELSE excluded.role
		  END,
		  source=CASE WHEN users.source='local' THEN users.source ELSE excluded.source END,
		  external_dn=CASE WHEN users.source='local' THEN users.external_dn ELSE excluded.external_dn END,
		  password_hash=CASE WHEN users.source='local' THEN users.password_hash ELSE '' END`,
		username, email, "", role, source, externalID, db.Now())
	if err != nil {
		return nil, fmt.Errorf("auth: upsert %s user: %w", source, err)
	}
	u, _, err := s.loadUser(ctx, username)
	return u, err
}

// GetMFASecret returns the (plaintext) TOTP secret for a user, or "" if not set.
func (s *Service) GetMFASecret(ctx context.Context, userID int64) (string, error) {
	var secret sql.NullString
	err := s.DB.QueryRowContext(ctx, `SELECT mfa_secret FROM users WHERE id=?`, userID).Scan(&secret)
	if err != nil {
		return "", err
	}
	return secret.String, nil
}

// SetMFASecret stores a TOTP secret but leaves mfa_enabled = 0 until verified.
func (s *Service) SetMFASecret(ctx context.Context, userID int64, secret string) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE users SET mfa_secret=?, mfa_enabled=0, mfa_exempt=0 WHERE id=?`, secret, userID)
	return err
}

// EnableMFA confirms TOTP enrollment and clears any admin exemption.
func (s *Service) EnableMFA(ctx context.Context, userID int64) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE users SET mfa_enabled=1, mfa_exempt=0 WHERE id=?`, userID)
	return err
}

// DisableMFA clears MFA enrollment. When exempt is true the user may skip MFA
// even if the global policy is required (admin override).
func (s *Service) DisableMFA(ctx context.Context, userID int64, exempt bool) error {
	ex := 0
	if exempt {
		ex = 1
	}
	_, err := s.DB.ExecContext(ctx,
		`UPDATE users SET mfa_secret=NULL, mfa_enabled=0, mfa_exempt=? WHERE id=?`, ex, userID)
	return err
}

// ResetMFA clears TOTP enrollment so the user must set up MFA again. It does
// not change the admin exemption flag.
func (s *Service) ResetMFA(ctx context.Context, userID int64) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE users SET mfa_secret=NULL, mfa_enabled=0 WHERE id=?`, userID)
	return err
}

// IssueToken signs a JWT for the given user.
func (s *Service) IssueToken(u *User) (string, error) {
	now := time.Now()
	c := Claims{
		UserID:   u.ID,
		Username: u.Username,
		Role:     u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.JWTIssuer,
			Audience:  []string{s.JWTAudience},
			Subject:   fmt.Sprintf("%d", u.ID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.JWTTTL)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return tok.SignedString(s.JWTSecret)
}

// IssueEnrollmentToken signs a short-lived JWT used only for MFA setup during login.
func (s *Service) IssueEnrollmentToken(u *User) (string, error) {
	now := time.Now()
	c := Claims{
		UserID:   u.ID,
		Username: u.Username,
		Role:     u.Role,
		Scope:    "mfa_enroll",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.JWTIssuer,
			Audience:  []string{s.JWTAudience},
			Subject:   fmt.Sprintf("%d", u.ID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return tok.SignedString(s.JWTSecret)
}

// VerifyToken parses a JWT and returns its claims.
func (s *Service) VerifyToken(raw string) (*Claims, error) {
	c := &Claims{}
	t, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("bad alg: %s", t.Method.Alg())
		}
		return s.JWTSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if !t.Valid {
		return nil, errors.New("invalid token")
	}
	return c, nil
}

// ListUsers returns all users (without password hashes).
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id, username, COALESCE(email,''), role, disabled,
		       COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(mfa_exempt,0),
		       COALESCE(last_login,0), COALESCE(role_locked,0)
		FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var disabled, mfa, exempt, roleLocked int
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &disabled,
			&u.Source, &mfa, &exempt, &u.LastLogin, &roleLocked); err != nil {
			return nil, err
		}
		u.Disabled = disabled != 0
		u.MFAEnabled = mfa != 0
		u.MFAExempt = exempt != 0
		u.RoleLocked = roleLocked != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUserInput is the mutable user fields from the admin UI.
type UpdateUserInput struct {
	Email     string `json:"email"`
	Role      string `json:"role"`
	Disabled  *bool  `json:"disabled"`
	MFAExempt *bool  `json:"mfa_exempt"`
	Password  string `json:"password,omitempty"`
}

// UpdateUser applies admin changes to a user record.
func (s *Service) UpdateUser(ctx context.Context, id int64, in UpdateUserInput) error {
	u, err := s.getUserByID(ctx, id)
	if err != nil {
		return err
	}
	if in.Email != "" {
		u.Email = in.Email
	}
	roleLocked := 0
	if u.RoleLocked {
		roleLocked = 1
	}
	if in.Role != "" && in.Role != u.Role {
		u.Role = in.Role
		roleLocked = 1
	}
	disabled := 0
	if u.Disabled {
		disabled = 1
	}
	if in.Disabled != nil {
		if *in.Disabled {
			disabled = 1
		} else {
			disabled = 0
		}
	}
	exempt := 0
	if u.MFAExempt {
		exempt = 1
	}
	if in.MFAExempt != nil {
		if *in.MFAExempt {
			exempt = 1
		} else {
			exempt = 0
		}
	}
	// LDAP/SAML users authenticate via IdP — local password is not used.
	if in.Password != "" && u.Source != "local" {
		in.Password = ""
	}
	if in.Password != "" {
		pwHash, err := cryptox.PasswordHash(in.Password)
		if err != nil {
			return fmt.Errorf("auth: hash: %w", err)
		}
		_, err = s.DB.ExecContext(ctx,
			`UPDATE users SET email=?, role=?, disabled=?, role_locked=?, mfa_exempt=?, password_hash=? WHERE id=?`,
			u.Email, u.Role, disabled, roleLocked, exempt, pwHash, id)
		return err
	}
	_, err = s.DB.ExecContext(ctx,
		`UPDATE users SET email=?, role=?, disabled=?, role_locked=?, mfa_exempt=? WHERE id=?`,
		u.Email, u.Role, disabled, roleLocked, exempt, id)
	return err
}

func (s *Service) GetUserByID(ctx context.Context, id int64) (*User, error) {
	return s.getUserByID(ctx, id)
}

func (s *Service) getUserByID(ctx context.Context, id int64) (*User, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT id, username, COALESCE(email,''), role, disabled,
		        COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(mfa_exempt,0),
		        COALESCE(last_login,0), COALESCE(role_locked,0)
		 FROM users WHERE id = ?`, id)
	var u User
	var disabled, mfa, exempt, roleLocked int
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &disabled,
		&u.Source, &mfa, &exempt, &u.LastLogin, &roleLocked); err != nil {
		return nil, errors.New("user not found")
	}
	u.Disabled = disabled != 0
	u.MFAEnabled = mfa != 0
	u.MFAExempt = exempt != 0
	u.RoleLocked = roleLocked != 0
	return &u, nil
}

// DeleteUser removes a user and related membership/checkout rows. Sessions and
// audit history are kept with the orphaned user_id for forensics.
func (s *Service) DeleteUser(ctx context.Context, id, actorID int64) (string, error) {
	if id <= 0 {
		return "", errors.New("invalid user id")
	}
	if id == actorID {
		return "", errors.New("cannot delete your own account")
	}
	u, err := s.getUserByID(ctx, id)
	if err != nil {
		return "", err
	}
	if u.Role == "admin" && !u.Disabled {
		var others int
		if err := s.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE role='admin' AND disabled=0 AND id != ?`, id).
			Scan(&others); err != nil {
			return "", err
		}
		if others == 0 {
			return "", errors.New("cannot delete the last active admin")
		}
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	cleanup := []struct {
		q string
		a any
	}{
		{`DELETE FROM approval_decisions WHERE approver_id = ?`, id},
		{`DELETE FROM approval_decisions WHERE request_id IN (SELECT id FROM access_requests WHERE user_id = ?)`, id},
		{`DELETE FROM access_requests WHERE user_id = ?`, id},
		{`UPDATE access_requests SET approver_id = NULL WHERE approver_id = ?`, id},
		{`DELETE FROM credential_checkouts WHERE user_id = ?`, id},
		{`DELETE FROM session_terminations WHERE requested_by = ?`, id},
		{`DELETE FROM saml_sessions WHERE user_id = ?`, id},
		{`DELETE FROM safe_members WHERE principal_type='user' AND principal_id = ?`, id},
		{`UPDATE threat_alerts SET user_id = NULL WHERE user_id = ?`, id},
	}
	for _, step := range cleanup {
		if _, err := tx.ExecContext(ctx, step.q, step.a); err != nil {
			return "", fmt.Errorf("auth: delete user cleanup: %w", err)
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return "", fmt.Errorf("auth: delete user: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return "", errors.New("user not found")
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return u.Username, nil
}
