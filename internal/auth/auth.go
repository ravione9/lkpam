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
	jwt.RegisteredClaims
}

// CreateUser inserts a new user with an Argon2id password hash.
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
		       COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(last_login,0),
		       COALESCE(role_locked,0)
		FROM users WHERE lower(username)=lower(?)`, loginID)
	if u, err := scanUserRow(row); err == nil {
		return u, nil
	} else if err != sql.ErrNoRows {
		return nil, err
	}
	// Prefer active directory-backed accounts when email is reused.
	row = s.DB.QueryRowContext(ctx, `
		SELECT id, username, COALESCE(email,''), role, disabled,
		       COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(last_login,0),
		       COALESCE(role_locked,0)
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
		       COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(last_login,0),
		       COALESCE(role_locked,0)
		FROM users WHERE lower(email)=lower(?)
		ORDER BY id LIMIT 1`, loginID)
	return scanUserRow(row)
}

func scanUserRow(row *sql.Row) (*User, error) {
	var u User
	var disabled, mfa, roleLocked int
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &disabled,
		&u.Source, &mfa, &u.LastLogin, &roleLocked); err != nil {
		return nil, err
	}
	u.Disabled = disabled != 0
	u.MFAEnabled = mfa != 0
	u.RoleLocked = roleLocked != 0
	return &u, nil
}

func (s *Service) loadUser(ctx context.Context, username string) (*User, string, error) {
	row := s.DB.QueryRowContext(ctx, `
		SELECT id, username, COALESCE(email,''), password_hash, role, disabled,
		       COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(last_login,0),
		       COALESCE(role_locked,0)
		FROM users WHERE username = ?`, username)
	var u User
	var pwHash string
	var disabled, mfa, roleLocked int
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &pwHash, &u.Role, &disabled,
		&u.Source, &mfa, &u.LastLogin, &roleLocked); err != nil {
		return nil, "", err
	}
	u.Disabled = disabled != 0
	u.MFAEnabled = mfa != 0
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
		  email=excluded.email,
		  role=CASE WHEN COALESCE(users.role_locked,0)=1 THEN users.role ELSE excluded.role END,
		  source=excluded.source,
		  external_dn=excluded.external_dn,
		  password_hash=''`,
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
		`UPDATE users SET mfa_secret=?, mfa_enabled=0 WHERE id=?`, secret, userID)
	return err
}

// EnableMFA confirms TOTP enrollment.
func (s *Service) EnableMFA(ctx context.Context, userID int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE users SET mfa_enabled=1 WHERE id=?`, userID)
	return err
}

// DisableMFA clears the TOTP secret and disables MFA.
func (s *Service) DisableMFA(ctx context.Context, userID int64) error {
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
		       COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(last_login,0),
		       COALESCE(role_locked,0)
		FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var disabled, mfa, roleLocked int
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &disabled,
			&u.Source, &mfa, &u.LastLogin, &roleLocked); err != nil {
			return nil, err
		}
		u.Disabled = disabled != 0
		u.MFAEnabled = mfa != 0
		u.RoleLocked = roleLocked != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpdateUserInput is the mutable user fields from the admin UI.
type UpdateUserInput struct {
	Email    string `json:"email"`
	Role     string `json:"role"`
	Disabled *bool  `json:"disabled"`
	Password string `json:"password,omitempty"`
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
			`UPDATE users SET email=?, role=?, disabled=?, role_locked=?, password_hash=? WHERE id=?`,
			u.Email, u.Role, disabled, roleLocked, pwHash, id)
		return err
	}
	_, err = s.DB.ExecContext(ctx,
		`UPDATE users SET email=?, role=?, disabled=?, role_locked=? WHERE id=?`,
		u.Email, u.Role, disabled, roleLocked, id)
	return err
}

func (s *Service) getUserByID(ctx context.Context, id int64) (*User, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT id, username, COALESCE(email,''), role, disabled,
		        COALESCE(source,'local'), COALESCE(mfa_enabled,0), COALESCE(last_login,0),
		        COALESCE(role_locked,0)
		 FROM users WHERE id = ?`, id)
	var u User
	var disabled, mfa, roleLocked int
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &disabled,
		&u.Source, &mfa, &u.LastLogin, &roleLocked); err != nil {
		return nil, errors.New("user not found")
	}
	u.Disabled = disabled != 0
	u.MFAEnabled = mfa != 0
	u.RoleLocked = roleLocked != 0
	return &u, nil
}
