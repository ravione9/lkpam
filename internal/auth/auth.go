// Package auth handles user authentication, JWT issuance/verification, and
// the (stub) MFA layer. In production, MFA hands off to the IdP — here we
// implement a simple TOTP check so the flow is real.
package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/example/pam-platform/internal/cryptox"
	"github.com/example/pam-platform/internal/db"

	"github.com/golang-jwt/jwt/v5"
)

// User is the canonical user record.
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Role     string `json:"role"`
	Disabled bool   `json:"disabled"`
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

// Authenticate verifies username/password and returns the User.
func (s *Service) Authenticate(ctx context.Context, username, password string) (*User, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT id, username, email, password_hash, role, disabled
		 FROM users WHERE username = ?`, username)
	var u User
	var pwHash string
	var disabled int
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &pwHash, &u.Role, &disabled); err != nil {
		// don't leak existence — generic error
		return nil, errors.New("invalid credentials")
	}
	u.Disabled = disabled != 0
	if u.Disabled {
		return nil, errors.New("account disabled")
	}
	if !cryptox.VerifyPassword(password, pwHash) {
		return nil, errors.New("invalid credentials")
	}
	return &u, nil
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
		SELECT id, username, email, role, disabled FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var disabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &disabled); err != nil {
			return nil, err
		}
		u.Disabled = disabled != 0
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
	if in.Role != "" {
		u.Role = in.Role
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
	pwHash := ""
	if in.Password != "" {
		pwHash, err = cryptox.PasswordHash(in.Password)
		if err != nil {
			return fmt.Errorf("auth: hash: %w", err)
		}
		_, err = s.DB.ExecContext(ctx,
			`UPDATE users SET email=?, role=?, disabled=?, password_hash=? WHERE id=?`,
			u.Email, u.Role, disabled, pwHash, id)
		return err
	}
	_, err = s.DB.ExecContext(ctx,
		`UPDATE users SET email=?, role=?, disabled=? WHERE id=?`,
		u.Email, u.Role, disabled, id)
	return err
}

func (s *Service) getUserByID(ctx context.Context, id int64) (*User, error) {
	row := s.DB.QueryRowContext(ctx,
		`SELECT id, username, email, role, disabled FROM users WHERE id = ?`, id)
	var u User
	var disabled int
	if err := row.Scan(&u.ID, &u.Username, &u.Email, &u.Role, &disabled); err != nil {
		return nil, errors.New("user not found")
	}
	u.Disabled = disabled != 0
	return &u, nil
}
