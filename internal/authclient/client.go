// Package authclient is the HTTP client that the SSH proxy, TACACS+ server,
// and any other data-plane component uses to delegate authentication to the
// auth-service. This is how AD/LDAP credentials become usable for machine
// access without re-implementing the LDAP flow in every service.
package authclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client talks to auth-service over HTTP.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// New returns a Client with a sensible default timeout.
func New(baseURL string) *Client {
	return &Client{
		BaseURL: baseURL,
		HTTP:    &http.Client{Timeout: 10 * time.Second},
	}
}

// User is the slimmed-down user representation we get back from auth-service.
type User struct {
	ID         int64  `json:"id"`
	Username   string `json:"username"`
	Email      string `json:"email"`
	Role       string `json:"role"`
	Source     string `json:"source"`
	MFAEnabled bool   `json:"mfa_enabled"`
}

// LoginResult captures the three possible outcomes of POST /login:
//   - Token + User on success
//   - MFARequired with UserID when the user needs a second factor
//   - error otherwise
type LoginResult struct {
	Token       string
	User        *User
	Roles       []string
	MFARequired bool
	UserID      int64
}

// Login attempts password (and optionally TOTP) authentication. Returns
// MFARequired=true if the user must supply an OTP — the caller should prompt,
// then call Login again with otp set.
func (c *Client) Login(ctx context.Context, username, password, otp string) (*LoginResult, error) {
	body, _ := json.Marshal(map[string]string{
		"Username": username,
		"Password": password,
		"OTP":      otp,
	})
	req, err := http.NewRequestWithContext(ctx, "POST", c.BaseURL+"/login", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authclient: post /login: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		var out struct {
			Token string   `json:"token"`
			User  User     `json:"user"`
			Roles []string `json:"roles"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("authclient: parse 200: %w", err)
		}
		return &LoginResult{Token: out.Token, User: &out.User, Roles: out.Roles}, nil
	case http.StatusAccepted:
		var out struct {
			MFARequired bool  `json:"mfa_required"`
			UserID      int64 `json:"user_id"`
		}
		_ = json.Unmarshal(raw, &out)
		return &LoginResult{MFARequired: out.MFARequired, UserID: out.UserID}, nil
	default:
		var e struct{ Error string `json:"error"` }
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = string(raw)
		}
		return nil, errors.New(e.Error)
	}
}
