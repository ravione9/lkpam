// Package ldap is the AD/LDAP integration layer. It handles:
//   - bind authentication of end users (login flow)
//   - user search (to resolve username → DN before binding)
//   - group membership lookup
//
// Configuration is persisted in the settings store + the vault (for the bind
// password). The package treats Active Directory as a special case of LDAP:
// the same `bindUser → search → bind` flow works against AD when configured
// with sAMAccountName as the username attribute.
package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config is the persisted LDAP configuration.
type Config struct {
	Enabled         bool   `json:"enabled"`
	URL             string `json:"url"`               // ldap://host:389 or ldaps://host:636
	StartTLS        bool   `json:"start_tls"`         // upgrade plain ldap:// to TLS
	SkipTLSVerify   bool   `json:"skip_tls_verify"`   // dev only — do not enable in production
	BindDN          string `json:"bind_dn"`           // service account, e.g. CN=pam-svc,OU=Service,DC=corp,DC=local
	BindPasswordSet bool   `json:"bind_password_set"` // read-only flag; password lives in the vault
	BaseDN          string `json:"base_dn"`           // search root, e.g. DC=corp,DC=local
	UserFilter      string `json:"user_filter"`       // %s = username, e.g. (sAMAccountName=%s)
	GroupFilter     string `json:"group_filter"`      // %s = userDN, e.g. (&(objectClass=group)(member=%s))
	UsernameAttr    string `json:"username_attr"`     // attribute to read as the local username, default sAMAccountName
	EmailAttr       string `json:"email_attr"`        // default mail
	DefaultRole     string `json:"default_role"`      // role assigned to LDAP users not matched by any group
}

// DefaultConfig returns sensible AD defaults.
func DefaultConfig() Config {
	return Config{
		UserFilter:   "(sAMAccountName=%s)",
		GroupFilter:  "(&(objectClass=group)(member=%s))",
		UsernameAttr: "sAMAccountName",
		EmailAttr:    "mail",
		DefaultRole:  "user",
	}
}

// User is the authenticated LDAP identity returned to the auth service.
type User struct {
	DN       string
	Username string
	Email    string
	Groups   []string // DNs of groups the user is a member of
}

// Client is a stateless wrapper around go-ldap that opens a new connection
// per operation. LDAP servers tolerate this; pooling can be added later.
type Client struct {
	Cfg      Config
	Password string // bind password loaded from the vault
}

// Authenticate binds as the service account, looks up the user, then binds as
// the user with the supplied password. Returns the user record on success.
func (c *Client) Authenticate(ctx context.Context, username, password string) (*User, error) {
	if password == "" {
		return nil, errors.New("ldap: empty password rejected")
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := c.bindService(conn); err != nil {
		return nil, fmt.Errorf("ldap: service bind: %w", err)
	}

	u, err := c.findUser(conn, username)
	if err != nil {
		return nil, err
	}

	if err := conn.Bind(u.DN, password); err != nil {
		return nil, fmt.Errorf("ldap: user bind: %w", err)
	}

	groups, err := c.userGroups(conn, u.DN)
	if err != nil {
		return nil, fmt.Errorf("ldap: list groups: %w", err)
	}
	u.Groups = groups
	return u, nil
}

// TestConnection does a service bind and reports success/failure. Used by the
// settings UI to verify configuration before saving.
func (c *Client) TestConnection(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	return c.bindService(conn)
}

func (c *Client) dial(ctx context.Context) (*ldap.Conn, error) {
	if c.Cfg.URL == "" {
		return nil, errors.New("ldap: URL not configured")
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: c.Cfg.SkipTLSVerify}
	opts := []ldap.DialOpt{ldap.DialWithDialer(&net.Dialer{Timeout: 8 * time.Second})}
	if strings.HasPrefix(strings.ToLower(c.Cfg.URL), "ldaps://") {
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}
	conn, err := ldap.DialURL(c.Cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("ldap: dial: %w", err)
	}
	if c.Cfg.StartTLS && strings.HasPrefix(strings.ToLower(c.Cfg.URL), "ldap://") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap: starttls: %w", err)
		}
	}
	conn.SetTimeout(8 * time.Second)
	_ = ctx // reserved for future per-call cancellation
	return conn, nil
}

func (c *Client) bindService(conn *ldap.Conn) error {
	if c.Cfg.BindDN == "" {
		return nil // anonymous bind
	}
	return conn.Bind(c.Cfg.BindDN, c.Password)
}

func (c *Client) findUser(conn *ldap.Conn, login string) (*User, error) {
	login = strings.TrimSpace(login)
	filter := fmt.Sprintf(c.Cfg.UserFilter, ldap.EscapeFilter(login))
	if u, err := c.searchOneUser(conn, filter); err == nil {
		return u, nil
	}
	// Allow sign-in with corporate email / UPN when users type mail instead of sAMAccountName.
	if strings.Contains(login, "@") {
		for _, attr := range []string{"mail", "userPrincipalName"} {
			f := fmt.Sprintf("(%s=%s)", attr, ldap.EscapeFilter(login))
			if u, err := c.searchOneUser(conn, f); err == nil {
				return u, nil
			}
		}
	}
	return nil, errors.New("ldap: user not found")
}

func (c *Client) searchOneUser(conn *ldap.Conn, filter string) (*User, error) {
	usernameAttr := c.Cfg.UsernameAttr
	if usernameAttr == "" {
		usernameAttr = "sAMAccountName"
	}
	emailAttr := c.Cfg.EmailAttr
	if emailAttr == "" {
		emailAttr = "mail"
	}
	req := ldap.NewSearchRequest(
		c.Cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 8, false,
		filter,
		[]string{"dn", usernameAttr, emailAttr},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap: search: %w", err)
	}
	if len(res.Entries) == 0 {
		return nil, errors.New("ldap: user not found")
	}
	if len(res.Entries) > 1 {
		return nil, errors.New("ldap: ambiguous username")
	}
	e := res.Entries[0]
	return &User{
		DN:       e.DN,
		Username: e.GetAttributeValue(usernameAttr),
		Email:    e.GetAttributeValue(emailAttr),
	}, nil
}

func (c *Client) userGroups(conn *ldap.Conn, userDN string) ([]string, error) {
	if c.Cfg.GroupFilter == "" {
		return nil, nil
	}
	filter := fmt.Sprintf(c.Cfg.GroupFilter, ldap.EscapeFilter(userDN))
	req := ldap.NewSearchRequest(
		c.Cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 8, false,
		filter,
		[]string{"dn", "cn"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, e.DN)
	}
	return out, nil
}
