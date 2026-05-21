package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// DirectoryEntry is a user or group row from AD/LDAP browse.
type DirectoryEntry struct {
	DN          string `json:"dn"`
	Name        string `json:"name"`
	Email       string `json:"email,omitempty"`
	Description string `json:"description,omitempty"`
	Type        string `json:"type"` // user | group
}

// SearchUsers finds AD/LDAP users matching q under BaseDN.
func (c *Client) SearchUsers(q string, limit int) ([]DirectoryEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	conn, err := c.dial(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := c.bindService(conn); err != nil {
		return nil, err
	}
	usernameAttr := c.Cfg.UsernameAttr
	if usernameAttr == "" {
		usernameAttr = "sAMAccountName"
	}
	emailAttr := c.Cfg.EmailAttr
	if emailAttr == "" {
		emailAttr = "mail"
	}
	filter := "(&(objectCategory=person)(objectClass=user))"
	if strings.TrimSpace(q) != "" {
		esc := ldap.EscapeFilter(q)
		filter = fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(|(cn=*%[1]s*)(%[2]s=*%[1]s*)(%[3]s=*%[1]s*)))",
			esc, usernameAttr, emailAttr)
	}
	req := ldap.NewSearchRequest(
		c.Cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, limit, 15, false,
		filter,
		[]string{"dn", "cn", usernameAttr, emailAttr, "displayName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap: search users: %w", err)
	}
	out := make([]DirectoryEntry, 0, len(res.Entries))
	for _, e := range res.Entries {
		name := e.GetAttributeValue(usernameAttr)
		if name == "" {
			name = e.GetAttributeValue("cn")
		}
		out = append(out, DirectoryEntry{
			DN:    e.DN,
			Name:  name,
			Email: e.GetAttributeValue(emailAttr),
			Type:  "user",
		})
	}
	return out, nil
}

// SearchGroups finds AD/LDAP groups matching q under BaseDN.
func (c *Client) SearchGroups(q string, limit int) ([]DirectoryEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	conn, err := c.dial(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := c.bindService(conn); err != nil {
		return nil, err
	}
	filter := "(objectClass=group)"
	if strings.TrimSpace(q) != "" {
		esc := ldap.EscapeFilter(q)
		filter = fmt.Sprintf("(&(objectClass=group)(|(cn=*%s*)(sAMAccountName=*%s*)))", esc, esc)
	}
	req := ldap.NewSearchRequest(
		c.Cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, limit, 15, false,
		filter,
		[]string{"dn", "cn", "description", "sAMAccountName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap: search groups: %w", err)
	}
	out := make([]DirectoryEntry, 0, len(res.Entries))
	for _, e := range res.Entries {
		name := e.GetAttributeValue("cn")
		if name == "" {
			name = e.GetAttributeValue("sAMAccountName")
		}
		out = append(out, DirectoryEntry{
			DN:          e.DN,
			Name:        name,
			Description: e.GetAttributeValue("description"),
			Type:        "group",
		})
	}
	return out, nil
}

// FetchUser loads one user entry by DN.
func (c *Client) FetchUser(dn string) (*User, error) {
	conn, err := c.dial(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := c.bindService(conn); err != nil {
		return nil, err
	}
	usernameAttr := c.Cfg.UsernameAttr
	if usernameAttr == "" {
		usernameAttr = "sAMAccountName"
	}
	emailAttr := c.Cfg.EmailAttr
	if emailAttr == "" {
		emailAttr = "mail"
	}
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 8, false,
		"(objectClass=*)",
		[]string{"dn", usernameAttr, emailAttr},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("ldap: user not found")
	}
	e := res.Entries[0]
	u := &User{
		DN:       e.DN,
		Username: e.GetAttributeValue(usernameAttr),
		Email:    e.GetAttributeValue(emailAttr),
	}
	groups, err := c.userGroups(conn, u.DN)
	if err != nil {
		return nil, err
	}
	u.Groups = groups
	return u, nil
}

// FetchGroup loads one group entry by DN.
func (c *Client) FetchGroup(dn string) (*DirectoryEntry, error) {
	conn, err := c.dial(context.Background())
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := c.bindService(conn); err != nil {
		return nil, err
	}
	req := ldap.NewSearchRequest(
		dn,
		ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 8, false,
		"(objectClass=*)",
		[]string{"dn", "cn", "description", "sAMAccountName"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("ldap: group not found")
	}
	e := res.Entries[0]
	name := e.GetAttributeValue("cn")
	if name == "" {
		name = e.GetAttributeValue("sAMAccountName")
	}
	return &DirectoryEntry{
		DN:          e.DN,
		Name:        name,
		Description: e.GetAttributeValue("description"),
		Type:        "group",
	}, nil
}
