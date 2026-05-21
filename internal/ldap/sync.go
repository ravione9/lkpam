package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/example/pam-platform/internal/auth"
	"github.com/example/pam-platform/internal/groups"
)

// SyncSelection lists AD users and groups chosen for import into PAM.
// When UserDNs is non-empty, only those users may log in via LDAP and are synced.
type SyncSelection struct {
	UserDNs  []string `json:"user_dns"`
	GroupDNs []string `json:"group_dns"`
}

// SyncResult summarizes one sync run.
type SyncResult struct {
	GroupsSynced int      `json:"groups_synced"`
	UsersSynced  int      `json:"users_synced"`
	Errors       []string `json:"errors,omitempty"`
}

// SyncService imports selected AD users and groups into PAM.
type SyncService struct {
	Client *Client
	Auth   *auth.Service
	Groups *groups.Service
	Cfg    Config
}

// Run syncs only the DNs in sel — no other AD objects are imported.
func (s *SyncService) Run(ctx context.Context, sel SyncSelection) (*SyncResult, error) {
	if s.Client == nil {
		return nil, fmt.Errorf("ldap client not configured")
	}
	res := &SyncResult{}
	defaultRole := s.Cfg.DefaultRole
	if defaultRole == "" {
		defaultRole = "user"
	}

	// Groups first so user membership can resolve.
	for _, dn := range sel.GroupDNs {
		dn = strings.TrimSpace(dn)
		if dn == "" {
			continue
		}
		g, err := s.Client.FetchGroup(dn)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("group %s: %v", dn, err))
			continue
		}
		role := defaultRole
		if _, err := s.Groups.UpsertLDAP(ctx, g.Name, g.Description, role, g.DN); err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("group %s: %v", g.Name, err))
			continue
		}
		res.GroupsSynced++
	}

	for _, dn := range sel.UserDNs {
		dn = strings.TrimSpace(dn)
		if dn == "" {
			continue
		}
		lu, err := s.Client.FetchUser(dn)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("user %s: %v", dn, err))
			continue
		}
		role := defaultRole
		var matchedGroupIDs []int64
		for _, gdn := range lu.Groups {
			g, _ := s.Groups.FindByLDAPDN(ctx, gdn)
			if g != nil {
				matchedGroupIDs = append(matchedGroupIDs, g.ID)
				if g.Role == "admin" {
					role = "admin"
				} else if role != "admin" {
					role = g.Role
				}
			}
		}
		u, err := s.Auth.UpsertLDAPUser(ctx, lu.Username, lu.Email, role, lu.DN)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("user %s: %v", lu.Username, err))
			continue
		}
		if len(matchedGroupIDs) > 0 {
			_ = s.Groups.ReplaceMemberships(ctx, u.ID, matchedGroupIDs)
		}
		res.UsersSynced++
	}
	return res, nil
}

// AllowedUser returns true if dn may authenticate when a sync whitelist is configured.
func AllowedUser(sel SyncSelection, dn string) bool {
	if len(sel.UserDNs) == 0 {
		return true
	}
	dn = strings.ToLower(strings.TrimSpace(dn))
	for _, allowed := range sel.UserDNs {
		if strings.ToLower(strings.TrimSpace(allowed)) == dn {
			return true
		}
	}
	return false
}
