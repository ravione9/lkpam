package ldap

import (
	"context"
	"fmt"
	"strings"

	"github.com/example/pam-platform/internal/auth"
	"github.com/example/pam-platform/internal/groups"
)

// SyncSelection lists AD users and groups chosen for import into PAM.
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

// Run imports selected AD groups, explicit users, and members of selected groups.
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

	syncedUsers := make(map[string]struct{})
	for _, dn := range sel.UserDNs {
		if err := s.syncUserDN(ctx, res, dn, defaultRole, syncedUsers); err != nil {
			res.Errors = append(res.Errors, err.Error())
		}
	}

	for _, gdn := range sel.GroupDNs {
		gdn = strings.TrimSpace(gdn)
		if gdn == "" {
			continue
		}
		members, err := s.Client.FetchGroupMemberDNs(gdn)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("group members %s: %v", gdn, err))
			continue
		}
		for _, udn := range members {
			if err := s.syncUserDN(ctx, res, udn, defaultRole, syncedUsers); err != nil {
				res.Errors = append(res.Errors, err.Error())
			}
		}
	}
	return res, nil
}

func (s *SyncService) syncUserDN(ctx context.Context, res *SyncResult, dn, defaultRole string, seen map[string]struct{}) error {
	dn = strings.TrimSpace(dn)
	if dn == "" {
		return nil
	}
	key := strings.ToLower(dn)
	if _, ok := seen[key]; ok {
		return nil
	}
	seen[key] = struct{}{}

	lu, err := s.Client.FetchUser(dn)
	if err != nil {
		return fmt.Errorf("user %s: %w", dn, err)
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
	if existing, err := s.Auth.FindByUsername(ctx, lu.Username); err == nil && existing.Source == "local" {
		return fmt.Errorf("user %s: skipped — local portal account already exists (rename AD account or remove local user first)", lu.Username)
	}
	u, err := s.Auth.UpsertLDAPUser(ctx, lu.Username, lu.Email, role, lu.DN)
	if err != nil {
		return fmt.Errorf("user %s: %w", lu.Username, err)
	}
	if len(matchedGroupIDs) > 0 {
		_ = s.Groups.ReplaceMemberships(ctx, u.ID, matchedGroupIDs)
	}
	res.UsersSynced++
	return nil
}
