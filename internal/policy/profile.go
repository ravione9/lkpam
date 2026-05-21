package policy

import (
	"context"

	"github.com/example/pam-platform/internal/approval"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/inventory"
)

// ProfileTarget is one machine evaluated against the user's effective policies.
type ProfileTarget struct {
	inventory.Target
	Allowed           bool     `json:"allowed"`
	RequireApproval   bool     `json:"require_approval"`
	PolicyRole        string   `json:"policy_role,omitempty"`
	MatrixRule        string   `json:"matrix_rule,omitempty"`
	ApproverGroups    []string `json:"approver_groups,omitempty"`
	RequiredApprovals int      `json:"required_approvals"`
}

// ProfileMatrixRule is an approval-matrix row that applies to this user as requester.
type ProfileMatrixRule struct {
	ID                int64    `json:"id"`
	Name              string   `json:"name"`
	TargetKind        string   `json:"target_kind"`
	TierMin           int      `json:"tier_min"`
	TierMax           int      `json:"tier_max"`
	RequiredApprovals int      `json:"required_approvals"`
	RequesterGroups   []string `json:"requester_groups"`
	ApproverGroups    []string `json:"approver_groups"`
}

// AccessProfile is the end-to-end access picture for one user.
type AccessProfile struct {
	PrimaryRole string              `json:"primary_role"`
	Roles       []string            `json:"roles"`
	Groups      []groups.Group      `json:"groups"`
	Policies    []Rule              `json:"policies"`
	Targets     []ProfileTarget     `json:"targets"`
	MatrixRules []ProfileMatrixRule `json:"matrix_rules"`
	Hints       []string            `json:"hints"`
}

// ProfileBuilder assembles an access profile from policy, inventory, groups, and matrix.
type ProfileBuilder struct {
	Engine *Engine
	Inv    *inventory.Service
	Groups *groups.Service
	Matrix *approval.MatrixService
}

// Build computes the full access profile for a user.
func (b *ProfileBuilder) Build(ctx context.Context, userID int64, primaryRole string) (*AccessProfile, error) {
	roles, err := b.Groups.EffectiveRoles(ctx, userID, primaryRole)
	if err != nil {
		roles = []string{primaryRole}
	}
	userGroups, err := b.Groups.UserGroups(ctx, userID)
	if err != nil {
		userGroups = nil
	}
	groupIDs, err := b.Groups.UserGroupIDs(ctx, userID)
	if err != nil {
		groupIDs = nil
	}

	allRules, err := b.Engine.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	roleSet := map[string]bool{}
	for _, r := range roles {
		roleSet[r] = true
	}
	var matched []Rule
	for _, p := range allRules {
		if roleSet[p.Role] {
			matched = append(matched, p)
		}
	}

	allGroups, _ := b.Groups.List(ctx)
	nameByID := map[int64]string{}
	for _, g := range allGroups {
		nameByID[g.ID] = g.Name
	}

	var matrixRules []ProfileMatrixRule
	if b.Matrix != nil {
		raw, err := b.Matrix.List(ctx)
		if err == nil {
			for _, mr := range raw {
				if !mr.Enabled {
					continue
				}
				if !requesterMatches(mr.RequesterGroupIDs, groupIDs) {
					continue
				}
				matrixRules = append(matrixRules, ProfileMatrixRule{
					ID:                mr.ID,
					Name:              mr.Name,
					TargetKind:        mr.TargetKind,
					TierMin:           mr.TierMin,
					TierMax:           mr.TierMax,
					RequiredApprovals: mr.RequiredApprovals,
					RequesterGroups:   namesForIDs(mr.RequesterGroupIDs, nameByID),
					ApproverGroups:    namesForIDs(mr.ApproverGroupIDs, nameByID),
				})
			}
		}
	}

	targets, _ := b.Inv.List(ctx)
	var profileTargets []ProfileTarget
	for _, t := range targets {
		dec, err := b.Engine.Decide(ctx, Input{
			UserID:     userID,
			Role:       primaryRole,
			Roles:      roles,
			TargetID:   t.ID,
			TargetKind: t.Kind,
			TargetTier: t.Tier,
			Action:     "connect",
		})
		if err != nil {
			continue
		}
		pt := ProfileTarget{
			Target:          t,
			Allowed:         dec.Allow,
			RequireApproval: dec.RequireApproval,
		}
		if dec.Allow && b.Matrix != nil {
			if rule, _ := b.Matrix.FindRule(ctx, t.Kind, t.Tier, groupIDs); rule != nil {
				pt.MatrixRule = rule.Name
				pt.RequiredApprovals = rule.RequiredApprovals
				pt.ApproverGroups = namesForIDs(rule.ApproverGroupIDs, nameByID)
			} else {
				pt.RequiredApprovals = 1
				if primaryRole == "admin" {
					pt.ApproverGroups = []string{"any admin (not you)"}
				} else {
					pt.ApproverGroups = []string{"any admin"}
				}
			}
		}
		profileTargets = append(profileTargets, pt)
	}

	hints := buildHints(primaryRole, roles, matched, profileTargets, matrixRules)

	return &AccessProfile{
		PrimaryRole: primaryRole,
		Roles:       roles,
		Groups:      userGroups,
		Policies:    matched,
		Targets:     profileTargets,
		MatrixRules: matrixRules,
		Hints:       hints,
	}, nil
}

func requesterMatches(ruleGroupIDs, userGroupIDs []int64) bool {
	if len(ruleGroupIDs) == 0 {
		return true
	}
	seen := map[int64]bool{}
	for _, id := range userGroupIDs {
		seen[id] = true
	}
	for _, id := range ruleGroupIDs {
		if seen[id] {
			return true
		}
	}
	return false
}

func namesForIDs(ids []int64, nameByID map[int64]string) []string {
	if len(ids) == 0 {
		return nil
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if n, ok := nameByID[id]; ok {
			out = append(out, n)
		}
	}
	return out
}

func buildHints(primaryRole string, roles []string, policies []Rule, targets []ProfileTarget, matrix []ProfileMatrixRule) []string {
	var hints []string
	if len(policies) == 0 {
		hints = append(hints, "No access policies match your role(s). Ask an admin to create a policy for role \""+primaryRole+"\" or add you to a group that grants a role like netops or sysadmin.")
	}
	allowed := 0
	for _, t := range targets {
		if t.Allowed {
			allowed++
		}
	}
	if len(policies) > 0 && allowed == 0 {
		hints = append(hints, "Policies exist for your role but no registered machines match (check target tier vs policy tier ceiling). Lower a machine's tier or ask an admin to widen your policy.")
	}
	if allowed > 0 && len(matrix) == 0 {
		hints = append(hints, "No approval-matrix rules target your groups — any admin (other than you) can approve your requests.")
	}
	return hints
}
