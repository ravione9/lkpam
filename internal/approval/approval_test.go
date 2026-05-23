package approval

import (
	"context"
	"testing"

	"github.com/example/pam-platform/internal/db"
)

func setupTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	now := db.Now()
	if _, err := d.Exec(`
		INSERT INTO users(id,username,password_hash,role,created_at) VALUES
		  (1,'alice','','user',?),
		  (2,'admin','','admin',?),
		  (3,'sec1','','admin',?),
		  (4,'sec2','','admin',?)`, now, now, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`
		INSERT INTO targets(id,name,kind,host,port,tier) VALUES
		  (1,'linux01','linux','127.0.0.1',22,2),
		  (2,'core-sw','cisco','10.0.0.1',22,0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`
		INSERT INTO groups(id,name,role,source,created_at) VALUES
		  (10,'Security',  'admin','local',?),
		  (20,'NetSec',    'admin','local',?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`
		INSERT INTO user_groups(user_id,group_id,added_at) VALUES
		  (3,10,?),
		  (4,10,?)`, now, now); err != nil {
		t.Fatal(err)
	}
	return d
}

type fakeGroups struct{ d *db.DB }

func (f *fakeGroups) UserGroupIDs(ctx context.Context, uid int64) ([]int64, error) {
	rows, err := f.d.QueryContext(ctx, `SELECT group_id FROM user_groups WHERE user_id=?`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func TestSelfApprovalBlocked(t *testing.T) {
	d := setupTestDB(t)
	svc := &Service{DB: d, Matrix: &MatrixService{DB: d}, GroupMembers: &fakeGroups{d}}

	ctx := context.Background()
	id, err := svc.Create(ctx, 1, 1, "need access", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Decide(ctx, id, 1, "user", true, ""); err != ErrSelfApproval {
		t.Fatalf("expected ErrSelfApproval, got %v", err)
	}
}

func TestSingleAdminApprovalNoMatrix(t *testing.T) {
	d := setupTestDB(t)
	svc := &Service{DB: d, Matrix: &MatrixService{DB: d}, GroupMembers: &fakeGroups{d}}
	ctx := context.Background()

	id, _ := svc.Create(ctx, 1, 1, "need access", 0, false)
	if _, err := svc.Decide(ctx, id, 2, "user", true, ""); err != ErrNotApprover {
		t.Fatalf("expected ErrNotApprover for non-admin, got %v", err)
	}
	res, err := svc.Decide(ctx, id, 2, "admin", true, "ok")
	if err != nil {
		t.Fatalf("admin approve: %v", err)
	}
	if res.Status != "approved" {
		t.Fatalf("expected approved, got %s", res.Status)
	}
}

func TestMatrixTwoApprovalsRequired(t *testing.T) {
	d := setupTestDB(t)
	matrix := &MatrixService{DB: d}
	ctx := context.Background()
	if _, err := matrix.Create(ctx, MatrixRule{
		Name: "Tier-0 critical", TargetKind: "*", TierMin: 0, TierMax: 0,
		RequiredApprovals: 2, ApproverGroupIDs: []int64{10}, Priority: 10, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	svc := &Service{DB: d, Matrix: matrix, GroupMembers: &fakeGroups{d}}

	id, _ := svc.Create(ctx, 1, 2, "tier0 access", 0, false)
	// admin (uid 2) is NOT in group 10 -> rejected.
	if _, err := svc.Decide(ctx, id, 2, "admin", true, ""); err != ErrNotApprover {
		t.Fatalf("expected ErrNotApprover for non-group admin, got %v", err)
	}
	// sec1 approves -> still pending (need 2).
	res, err := svc.Decide(ctx, id, 3, "admin", true, "lgtm")
	if err != nil {
		t.Fatalf("sec1 approve: %v", err)
	}
	if res.Status != "pending" || res.ApprovalsHave != 1 || res.ApprovalsNeed != 2 {
		t.Fatalf("unexpected result %+v", res)
	}
	// sec1 cannot vote twice.
	if _, err := svc.Decide(ctx, id, 3, "admin", true, ""); err != ErrAlreadyDecided {
		t.Fatalf("expected ErrAlreadyDecided, got %v", err)
	}
	// sec2 approves -> approved.
	res, err = svc.Decide(ctx, id, 4, "admin", true, "")
	if err != nil {
		t.Fatalf("sec2 approve: %v", err)
	}
	if res.Status != "approved" {
		t.Fatalf("expected approved after 2 approvals, got %s", res.Status)
	}
}

func TestMatrixRequesterGroupRouting(t *testing.T) {
	d := setupTestDB(t)
	matrix := &MatrixService{DB: d}
	ctx := context.Background()
	now := db.Now()
	// NetSec group (id 20) — requesters route to Security approvers only.
	if _, err := d.Exec(`INSERT INTO user_groups(user_id, group_id, added_at) VALUES (1, 20, ?)`, now); err != nil {
		t.Fatal(err)
	}
	// Rule: NetSec requesters on tier 0 → Security approvers, 1 approval.
	if _, err := matrix.Create(ctx, MatrixRule{
		Name: "NetSec→Security", TargetKind: "*", TierMin: 0, TierMax: 0,
		RequiredApprovals: 1, RequesterGroupIDs: []int64{20},
		ApproverGroupIDs: []int64{10}, Priority: 5, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	// Catch-all: any requester → any admin group not needed, approver group 10 only for sec.
	svc := &Service{DB: d, Matrix: matrix, GroupMembers: &fakeGroups{d}}

	id, _ := svc.Create(ctx, 1, 2, "tier0 from netsec user", 0, false)
	// admin uid 2 is not in Security group 10.
	if _, err := svc.Decide(ctx, id, 2, "admin", true, ""); err != ErrNotApprover {
		t.Fatalf("expected ErrNotApprover for non-security admin, got %v", err)
	}
	res, err := svc.Decide(ctx, id, 3, "admin", true, "ok")
	if err != nil {
		t.Fatalf("security approver: %v", err)
	}
	if res.Status != "approved" {
		t.Fatalf("expected approved, got %s", res.Status)
	}
}

func TestMatrixDenialFinalizes(t *testing.T) {
	d := setupTestDB(t)
	matrix := &MatrixService{DB: d}
	ctx := context.Background()
	_, _ = matrix.Create(ctx, MatrixRule{
		Name: "Tier-0", TargetKind: "*", TierMin: 0, TierMax: 0,
		RequiredApprovals: 2, ApproverGroupIDs: []int64{10}, Enabled: true,
	})
	svc := &Service{DB: d, Matrix: matrix, GroupMembers: &fakeGroups{d}}

	id, _ := svc.Create(ctx, 1, 2, "tier0", 0, false)
	res, err := svc.Decide(ctx, id, 3, "admin", false, "looks risky")
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	if res.Status != "denied" {
		t.Fatalf("expected denied, got %s", res.Status)
	}
}
