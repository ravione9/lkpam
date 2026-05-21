package approval

import (
	"context"
	"testing"

	"github.com/example/pam-platform/internal/db"
)

func TestDecideBlocksSelfApproval(t *testing.T) {
	d, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()

	now := db.Now()
	if _, err := d.Exec(`INSERT INTO users(id,username,password_hash,role,created_at) VALUES(1,'alice','','user',?), (2,'admin','','admin',?)`, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO targets(id,name,kind,host,port,tier,created_at) VALUES(1,'host','linux','127.0.0.1',22,2,?)`, now); err != nil {
		t.Fatal(err)
	}

	svc := &Service{DB: d}
	id, err := svc.Create(context.Background(), 1, 1, "need access", 0)
	if err != nil {
		t.Fatal(err)
	}

	if err := svc.Decide(context.Background(), id, 1, "admin", true); err != ErrSelfApproval {
		t.Fatalf("expected ErrSelfApproval, got %v", err)
	}
	if err := svc.Decide(context.Background(), id, 2, "user", true); err != ErrNotApprover {
		t.Fatalf("expected ErrNotApprover, got %v", err)
	}
	if err := svc.Decide(context.Background(), id, 2, "admin", true); err != nil {
		t.Fatalf("admin approve: %v", err)
	}
	ok, err := svc.IsApproved(context.Background(), 1, 1)
	if err != nil || !ok {
		t.Fatalf("expected approved access, ok=%v err=%v", ok, err)
	}
}
