package inventory

import (
	"context"
	"testing"

	"github.com/example/pam-platform/internal/db"
)

func TestKindForHostWebURLOnly(t *testing.T) {
	d, err := db.Open("file::memory:?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, err = d.ExecContext(ctx, `
		INSERT INTO targets(name, kind, connection_type, host, port, web_url, tier)
		VALUES('HQ FW', 'fortinet-fortigate', 'web', '', 0, 'https://192.168.24.253/', 1)`)
	if err != nil {
		t.Fatal(err)
	}
	kind, err := KindForHost(ctx, d, "192.168.24.253")
	if err != nil {
		t.Fatal(err)
	}
	if kind != "fortinet-fortigate" {
		t.Fatalf("kind=%q want fortinet-fortigate", kind)
	}
}

func TestNormalizeTargetHost(t *testing.T) {
	tgt := Target{ConnectionType: ConnWeb, WebURL: "https://10.0.0.5/admin"}
	NormalizeTargetHost(&tgt)
	if tgt.Host != "10.0.0.5" {
		t.Fatalf("host=%q", tgt.Host)
	}
}
