package radius

import (
	"context"
	"testing"

	"github.com/example/pam-platform/internal/db"
)

func mustDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open("file::memory:?cache=shared&_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	return d
}

func TestClientStoreFallsBackToDefaultSecret(t *testing.T) {
	d := mustDB(t)
	defer d.Close()
	store := NewClientStore(d, []byte("FALLBACK"))
	if err := store.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	rec, err := store.Lookup(context.Background(), "10.0.0.1:50000")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if string(rec.Secret) != "FALLBACK" {
		t.Fatalf("expected fallback secret, got %q", rec.Secret)
	}
	if rec.Name != "default" {
		t.Fatalf("expected name=default, got %q", rec.Name)
	}
}

func TestClientStoreExactMatch(t *testing.T) {
	d := mustDB(t)
	defer d.Close()
	if _, err := d.Exec(`
		INSERT INTO radius_clients(name, nas_ip, secret, require_message_auth,
		                           vendor, disabled, created_at)
		VALUES('switch-1','10.0.0.5','per-device-key',1,'cisco',0, 1234)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store := NewClientStore(d, []byte("FALLBACK"))
	rec, err := store.Lookup(context.Background(), "10.0.0.5:50000")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if string(rec.Secret) != "per-device-key" {
		t.Fatalf("expected per-device secret, got %q", rec.Secret)
	}
	if !rec.RequireMessageAuth {
		t.Fatalf("expected RequireMessageAuth=true")
	}
	if rec.Vendor != "cisco" {
		t.Fatalf("expected vendor=cisco")
	}
}

func TestClientStoreCIDRMatch(t *testing.T) {
	d := mustDB(t)
	defer d.Close()
	if _, err := d.Exec(`
		INSERT INTO radius_clients(name, nas_ip, secret, require_message_auth,
		                           vendor, disabled, created_at)
		VALUES('site-a','192.168.20.0/24','site-secret',0,'',0, 1)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store := NewClientStore(d, []byte("FALLBACK"))
	rec, err := store.Lookup(context.Background(), "192.168.20.42:50000")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if string(rec.Secret) != "site-secret" {
		t.Fatalf("expected CIDR secret, got %q", rec.Secret)
	}
	// outside the CIDR falls back to default
	rec, err = store.Lookup(context.Background(), "192.168.21.42:50000")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if string(rec.Secret) != "FALLBACK" {
		t.Fatalf("expected fallback, got %q", rec.Secret)
	}
}

func TestClientStoreDisabledRejected(t *testing.T) {
	d := mustDB(t)
	defer d.Close()
	if _, err := d.Exec(`
		INSERT INTO radius_clients(name, nas_ip, secret, require_message_auth,
		                           vendor, disabled, created_at)
		VALUES('off','10.0.0.6','x',0,'',1, 1)`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	store := NewClientStore(d, []byte("FALLBACK"))
	if _, err := store.Lookup(context.Background(), "10.0.0.6:5000"); err != ErrClientDisabled {
		t.Fatalf("expected ErrClientDisabled, got %v", err)
	}
}

func TestClientStoreUnknownClientWithoutDefault(t *testing.T) {
	d := mustDB(t)
	defer d.Close()
	store := NewClientStore(d, nil)
	if _, err := store.Lookup(context.Background(), "10.0.0.99:5000"); err != ErrUnknownClient {
		t.Fatalf("expected ErrUnknownClient, got %v", err)
	}
}
