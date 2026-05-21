package ldap

import "testing"

func TestAllowedUser(t *testing.T) {
	sel := SyncSelection{UserDNs: []string{"CN=Alice,DC=corp,DC=local"}}
	if !AllowedUser(sel, "CN=Alice,DC=corp,DC=local") {
		t.Fatal("expected allowed")
	}
	if AllowedUser(sel, "CN=Bob,DC=corp,DC=local") {
		t.Fatal("expected denied")
	}
	if !AllowedUser(SyncSelection{}, "CN=Anyone,DC=corp,DC=local") {
		t.Fatal("empty selection should allow all")
	}
}
