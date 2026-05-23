package tacacs

import (
	"slices"
	"testing"
)

func TestFortinetAuthorArgs(t *testing.T) {
	s := &Server{FortinetMemberOf: "PAM-Admins"}
	args := s.fortinetAuthorArgs("admin", "fortigate", "")
	want := []string{
		"service=fortigate",
		"admin_prof=super_admin",
		"memberof=PAM-Admins",
	}
	for _, w := range want {
		if !slices.Contains(args, w) {
			t.Fatalf("args=%v missing %q", args, w)
		}
	}
}

func TestFortinetAuthorArgsRequestMemberofFallback(t *testing.T) {
	s := &Server{
		FortinetMemberOf: "PAM-Admins",
		FortinetRoleMemberofMap: map[string]string{
			"user": "PAM-Users",
		},
	}
	args := s.fortinetAuthorArgs("user", "FortiGate", "group3")
	if !slices.Contains(args, "memberof=PAM-Users") {
		t.Fatalf("args=%v, want per-role memberof=PAM-Users (not FortiGate request group3)", args)
	}
	s2 := &Server{} // no default, no map
	args2 := s2.fortinetMemberofForRole("user", "group3")
	if args2 != "group3" {
		t.Fatalf("got %q, want group3 when no map/default configured", args2)
	}
}

func TestFortinetProfRank(t *testing.T) {
	if fortinetProfRank("read_only") >= fortinetProfRank("super_admin") {
		t.Fatal("read_only should rank lower than super_admin")
	}
	if fortinetProfRank("no_access") >= fortinetProfRank("prof_admin") {
		t.Fatal("no_access should rank lower than prof_admin")
	}
}

func TestFortinetAdminProf(t *testing.T) {
	if fortinetAdminProf("admin") != "super_admin" {
		t.Fatal("admin -> super_admin")
	}
	if fortinetAdminProf("user") != "prof_admin" {
		t.Fatal("user -> prof_admin")
	}
}

// TestFortinetRoleProfileMap verifies the configurable role→profile map.
func TestFortinetRoleProfileMap(t *testing.T) {
	s := &Server{
		FortinetMemberOf: "PAM-Admins",
		FortinetRoleProfileMap: map[string]string{
			"admin":  "super_admin",
			"secops": "read_write",   // overridden from built-in super_admin
			"netops": "prof_admin",
			"viewer": "no_access",
		},
		FortinetRoleMemberofMap: map[string]string{
			"admin":  "PAM-SuperAdmins",
			"netops": "PAM-NetAdmins",
		},
	}

	cases := []struct {
		role        string
		wantProfile string
		wantMemberof string
	}{
		{"admin", "super_admin", "PAM-SuperAdmins"},
		{"secops", "read_write", "PAM-Admins"}, // memberof falls back to default
		{"netops", "prof_admin", "PAM-NetAdmins"},
		{"viewer", "no_access", "PAM-Admins"},
		{"user", "prof_admin", "PAM-Admins"}, // not in map → built-in default
	}
	for _, tc := range cases {
		args := s.fortinetAuthorArgs(tc.role, "fortigate", "")
		if !slices.Contains(args, "admin_prof="+tc.wantProfile) {
			t.Errorf("role=%q: args=%v, want admin_prof=%s", tc.role, args, tc.wantProfile)
		}
		if !slices.Contains(args, "memberof="+tc.wantMemberof) {
			t.Errorf("role=%q: args=%v, want memberof=%s", tc.role, args, tc.wantMemberof)
		}
	}
}

// TestParseRoleMap verifies the env-var parser.
func TestParseRoleMap(t *testing.T) {
	m := ParseRoleMap("admin=super_admin,netops=prof_admin, viewer=no_access ,user=")
	if m["admin"] != "super_admin" {
		t.Errorf("admin: got %q", m["admin"])
	}
	if m["netops"] != "prof_admin" {
		t.Errorf("netops: got %q", m["netops"])
	}
	if m["viewer"] != "no_access" {
		t.Errorf("viewer: got %q", m["viewer"])
	}
	// Empty value should be skipped
	if _, ok := m["user"]; ok {
		t.Error("user with empty value should not be in map")
	}
	if ParseRoleMap("") != nil {
		t.Error("empty string should return nil")
	}
}
