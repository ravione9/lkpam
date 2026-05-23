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

func TestFortinetAuthorArgsEchoMemberof(t *testing.T) {
	s := &Server{FortinetMemberOf: "PAM-Admins"}
	args := s.fortinetAuthorArgs("user", "FortiGate", "group3")
	if !slices.Contains(args, "memberof=group3") {
		t.Fatalf("args=%v, want memberof=group3 from FortiGate request", args)
	}
	if !slices.Contains(args, "admin_prof=prof_admin") {
		t.Fatalf("args=%v, want prof_admin for user role", args)
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
