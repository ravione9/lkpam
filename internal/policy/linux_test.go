package policy

import "testing"

func TestIsLinuxKind(t *testing.T) {
	for _, k := range []string{"linux", "ubuntu", "rhel-8", "amazon-linux", "cisco-ios"} {
		got := IsLinuxKind(k)
		want := k != "cisco-ios"
		if got != want {
			t.Errorf("IsLinuxKind(%q) = %v, want %v", k, got, want)
		}
	}
}

func TestMergeLinuxPrivilege(t *testing.T) {
	if got := MergeLinuxPrivilege("none", "sudo"); got != "sudo" {
		t.Fatalf("got %q", got)
	}
	if got := MergeLinuxPrivilege("sudo", "root"); got != "root" {
		t.Fatalf("got %q", got)
	}
}
