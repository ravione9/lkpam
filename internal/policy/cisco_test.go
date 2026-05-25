package policy

import "testing"

func TestMergeCiscoPrivilegeLevel(t *testing.T) {
	if got := MergeCiscoPrivilegeLevel(0, 10); got != 10 {
		t.Fatalf("merge 0+10 = %d", got)
	}
	if got := MergeCiscoPrivilegeLevel(5, 15); got != 15 {
		t.Fatalf("merge 5+15 = %d", got)
	}
	if got := MergeCiscoPrivilegeLevel(12, 0); got != 12 {
		t.Fatalf("merge 12+0 = %d", got)
	}
}

func TestEffectiveCiscoPrivilege(t *testing.T) {
	if got := EffectiveCiscoPrivilege(Decision{CiscoPrivilegeLevel: 7}, "admin"); got != 7 {
		t.Fatalf("policy override = %d", got)
	}
	if got := EffectiveCiscoPrivilege(Decision{}, "netops"); got != 10 {
		t.Fatalf("role default netops = %d", got)
	}
}

func TestIsCiscoKind(t *testing.T) {
	if !IsCiscoKind("cisco-ios") || !IsCiscoKind("cisco") {
		t.Fatal("expected cisco kinds")
	}
	if IsCiscoKind("linux") || IsCiscoKind("arista") {
		t.Fatal("unexpected cisco kind match")
	}
}
