package radius

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestEncodeVSA(t *testing.T) {
	v := EncodeVSA(VendorCisco, CiscoAVPair, []byte("shell:priv-lvl=15"))
	if binary.BigEndian.Uint32(v[:4]) != VendorCisco {
		t.Fatal("vendor id wrong")
	}
	if v[4] != CiscoAVPair {
		t.Fatal("subtype wrong")
	}
	if int(v[5]) != 2+len("shell:priv-lvl=15") {
		t.Fatal("sub-length wrong")
	}
	if !bytes.Equal(v[6:], []byte("shell:priv-lvl=15")) {
		t.Fatal("value wrong")
	}
}

func TestProfileForKnownVendors(t *testing.T) {
	cases := []struct {
		kind   string
		family string
	}{
		{"cisco-ios", "cisco"},
		{"arista", "cisco"},
		{"juniper", "juniper"},
		{"junos", "juniper"},
		{"hp", "hp"},
		{"procurve", "hp"},
		{"aruba", "aruba"},
		{"mikrotik", "mikrotik"},
		{"routeros", "mikrotik"},
		{"paloalto", "paloalto"},
		{"panos", "paloalto"},
		{"huawei", "huawei"},
		{"fortinet", "fortinet"},
		{"fortigate", "fortinet"},
		{"f5", "f5"},
		{"checkpoint", "checkpoint"},
		{"randomswitchos", "generic"},
		{"", "generic"},
	}
	for _, tc := range cases {
		p := profileFor(tc.kind)
		if p.Family != tc.family {
			t.Errorf("kind=%q got family=%q want %q", tc.kind, p.Family, tc.family)
		}
	}
}

func TestCiscoReplyContainsPrivLvl15(t *testing.T) {
	var out AttributeList
	profileFor("cisco").FillReply(&out, "admin", 15)

	vsas := out.GetAll(AttrVendorSpecific)
	if len(vsas) == 0 {
		t.Fatal("expected at least one VSA")
	}
	found := false
	for _, v := range vsas {
		if len(v) < 6 || binary.BigEndian.Uint32(v[:4]) != VendorCisco {
			continue
		}
		if strings.Contains(string(v[6:]), "shell:priv-lvl=15") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Cisco profile must emit shell:priv-lvl=15 VSA")
	}
}

func TestHPProfileEmitsPrivilege15(t *testing.T) {
	var out AttributeList
	profileFor("hp").FillReply(&out, "admin", 15)
	vsas := out.GetAll(AttrVendorSpecific)
	if len(vsas) == 0 {
		t.Fatal("expected VSA")
	}
	for _, v := range vsas {
		if binary.BigEndian.Uint32(v[:4]) != VendorHP || v[4] != HPPrivilegeLevel {
			continue
		}
		if binary.BigEndian.Uint32(v[6:10]) != 15 {
			t.Fatalf("expected priv-level 15, got %d", binary.BigEndian.Uint32(v[6:10]))
		}
		return
	}
	t.Fatalf("HP-Privilege-Level VSA missing")
}

func TestMikrotikGroupForRole(t *testing.T) {
	cases := map[string]string{
		"admin":   "full",
		"secops":  "full",
		"netops":  "write",
		"viewer":  "read",
		"unknown": "read",
	}
	for role, want := range cases {
		if got := mikrotikGroupForRole(role); got != want {
			t.Errorf("role=%q got=%q want=%q", role, got, want)
		}
	}
}

func TestPaloAltoRoleForRole(t *testing.T) {
	if paloAltoRoleForRole("admin", 15) != "superuser" {
		t.Error("admin should get superuser")
	}
	if paloAltoRoleForRole("viewer", 1) != "auditadmin" {
		t.Error("viewer should get auditadmin")
	}
	if paloAltoRoleForRole("netops", 10) != "deviceadmin" {
		t.Error("netops should get deviceadmin")
	}
}

func TestJunosClassForRole(t *testing.T) {
	if junosClassForRole("admin", 15) != "super-user" {
		t.Error("admin should map to super-user")
	}
	if junosClassForRole("viewer", 1) != "read-only" {
		t.Error("viewer should map to read-only")
	}
	if junosClassForRole("netops", 10) != "operator" {
		t.Error("netops should map to operator")
	}
}

func TestPrivLevelForRole(t *testing.T) {
	if privLevelForRole("admin") != 15 {
		t.Error("admin -> 15")
	}
	if privLevelForRole("viewer") != 1 {
		t.Error("viewer -> 1")
	}
	if privLevelForRole("netops") != 10 {
		t.Error("netops -> 10")
	}
}
