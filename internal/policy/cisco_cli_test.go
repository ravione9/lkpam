package policy

import "testing"

func TestExpandCiscoAbbreviations(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"config t", "configure terminal"},
		{"conf ter", "configure terminal"},
		{"configure terminal", "configure terminal"},
		{"sh run", "show running-config"},
		{"sho startup-config", "show startup-config"},
		{"sh ver", "show version"},
		{"sh int br", "show interface br"},
		{"en", "enable"},
		{"rel", "reload"},
		{"wr mem", "write memory"},
		{"wr erase", "write erase"},
		{"era start", "erase startup-config"},
		{"cop run start", "copy running-config startup-config"},
		{"no shut", "no shutdown"},
		{"int gi0/1", "interface gi0/1"},
		{"ping 10.0.0.1", "ping 10.0.0.1"},
	}
	for _, tc := range cases {
		got := NormalizeCLI(tc.in)
		if got != tc.want {
			t.Errorf("NormalizeCLI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCommandAllowedCiscoAbbrev(t *testing.T) {
	deny := []string{"reload", "erase startup-config", "configure terminal", "write erase"}
	allow := []string{"show", "ping", "interface"}

	checks := []struct {
		cmd  string
		want bool
	}{
		{"show ip int brief", true},
		{"sh ip int br", true},
		{"reload", false},
		{"rel", false},
		{"config t", false},
		{"era start", false},
		{"wr erase", false},
		{"wr er", false},
	}
	for _, c := range checks {
		got := CommandAllowed(c.cmd, allow, deny)
		if got != c.want {
			t.Errorf("CommandAllowed(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}
