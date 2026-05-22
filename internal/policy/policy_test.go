package policy

import "testing"

func TestCommandAllowed(t *testing.T) {
	cases := []struct {
		cmd  string
		want bool
	}{
		{"show run", true},
		{"SHOW RUN", true},
		{"reload", false},
		{"RELOAD", false},
		{"erase startup-config", false},
		{"configure terminal", false},
		{"configure t", false},
		{"conf t", false},
		{"config t", false},
		{"config ter", false},
		{"en", false},
		{"exit", true},
		{"end", true},
		{"ping 8.8.8.8", true},
		{"sh run", true},
		{"rel", false},
		{"wr erase", false},
		{"era start", false},
	}
	allow := []string{"show", "ping"}
	deny := []string{"reload", "erase startup-config", "configure terminal", "enable", "write erase"}
	for _, tc := range cases {
		got := CommandAllowed(tc.cmd, allow, deny)
		if got != tc.want {
			t.Fatalf("CommandAllowed(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
}

func TestNormalizeCLI(t *testing.T) {
	cases := map[string]string{
		"config t":            "configure terminal",
		"CONFIG T":            "configure terminal",
		"conf t":              "configure terminal",
		"configure t":         "configure terminal",
		"config ter":          "configure terminal",
		"configure terminal":  "configure terminal",
		"en":                  "enable",
		"show run":            "show running-config",
		"sh run":              "show running-config",
		"sho ver":             "show version",
		"wr mem":              "write memory",
		"int gi0/1":           "interface gi0/1",
		"era start":           "erase startup-config",
	}
	for in, want := range cases {
		if got := NormalizeCLI(in); got != want {
			t.Fatalf("NormalizeCLI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFullCommand(t *testing.T) {
	got := FullCommand("show", []string{"running-config"})
	if got != "show running-config" {
		t.Fatalf("FullCommand = %q", got)
	}
}
