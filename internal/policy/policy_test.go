package policy

import "testing"

func TestCommandAllowed(t *testing.T) {
	allow := []string{"show", "ping"}
	deny := []string{"reload", "erase startup-config"}

	cases := []struct {
		cmd    string
		want   bool
	}{
		{"show run", true},
		{"SHOW RUN", true},
		{"reload", false},
		{"RELOAD", false},
		{"erase startup-config", false},
		{"configure terminal", false},
		{"ping 8.8.8.8", true},
	}
	for _, tc := range cases {
		got := CommandAllowed(tc.cmd, allow, deny)
		if got != tc.want {
			t.Fatalf("CommandAllowed(%q) = %v, want %v", tc.cmd, got, tc.want)
		}
	}
}

func TestFullCommand(t *testing.T) {
	got := FullCommand("show", []string{"running-config"})
	if got != "show running-config" {
		t.Fatalf("FullCommand = %q", got)
	}
}
