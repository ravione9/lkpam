package linuxprovision

import "strings"
import "testing"

func TestProvisionScriptUsesSudo(t *testing.T) {
	s := provisionScript("ravi.verma1", "cGFzcw==", "sudo")
	if !strings.Contains(s, "sudo -n") {
		t.Fatal("script should use sudo -n when not root")
	}
	if !strings.Contains(s, "RUN useradd") {
		t.Fatal("script should run useradd via RUN helper")
	}
	if !strings.Contains(s, "RUN chpasswd") {
		t.Fatal("script should run chpasswd via RUN helper")
	}
}

func TestLinuxUsername(t *testing.T) {
	if got := LinuxUsername("Ravi.Verma1"); got != "ravi.verma1" {
		t.Fatalf("got %q", got)
	}
}
