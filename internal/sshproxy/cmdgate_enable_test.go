package sshproxy

import (
	"bytes"
	"strings"
	"testing"
)

func TestCmdGateInjectsEnableSecret(t *testing.T) {
	var up, down bytes.Buffer
	gate := newCmdGate(&up, &down, nil, nil, nil, "EnableSecret99", "", nil)

	gate.noteOutput([]byte("Switch>"))
	_, _ = gate.Write([]byte("en\r"))
	gate.noteOutput([]byte("\r\nPassword: "))

	got := up.String()
	if !bytes.Contains([]byte(got), []byte("EnableSecret99")) {
		t.Fatalf("upstream = %q, want enable secret injected", got)
	}
	filtered := string(gate.filterDownstream([]byte("Password: EnableSecret99\r\n")))
	if strings.Contains(filtered, "EnableSecret99") {
		t.Fatalf("filtered = %q, must not contain plaintext password", filtered)
	}
	if !strings.Contains(filtered, strings.Repeat("*", len("EnableSecret99"))) {
		t.Fatalf("filtered = %q, want masked password line", filtered)
	}
}

func TestCmdGateSwallowsKeystrokesDuringEnableInject(t *testing.T) {
	var up bytes.Buffer
	gate := newCmdGate(&up, &bytes.Buffer{}, nil, nil, nil, "Secret99", "", nil)
	gate.mu.Lock()
	gate.expectEnablePass = true
	gate.mu.Unlock()

	_, _ = gate.Write([]byte("norecho\r"))
	if strings.Contains(up.String(), "norecho") {
		t.Fatalf("upstream = %q, user keystrokes must be swallowed", up.String())
	}
	if !strings.HasSuffix(up.String(), "Secret99\r") {
		t.Fatalf("upstream = %q, want injected secret on Enter", up.String())
	}
}

func TestCmdGateFilterDownstreamRedactsEnableSecret(t *testing.T) {
	gate := newCmdGate(nil, nil, nil, nil, nil, "Rescue@9897", "", nil)
	out := gate.filterDownstream([]byte("Password: Rescue@9897\r\nok\r\n"))
	if strings.Contains(string(out), "Rescue@9897") {
		t.Fatalf("filter = %q, must not contain plaintext secret", string(out))
	}
	if !strings.Contains(string(out), strings.Repeat("*", len("Rescue@9897"))) {
		t.Fatalf("filter = %q, want asterisks", string(out))
	}
}
