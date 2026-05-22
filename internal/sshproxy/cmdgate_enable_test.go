package sshproxy

import (
	"bytes"
	"testing"
)

func TestCmdGateInjectsEnableSecret(t *testing.T) {
	var up, down bytes.Buffer
	gate := newCmdGate(&up, &down, nil, nil, nil, "EnableSecret99")

	gate.noteOutput([]byte("Switch>en"))
	_, _ = gate.Write([]byte{'\r'})
	gate.noteOutput([]byte("\r\nPassword: "))
	_, _ = gate.Write([]byte{'\r'})

	got := up.String()
	if !bytes.Contains([]byte(got), []byte("EnableSecret99")) {
		t.Fatalf("upstream = %q, want enable secret injected", got)
	}
}
