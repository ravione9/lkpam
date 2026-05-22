package sshproxy

import (
	"bytes"
	"strings"
	"testing"
)

func TestCmdGateDenyClearsLineAndSendsCtrlC(t *testing.T) {
	var up, down bytes.Buffer
	gate := newCmdGate(&up, &down, nil, []string{"configure terminal"}, nil, "Rescue@9897", "", nil)

	// Device echoed prompt + command (as gateAwareWriter would).
	gate.noteOutput([]byte("Switch#configure terminal"))

	// User presses Enter (CRLF).
	_, _ = gate.Write([]byte{'\r', '\n'})

	if up.String() != "\x03" {
		t.Fatalf("upstream = %q, want Ctrl-C only", up.String())
	}
	if !strings.Contains(down.String(), "command denied") {
		t.Fatalf("downstream = %q, want denial message", down.String())
	}

	up.Reset()
	down.Reset()
	gate.noteOutput([]byte("\r\nSwitch#"))

	// Empty Enter must reach device (not re-deny stale command).
	_, _ = gate.Write([]byte{'\r', '\n'})
	if up.String() != "\r" {
		t.Fatalf("empty enter upstream = %q, want \\r", up.String())
	}

	up.Reset()
	gate.noteOutput([]byte("Switch#exit"))
	_, _ = gate.Write([]byte{'\r'})
	if up.String() != "\r" {
		t.Fatalf("exit upstream = %q, want \\r", up.String())
	}
}

func TestCmdGateAllowForwardsSingleLineEnd(t *testing.T) {
	var up bytes.Buffer
	gate := newCmdGate(&up, &bytes.Buffer{}, []string{"show"}, []string{"reload"}, nil, "", "", nil)
	gate.noteOutput([]byte("Switch#show version"))
	_, _ = gate.Write([]byte{'\r', '\n'})
	if up.String() != "\r" {
		t.Fatalf("upstream = %q, want single \\r", up.String())
	}
}
