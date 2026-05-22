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
	if down.Len() > 0 {
		t.Fatalf("downstream = %q, must not synthesize Password lines on the terminal", down.String())
	}
	filtered := string(gate.filterDownstream([]byte("Password: EnableSecret99\r\n")))
	if strings.Contains(filtered, "EnableSecret99") {
		t.Fatalf("filtered = %q, must not contain plaintext password", filtered)
	}
	if !strings.Contains(filtered, strings.Repeat("*", len("EnableSecret99"))) {
		t.Fatalf("filtered = %q, want masked password line", filtered)
	}
}

func TestCmdGateAutoInjectOnlyOncePerEnable(t *testing.T) {
	var up, down bytes.Buffer
	gate := newCmdGate(&up, &down, nil, nil, nil, "Secret99", "", nil)

	_, _ = gate.Write([]byte("en\r"))
	gate.noteOutput([]byte("Password: "))
	gate.noteOutput([]byte("Password: "))
	gate.noteOutput([]byte("Password: "))

	count := strings.Count(up.String(), "Secret99")
	if count != 1 {
		t.Fatalf("upstream = %q, want exactly one inject, got %d", up.String(), count)
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

func TestCmdGateBlocksEnableSecretPasteAtPrivilegedPrompt(t *testing.T) {
	var up, down bytes.Buffer
	gate := newCmdGate(&up, &down, nil, nil, nil, "Rescue@9897", "", nil)
	gate.mu.Lock()
	gate.execPrivileged = true
	gate.mu.Unlock()

	n, err := gate.Write([]byte("Rescue@9897\r"))
	if err != nil || n != len("Rescue@9897\r") {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if up.Len() != 0 {
		t.Fatalf("upstream = %q, pasted enable secret must not be sent at # prompt", up.String())
	}
	if !strings.Contains(down.String(), "do not type or paste") {
		t.Fatalf("downstream = %q, want PAM warning", down.String())
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

func TestCmdGateClearsEnableStateAtHashPromptWithoutNewline(t *testing.T) {
	// Cisco IOS prints the privileged prompt without a trailing newline.
	// Before this fix, expectEnablePass stayed true and the next Enter from the
	// user re-injected the enable secret as a command at the # prompt.
	var up, down bytes.Buffer
	gate := newCmdGate(&up, &down, nil, nil, nil, "Rescue@9897", "", nil)

	_, _ = gate.Write([]byte("en\r"))
	gate.noteOutput([]byte("\r\nPassword: "))
	gate.noteOutput([]byte("\r\nok\r\nMonitoringSwitch#"))

	if gate.waitingForEnablePassword() {
		t.Fatalf("expected enable flow cleared after # prompt without trailing newline")
	}
	upBefore := up.Len()
	_, _ = gate.Write([]byte("show ver\r"))
	if !strings.Contains(up.String()[upBefore:], "show ver") {
		t.Fatalf("subsequent keystrokes must reach upstream, got %q", up.String()[upBefore:])
	}
	if strings.Contains(up.String()[upBefore:], "Rescue@9897") {
		t.Fatalf("must not re-inject enable secret at # prompt: %q", up.String()[upBefore:])
	}
}

func TestCmdGateFilterDownstreamMasksByteByByteEcho(t *testing.T) {
	// Simulate the real device echoing the Password: prompt and then the password
	// one byte at a time, which is what showed plaintext in the browser session.
	gate := newCmdGate(nil, nil, nil, nil, nil, "", "", func() {})
	if gate == nil {
		t.Fatal("expected cmdGate, got nil")
	}
	var combined []byte
	for _, b := range []byte("Password: Rescue@9897\r\nok\r\n") {
		combined = append(combined, gate.filterDownstream([]byte{b})...)
	}
	out := string(combined)
	if strings.Contains(out, "Rescue@9897") {
		t.Fatalf("chunked filter = %q, must not contain plaintext", out)
	}
	if !strings.Contains(out, "Password: **") {
		t.Fatalf("chunked filter = %q, want masked password chars after Password:", out)
	}
}
