package sshproxy

import (
	"bytes"
	"sync/atomic"
	"testing"
	"time"
)

func TestCmdGateLogoutEndsSession(t *testing.T) {
	var up bytes.Buffer
	closed := int32(0)
	gate := newCmdGate(&up, &bytes.Buffer{}, nil, nil, nil, "", "", func() {
		atomic.StoreInt32(&closed, 1)
	})

	gate.noteOutput([]byte("Switch>"))
	_, _ = gate.Write([]byte("logout"))
	_, _ = gate.Write([]byte{'\r'})

	time.Sleep(500 * time.Millisecond)
	if atomic.LoadInt32(&closed) != 1 {
		t.Fatal("expected session close callback on logout")
	}
}

func TestCmdGateExitAtPrivilegedDoesNotEndSession(t *testing.T) {
	var up bytes.Buffer
	closed := int32(0)
	gate := newCmdGate(&up, &bytes.Buffer{}, nil, nil, nil, "", "", func() {
		atomic.StoreInt32(&closed, 1)
	})

	gate.noteOutput([]byte("Switch#\r\n"))
	_, _ = gate.Write([]byte("exit"))
	_, _ = gate.Write([]byte{'\r'})

	time.Sleep(500 * time.Millisecond)
	if atomic.LoadInt32(&closed) != 0 {
		t.Fatal("exit from privileged prompt should not end SSH session")
	}
	if !bytes.Contains(up.Bytes(), []byte("exit")) {
		t.Fatalf("expected exit forwarded, got %q", up.String())
	}
}
