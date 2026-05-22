package tacacs

import (
	"strings"
	"testing"
)

func TestParseUnknownUserDefer(t *testing.T) {
	if ParseUnknownUserDefer("drop") != DeferUnknownDrop {
		t.Fatal("expected drop")
	}
	if ParseUnknownUserDefer("error") != DeferUnknownError {
		t.Fatal("expected error")
	}
	if ParseUnknownUserDefer("") != DeferUnknownError {
		t.Fatal("expected default error")
	}
}

func TestAuthenStatusForResult(t *testing.T) {
	tests := []struct {
		ok, pamUser     bool
		wantStatus      uint8
		wantMsgContains string
	}{
		{true, true, AuthenStatusPass, "ok"},
		{true, false, AuthenStatusPass, "ok"},
		{false, true, AuthenStatusFail, "auth failed"},
		{false, false, AuthenStatusError, "not managed by PAM"},
	}
	for _, tc := range tests {
		st, msg := authenStatusForResult(tc.ok, tc.pamUser)
		if st != tc.wantStatus {
			t.Fatalf("ok=%v pamUser=%v: status=%#x want %#x", tc.ok, tc.pamUser, st, tc.wantStatus)
		}
		if tc.wantMsgContains != "" && !strings.Contains(msg, tc.wantMsgContains) {
			t.Fatalf("ok=%v pamUser=%v: msg=%q want substring %q", tc.ok, tc.pamUser, msg, tc.wantMsgContains)
		}
	}
}
