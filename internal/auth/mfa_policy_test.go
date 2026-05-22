package auth

import "testing"

func TestEffectiveMFAPolicy(t *testing.T) {
	if got := EffectiveMFAPolicy(""); got != "required" {
		t.Fatalf("empty policy = %q, want required", got)
	}
	if got := EffectiveMFAPolicy("optional"); got != "optional" {
		t.Fatalf("optional = %q", got)
	}
}

func TestLoginMFADecision(t *testing.T) {
	u := &User{MFAEnabled: false}
	if d := LoginMFADecision(u, "required"); !d.RequireEnrollment {
		t.Fatal("expected enrollment required")
	}
	u.MFAExempt = true
	if d := LoginMFADecision(u, "required"); d.RequireEnrollment || d.RequireOTP {
		t.Fatal("exempt user should skip MFA")
	}
	u = &User{MFAEnabled: true}
	if d := LoginMFADecision(u, "optional"); !d.RequireOTP {
		t.Fatal("optional enrolled user needs OTP")
	}
}
