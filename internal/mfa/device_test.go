package mfa

import "testing"

func TestNormalizeOTP(t *testing.T) {
	if got := NormalizeOTP(" 482 913 "); got != "482913" {
		t.Fatalf("got %q", got)
	}
	if got := NormalizeOTP("1234567890"); got != "567890" {
		t.Fatalf("last 6 digits: got %q", got)
	}
}

func TestSplitAppendedOTP(t *testing.T) {
	base, otp := SplitAppendedOTP("Secret1!482913")
	if base != "Secret1!" || otp != "482913" {
		t.Fatalf("got %q + %q", base, otp)
	}
	base, otp = SplitAppendedOTP("short")
	if base != "short" || otp != "" {
		t.Fatalf("short password should not split")
	}
}
