package authclient

import "testing"

func TestSplitAppendedOTP(t *testing.T) {
	base, otp := SplitAppendedOTP("Secret1!482913")
	if base != "Secret1!" || otp != "482913" {
		t.Fatalf("got %q + %q", base, otp)
	}
	base, otp = SplitAppendedOTP("short")
	if base != "short" || otp != "" {
		t.Fatalf("short password should not split")
	}
	base, otp = SplitAppendedOTP("pass12345X")
	if otp != "" {
		t.Fatalf("non-numeric suffix should not split")
	}
}
