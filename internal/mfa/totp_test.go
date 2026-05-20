package mfa

import (
	"testing"
	"time"
)

func TestGenerateVerify(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	code, err := Generate(secret, time.Now())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(code) != digits {
		t.Fatalf("code len = %d, want %d", len(code), digits)
	}
	if !Verify(secret, code) {
		t.Fatalf("Verify rejected its own code %q", code)
	}
	if Verify(secret, "000000") && code != "000000" {
		t.Fatalf("Verify accepted an unrelated code")
	}
}

func TestRFC6238Vectors(t *testing.T) {
	// RFC 6238 Appendix B test vectors (SHA1 column, T0 = 0, X = 30).
	// Secret = ASCII "12345678901234567890" → base32 "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, c := range cases {
		got, err := Generate(secret, time.Unix(c.unix, 0))
		if err != nil {
			t.Errorf("Generate(%d): %v", c.unix, err)
			continue
		}
		if got != c.want {
			t.Errorf("t=%d: got %s want %s", c.unix, got, c.want)
		}
	}
}
