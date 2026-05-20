package cryptox

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := NewMasterKey()
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("hello, vault — store me carefully")
	ct, err := Encrypt(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plain)
	}
}

func TestEncryptIsRandom(t *testing.T) {
	key, _ := NewMasterKey()
	a, _ := Encrypt(key, []byte("same"))
	b, _ := Encrypt(key, []byte("same"))
	if a == b {
		t.Fatalf("two encryptions of the same plaintext returned the same ciphertext (nonce reuse)")
	}
}

func TestPasswordHashVerify(t *testing.T) {
	h, err := PasswordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery staple", h) {
		t.Fatal("verify failed for correct password")
	}
	if VerifyPassword("wrong", h) {
		t.Fatal("verify accepted wrong password")
	}
}
