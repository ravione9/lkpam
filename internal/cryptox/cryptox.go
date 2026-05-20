// Package cryptox provides authenticated encryption and SSH CA primitives
// used by the PAM vault. Everything here is constant-time where the underlying
// stdlib primitive is constant-time. Do not roll your own; use these helpers.
package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// MasterKeyLen is the length in bytes of the master encryption key (AES-256).
const MasterKeyLen = 32

// ErrCiphertextTooShort is returned when the ciphertext is shorter than the
// nonce length and therefore cannot be decrypted.
var ErrCiphertextTooShort = errors.New("cryptox: ciphertext too short")

// NewMasterKey returns a fresh 32-byte key suitable for AES-256-GCM.
func NewMasterKey() ([]byte, error) {
	k := make([]byte, MasterKeyLen)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		return nil, fmt.Errorf("cryptox: read random: %w", err)
	}
	return k, nil
}

// Encrypt seals plaintext with AES-256-GCM using key. The output is
// nonce || ciphertext || tag. Returns a base64-encoded string convenient for
// storage in a database column.
func Encrypt(key, plaintext []byte) (string, error) {
	if len(key) != MasterKeyLen {
		return "", fmt.Errorf("cryptox: key must be %d bytes", MasterKeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cryptox: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("cryptox: new gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("cryptox: read nonce: %w", err)
	}
	ct := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt.
func Decrypt(key []byte, b64 string) ([]byte, error) {
	if len(key) != MasterKeyLen {
		return nil, fmt.Errorf("cryptox: key must be %d bytes", MasterKeyLen)
	}
	ct, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("cryptox: decode b64: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cryptox: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptox: new gcm: %w", err)
	}
	if len(ct) < gcm.NonceSize() {
		return nil, ErrCiphertextTooShort
	}
	nonce, body := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, fmt.Errorf("cryptox: gcm open: %w", err)
	}
	return pt, nil
}

// PasswordHash returns an Argon2id hash of pw with a fresh 16-byte salt.
// Format: argon2id$<saltB64>$<hashB64>. Suitable for storage and constant-time
// comparison via VerifyPassword.
func PasswordHash(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	hash := argon2.IDKey([]byte(pw), salt, 1, 64*1024, 4, 32)
	return fmt.Sprintf("argon2id$%s$%s",
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword checks pw against an Argon2id encoded hash produced by
// PasswordHash. Constant-time comparison is used.
func VerifyPassword(pw, encoded string) bool {
	parts := splitDollar(encoded)
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, 1, 64*1024, 4, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

func splitDollar(s string) []string {
	out := []string{}
	cur := ""
	for _, r := range s {
		if r == '$' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}
