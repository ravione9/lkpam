// Package mfa implements TOTP (RFC 6238) for second-factor authentication.
// We use 6-digit codes, 30-second steps, HMAC-SHA1 — matching Google
// Authenticator, Microsoft Authenticator, 1Password, and every other widely
// deployed authenticator app.
package mfa

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	step    = 30
	digits  = 6
	skewWin = 2 // accept current ± 2 steps (~60s) for clock drift
)

// NewSecret returns a fresh 20-byte secret base32-encoded (no padding).
// 160 bits is the size required by RFC 4226 and accepted by all authenticators.
func NewSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// OtpAuthURI builds the otpauth:// URI for the secret, suitable for QR encoding.
//
//	issuer  - product name shown in the authenticator app (e.g. "PAM Platform")
//	account - typically the username or "username@host"
func OtpAuthURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(digits))
	q.Set("period", fmt.Sprint(step))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// Generate returns the current TOTP code for secret at time t.
func Generate(secret string, t time.Time) (string, error) {
	key, err := decode(secret)
	if err != nil {
		return "", err
	}
	return hotp(key, uint64(t.Unix()/step)), nil
}

// Verify checks code against the secret, allowing a one-step skew window.
func Verify(secret, code string) bool {
	code = NormalizeOTP(code)
	if len(code) != digits {
		return false
	}
	key, err := decode(secret)
	if err != nil {
		return false
	}
	counter := uint64(time.Now().Unix() / step)
	for d := -skewWin; d <= skewWin; d++ {
		c := counter
		if d < 0 {
			c -= uint64(-d)
		} else {
			c += uint64(d)
		}
		if hotp(key, c) == code {
			return true
		}
	}
	return false
}

func decode(secret string) ([]byte, error) {
	secret = strings.ReplaceAll(strings.ToUpper(secret), " ", "")
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
}

// hotp computes RFC 4226 HOTP(K, C) truncated to `digits` decimal digits.
func hotp(key []byte, counter uint64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}
