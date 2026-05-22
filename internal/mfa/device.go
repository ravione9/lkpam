package mfa

import "strings"

// NormalizeOTP strips non-digits and returns up to 6 digits for TOTP entry.
func NormalizeOTP(code string) string {
	var b strings.Builder
	for _, c := range strings.TrimSpace(code) {
		if c >= '0' && c <= '9' {
			b.WriteRune(c)
		}
	}
	s := b.String()
	if len(s) > digits {
		s = s[len(s)-digits:]
	}
	return s
}

// SplitAppendedOTP extracts a 6-digit TOTP suffix appended to a password with no
// separator (used for FortiGate TACACS and users who type password+code together).
func SplitAppendedOTP(password string) (base, otp string) {
	password = strings.TrimSpace(password)
	if len(password) <= digits {
		return password, ""
	}
	suffix := password[len(password)-digits:]
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return password, ""
		}
	}
	return password[:len(password)-digits], suffix
}
