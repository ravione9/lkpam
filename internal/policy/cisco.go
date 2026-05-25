package policy

import "strings"

// IsCiscoKind reports whether a target kind is Cisco IOS/NX-OS/IOS-XE/etc.
func IsCiscoKind(kind string) bool {
	k := strings.ToLower(strings.TrimSpace(kind))
	if k == "cisco" {
		return true
	}
	return strings.HasPrefix(k, "cisco-")
}

// CiscoPrivilegeFromRole is the legacy default when policy cisco_privilege_level=0.
func CiscoPrivilegeFromRole(role string) int {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin", "secops":
		return 15
	case "netops":
		return 10
	case "viewer", "user":
		return 1
	}
	return 1
}

// NormalizeCiscoPrivilegeLevel clamps IOS privilege to 0 (unset) or 1–15.
func NormalizeCiscoPrivilegeLevel(n int) int {
	if n <= 0 {
		return 0
	}
	if n > 15 {
		return 15
	}
	return n
}

// MergeCiscoPrivilegeLevel picks the highest configured privilege when a user
// has multiple matching roles (same strategy as Linux privilege merge).
func MergeCiscoPrivilegeLevel(current, next int) int {
	current = NormalizeCiscoPrivilegeLevel(current)
	next = NormalizeCiscoPrivilegeLevel(next)
	if next <= 0 {
		return current
	}
	if current <= 0 {
		return next
	}
	if next > current {
		return next
	}
	return current
}

// EffectiveCiscoPrivilege returns the TACACS/RADIUS priv-lvl for a decision.
func EffectiveCiscoPrivilege(dec Decision, role string) int {
	if dec.CiscoPrivilegeLevel > 0 {
		return dec.CiscoPrivilegeLevel
	}
	return CiscoPrivilegeFromRole(role)
}
