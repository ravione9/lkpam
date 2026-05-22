package policy

import "strings"

// IsLinuxKind reports whether target kind is a Linux/Unix SSH family OS.
func IsLinuxKind(kind string) bool {
	k := strings.ToLower(strings.TrimSpace(kind))
	if k == "" {
		return false
	}
	family := k
	if i := strings.Index(k, "-"); i > 0 {
		family = k[:i]
	}
	switch family {
	case "linux", "ubuntu", "debian", "rhel", "centos", "rocky", "alma", "suse", "amazon":
		return true
	}
	return k == "amazon-linux"
}

// NormalizeLinuxPrivilege returns none | sudo | root.
func NormalizeLinuxPrivilege(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "sudo", "root":
		return strings.ToLower(strings.TrimSpace(p))
	default:
		return "none"
	}
}

func linuxPrivilegeRank(p string) int {
	switch NormalizeLinuxPrivilege(p) {
	case "root":
		return 2
	case "sudo":
		return 1
	default:
		return 0
	}
}

// MergeLinuxPrivilege picks the highest privilege level.
func MergeLinuxPrivilege(current, next string) string {
	if linuxPrivilegeRank(next) > linuxPrivilegeRank(current) {
		return NormalizeLinuxPrivilege(next)
	}
	return NormalizeLinuxPrivilege(current)
}
