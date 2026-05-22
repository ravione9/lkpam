package sshlaunch

import "strings"

// TargetSSHRef returns the @target suffix used by PuTTY/Terminal in the portal
// (host slug, then target name slug, else #id).
func TargetSSHRef(host, name string, targetID int64) string {
	if sl := sshTargetSlug(host); sl != "" {
		return sl
	}
	if sl := sshTargetSlug(name); sl != "" {
		return sl
	}
	return TargetRef(targetID)
}

func sshTargetSlug(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	for _, r := range s {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') ||
			r == '.' || r == '_' || r == '-' {
			continue
		}
		return ""
	}
	return s
}
