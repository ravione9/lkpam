package sshproxy

import "github.com/example/pam-platform/internal/cryptox"

// cryptoxVerify is a small indirection so the proxy can use cryptox without
// circular dependencies if we later split it.
func cryptoxVerify(pw, encoded string) bool { return cryptox.VerifyPassword(pw, encoded) }
