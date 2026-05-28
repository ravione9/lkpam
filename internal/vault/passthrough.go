package vault

import "strconv"

// UserPassthroughKey is the vault key for a user's cached portal password
// (encrypted). Used for browser SSH and FortiGate web TACACS login so users
// are not re-prompted after signing in to the portal.
func UserPassthroughKey(uid int64) string {
	return "_user_passthrough_pw_" + strconv.FormatInt(uid, 10)
}
