# Example OPA policy bundle — drop in if you swap the reference policy
# engine for Open Policy Agent. The policy-service Decide() function would
# call `opa eval` (or embed github.com/open-policy-agent/opa/rego).
#
# Convention:
#   input = {
#     "user":   {"id": 42, "role": "netops", "groups": ["netops"]},
#     "target": {"name": "core-sw-01", "kind": "cisco", "tier": 1},
#     "action": "ssh",
#     "time":   "2026-05-11T14:30:00Z"
#   }
package pam.access

default allow := false
default require_approval := false

# admins can reach anything
allow if input.user.role == "admin"

# netops can reach cisco/arista/juniper at tier >= 1
allow if {
  input.user.role == "netops"
  input.target.kind in {"cisco", "arista", "juniper"}
  input.target.tier >= 1
}

# secops can reach palo/forti
allow if {
  input.user.role == "secops"
  input.target.kind in {"palo", "forti"}
  input.target.tier >= 1
}

# tier-0 (crown-jewel) targets always require approval
require_approval if input.target.tier == 0

# After-hours access requires approval
require_approval if {
  hour := time.parse_rfc3339_ns(input.time) / 1000000000 / 3600 % 24
  hour < 9
}
require_approval if {
  hour := time.parse_rfc3339_ns(input.time) / 1000000000 / 3600 % 24
  hour >= 19
}

# Dangerous commands always denied — even for admins
denied_commands := [
  "reload",
  "erase startup-config",
  "write erase",
  "format",
  "delete /force /recursive flash:",
  "request system zeroize",
  "rm -rf /",
]
