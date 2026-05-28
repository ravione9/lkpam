package policy

import (
	"strings"
	"unicode"
)

// ciscoVocabulary lists canonical IOS command keywords used for unambiguous
// prefix expansion (typed abbrev must be a unique prefix of exactly one word).
var ciscoVocabulary = []string{
	"access-list", "archive", "aux", "bfd", "boot", "certificate", "channel-group",
	"class-map", "clear", "clock", "configure", "console", "copy", "crypto",
	"debug", "default", "delete", "description", "disable", "domain", "duplex",
	"enable", "erase", "etherchannel", "exec", "exit", "format", "gateway",
	"hostname", "interface", "ip", "ipv6", "key", "line", "logging", "mode",
	"monitor", "neighbor", "network", "ntp", "password", "ping", "policy-map",
	"port-channel", "prefix-list", "privilege", "redistribute", "reload", "route",
	"route-map", "router", "routing", "running-config", "secret", "service",
	"shutdown", "show", "snmp-server", "spanning-tree", "speed", "startup-config",
	"static", "switchport", "telnet", "terminal", "traceroute", "trunk", "undebug",
	"username", "vlan", "vrf", "vty", "write",
}

// ciscoTokenAlias maps common global abbreviations to canonical tokens.
var ciscoTokenAlias = map[string]string{
	"sh": "show", "sho": "show",
	"en": "enable", "ena": "enable",
	"dis": "disable",
	"conf": "configure", "config": "configure", "con": "configure",
	"cop": "copy",
	"wr": "write", "writ": "write",
	"era": "erase", "er": "erase",
	"rel": "reload", "relo": "reload",
	"del": "delete",
	"cle": "clear", "clr": "clear",
	"pin": "ping", "pi": "ping",
	"tra": "traceroute", "trac": "traceroute",
	"tel": "telnet",
	"log": "logging", "logg": "logging",
	"deb": "debug", "unde": "undebug", "und": "undebug",
	"mon": "monitor",
	"int": "interface", "interf": "interface", "inte": "interface",
	"desc": "description", "descri": "description",
	"shut": "shutdown", "shutd": "shutdown",
	"sw": "switchport", "swi": "switchport", "switchp": "switchport",
	"host": "hostname", "hostn": "hostname",
	"acc": "access-list", "access": "access-list",
	"rout": "router",
	"priv": "privilege",
	"pass": "password",
	"sec": "secret",
	"snmp": "snmp-server",
	"spa": "spanning-tree", "span": "spanning-tree",
	"pol": "policy-map", "policy": "policy-map",
	"class": "class-map",
	"red": "redistribute",
	"nei": "neighbor",
	"net": "network",
	"stat": "static",
	"def": "default",
	"dup": "duplex",
	"spe": "speed",
	"mod": "mode",
	"tru": "trunk",
	"enc": "encapsulation",
	"form": "format",
	"ntp": "ntp",
	"vrf": "vrf",
	"vlan": "vlan",
	"vl": "vlan",
	"ip": "ip",
	"ipv6": "ipv6",
	"crypto": "crypto",
	"cry": "crypto",
	"key": "key",
	"boot": "boot",
	"clock": "clock",
	"service": "service",
	"ser": "service",
	"username": "username", "user": "username",
	"line": "line", "lin": "line",
	"vty": "vty",
	"aux": "aux",
	"exit": "exit", "ex": "exit",
	"end": "end",
	"do": "do",
	"no": "no",
}

// ciscoContextNext maps "parent [grandparent]" → {abbrev: canonical} for the next token.
var ciscoContextNext = map[string]map[string]string{
	"configure": {
		"t": "terminal", "ter": "terminal", "term": "terminal",
		"mem": "memory", "memor": "memory",
	},
	"show": {
		"run": "running-config", "running": "running-config", "ru": "running-config",
		"start": "startup-config", "startup": "startup-config", "sta": "startup-config",
		"ver": "version", "vers": "version", "versi": "version",
		"int": "interface", "interf": "interface", "interfaces": "interfaces",
		"ip": "ip", "vlan": "vlan", "clock": "clock", "log": "logging",
		"span": "spanning-tree", "spanning": "spanning-tree",
		"access": "access-list", "acc": "access-list",
		"route": "route", "route-map": "route-map",
	},
	"copy": {
		"run": "running-config", "running": "running-config",
		"start": "startup-config", "startup": "startup-config",
		"ftp": "ftp", "tftp": "tftp", "scp": "scp",
	},
	"erase": {
		"start": "startup-config", "startup": "startup-config",
	},
	"write": {
		"mem": "memory", "memor": "memory", "eri": "erase", "erase": "erase",
		"term": "terminal", "ter": "terminal",
	},
	"interface": {
		"desc": "description", "descri": "description",
		"shut": "shutdown", "shutd": "shutdown",
		"sw": "switchport", "switchp": "switchport",
	},
	"router": {
		"bgp": "bgp", "ospf": "ospf", "eigrp": "eigrp", "rip": "rip", "isis": "isis",
	},
	"ip": {
		"route": "route", "routing": "routing", "access": "access-list",
		"dhcp": "dhcp", "nat": "nat", "ssh": "ssh", "domain": "domain",
	},
	"line": {
		"vty": "vty", "con": "console", "cons": "console", "console": "console",
		"aux": "aux",
	},
	"snmp-server": {
		"community": "community", "comm": "community", "host": "host",
	},
	"username": {
		"priv": "privilege", "privilege": "privilege",
	},
	"access-list": {},
	"no": {}, // pass-through; children use global rules
}

func expandCiscoTokens(fields []string) []string {
	if len(fields) == 0 {
		return fields
	}
	out := make([]string, 0, len(fields))
	for i, f := range fields {
		prev := out
		if len(prev) > 3 {
			prev = prev[len(prev)-3:]
		}
		out = append(out, expandCiscoToken(f, prev, fields[i+1:]))
	}
	return out
}

func expandCiscoToken(token string, prev []string, rest []string) string {
	raw := token
	token = strings.ToLower(strings.TrimSpace(token))
	if token == "" || isCiscoLiteral(token) {
		return raw
	}

	if canon := ciscoContextExpand(token, prev); canon != "" {
		return canon
	}
	if canon, ok := ciscoTokenAlias[token]; ok {
		return canon
	}
	if len(token) >= 2 {
		if canon := ciscoUniquePrefix(token); canon != "" {
			return canon
		}
	}
	return token
}

func ciscoContextExpand(token string, prev []string) string {
	if len(prev) == 0 {
		return ""
	}
	parent := prev[len(prev)-1]
	if m, ok := ciscoContextNext[parent]; ok {
		if canon, ok := m[token]; ok {
			return canon
		}
	}
	if len(prev) >= 2 {
		key := prev[len(prev)-2] + " " + prev[len(prev)-1]
		if m, ok := ciscoContextNext[key]; ok {
			if canon, ok := m[token]; ok {
				return canon
			}
		}
	}
	return ""
}

func ciscoUniquePrefix(partial string) string {
	var matches []string
	for _, w := range ciscoVocabulary {
		if strings.HasPrefix(w, partial) {
			matches = append(matches, w)
		}
	}
	if len(matches) == 1 {
		return matches[0]
	}
	return ""
}

func isCiscoLiteral(s string) bool {
	if s == "?" || s == "|" {
		return true
	}
	hasDigit := false
	hasAlpha := false
	for _, r := range s {
		switch {
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsLetter(r):
			hasAlpha = true
		}
	}
	// Pure numbers, ranges (0/1), IPs, MACs, ACL numbers
	if hasDigit && !hasAlpha {
		return true
	}
	if strings.ContainsAny(s, "/.:<>") {
		return true
	}
	return false
}
