package rdpproxy

import (
	"os"
	"strings"
)

// resolveRDPReachableHost maps portal target hostnames to an address reachable from
// the guacd container (e.g. localhost → host.docker.internal on Docker Desktop).
func resolveRDPReachableHost(host string) string {
	h := strings.TrimSpace(host)
	if h == "" {
		return h
	}
	lower := strings.ToLower(h)
	switch lower {
	case "localhost", "127.0.0.1", "::1", "0.0.0.0":
		if alias := strings.TrimSpace(os.Getenv("PAM_RDP_DOCKER_HOST")); alias != "" {
			return alias
		}
		return "host.docker.internal"
	default:
		return h
	}
}

func normalizeRDPPort(port int) int {
	if port <= 0 {
		return 3389
	}
	return port
}
