package rdpproxy

import (
	"context"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
)

// discoverSSHProxyAddr picks an address guacd can use to reach the PAM SSH proxy.
// guacd normally runs with Docker host networking, so it cannot resolve bridge-only
// names like "ssh-proxy". Probes run from rdp-proxy; explicit PAM_SSH_PROXY_DIAL_ADDR
// is always honored (use 127.0.0.1:2222 on Linux when ssh-proxy publishes port 2222).
func discoverSSHProxyAddr(configured string) (host string, port int) {
	configured = strings.TrimSpace(configured)
	if configured != "" {
		h, p := splitHostPort(configured, 2222)
		if h != "" {
			log.Printf("rdp-proxy: guacd SSH upstream (PAM_SSH_PROXY_DIAL_ADDR) %s:%d", h, p)
			return h, p
		}
	}

	seen := map[string]struct{}{}
	candidates := []string{
		"host.docker.internal:2222",
		"127.0.0.1:2222",
		"ssh-proxy:2222",
		"pam-ssh-proxy:2222",
	}

	for _, addr := range candidates {
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		h, p := splitHostPort(addr, 2222)
		if tcpOpen(h, p) {
			// guacd uses host network on Linux — it cannot resolve bridge DNS names.
			// ssh-proxy publishes 2222 on the host, so loopback is always correct here.
			if h == "ssh-proxy" || h == "pam-ssh-proxy" {
				log.Printf("rdp-proxy: guacd SSH upstream probe OK at %s:%d (guacd dials 127.0.0.1:%d)", h, p, p)
				return "127.0.0.1", p
			}
			log.Printf("rdp-proxy: guacd SSH upstream probe OK at %s:%d", h, p)
			return h, p
		}
	}
	h, p := "127.0.0.1", 2222
	log.Printf("rdp-proxy: WARNING no SSH proxy TCP probe succeeded; guacd will use %s:%d (set PAM_SSH_PROXY_DIAL_ADDR)", h, p)
	return h, p
}

func tcpOpen(host string, port int) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
