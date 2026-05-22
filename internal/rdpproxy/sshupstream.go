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
// Probes from the rdp-proxy container (same Docker network as guacd in normal deploy).
func discoverSSHProxyAddr(configured string) (host string, port int) {
	seen := map[string]struct{}{}
	var candidates []string
	if strings.TrimSpace(configured) != "" {
		candidates = append(candidates, strings.TrimSpace(configured))
	}
	candidates = append(candidates,
		"ssh-proxy:2222",
		"pam-ssh-proxy:2222",
		"host.docker.internal:2222",
	)

	for _, addr := range candidates {
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		h, p := splitHostPort(addr, 2222)
		if h == "localhost" || h == "127.0.0.1" || h == "::1" {
			continue
		}
		if tcpOpen(h, p) {
			log.Printf("rdp-proxy: guacd SSH upstream probe OK at %s:%d", h, p)
			return h, p
		}
	}
	h, p := sshProxyAddrForGuacd(configured)
	log.Printf("rdp-proxy: WARNING no SSH proxy TCP probe succeeded; guacd will use %s:%d (check guacd + ssh-proxy on pam-net)", h, p)
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
