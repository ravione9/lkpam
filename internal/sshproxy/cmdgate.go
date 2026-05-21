package sshproxy

import (
	"fmt"
	"io"
	"strings"

	"github.com/example/pam-platform/internal/policy"
)

// cmdGate buffers user keystrokes until Enter and blocks lines denied by policy.
type cmdGate struct {
	up, down    io.Writer
	allow, deny []string
	buf         []byte
}

func newCmdGate(up, down io.Writer, allow, deny []string) *cmdGate {
	if len(allow) == 0 && len(deny) == 0 {
		return nil
	}
	return &cmdGate{up: up, down: down, allow: allow, deny: deny}
}

func (g *cmdGate) Write(p []byte) (int, error) {
	n := len(p)
	for _, b := range p {
		if b == '\n' || b == '\r' {
			line := strings.TrimSpace(string(g.buf))
			pending := append([]byte(nil), g.buf...)
			g.buf = g.buf[:0]
			if line != "" && !policy.CommandAllowed(line, g.allow, g.deny) {
				msg := fmt.Sprintf("\r\nPAM: command denied by policy: %s\r\n", line)
				_, _ = g.down.Write([]byte(msg))
				continue
			}
			if len(pending) > 0 {
				_, _ = g.up.Write(pending)
			}
			_, _ = g.up.Write([]byte{b})
			continue
		}
		g.buf = append(g.buf, b)
	}
	return n, nil
}
