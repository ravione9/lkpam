package sshproxy

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/example/pam-platform/internal/policy"
)

// cmdGate forwards keystrokes immediately (so the device can echo them) and
// evaluates the completed line when the user presses Enter.
type cmdGate struct {
	up, down    io.Writer
	allow, deny []string
	mu          sync.Mutex
	buf         []byte
	ignoreLine  bool // skip policy check for enable/login password prompts
	outTail     string
}

func newCmdGate(up, down io.Writer, allow, deny []string) *cmdGate {
	if len(allow) == 0 && len(deny) == 0 {
		return nil
	}
	return &cmdGate{up: up, down: down, allow: allow, deny: deny}
}

// noteOutput watches device output for password prompts so the next line is
// not mistaken for a CLI command (e.g. after "enable" on Cisco IOS).
func (g *cmdGate) noteOutput(p []byte) {
	if len(p) == 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.outTail += strings.ToLower(string(p))
	if len(g.outTail) > 256 {
		g.outTail = g.outTail[len(g.outTail)-256:]
	}
	if strings.Contains(g.outTail, "password:") ||
		strings.Contains(g.outTail, "passphrase:") ||
		strings.Contains(g.outTail, "secret:") {
		g.ignoreLine = true
	}
}

func (g *cmdGate) Write(p []byte) (int, error) {
	n := len(p)
	for _, b := range p {
		switch b {
		case 0x7f, 0x08: // backspace / delete
			g.mu.Lock()
			if len(g.buf) > 0 {
				g.buf = g.buf[:len(g.buf)-1]
			}
			g.mu.Unlock()
			_, _ = g.up.Write([]byte{b})
		case 0x15: // Ctrl+U — clear line on many CLIs
			g.mu.Lock()
			g.buf = g.buf[:0]
			g.mu.Unlock()
			_, _ = g.up.Write([]byte{b})
		case '\n', '\r':
			g.mu.Lock()
			ignore := g.ignoreLine
			if ignore {
				g.ignoreLine = false
			}
			line := strings.TrimSpace(string(g.buf))
			g.buf = g.buf[:0]
			g.mu.Unlock()

			if ignore {
				_, _ = g.up.Write([]byte{b})
				continue
			}
			if line != "" && !policy.CommandAllowed(line, g.allow, g.deny) {
				_, _ = g.up.Write([]byte{0x03}) // ^C — cancel buffered line on device
				msg := fmt.Sprintf("\r\nPAM: command denied by policy: %s\r\n", line)
				_, _ = g.down.Write([]byte(msg))
				continue
			}
			_, _ = g.up.Write([]byte{b})
		default:
			g.mu.Lock()
			g.buf = append(g.buf, b)
			g.mu.Unlock()
			_, _ = g.up.Write([]byte{b})
		}
	}
	return n, nil
}

// gateAwareWriter passes device output to the client and notifies cmdGate.
type gateAwareWriter struct {
	gate *cmdGate
	w    io.Writer
}

func (w *gateAwareWriter) Write(p []byte) (int, error) {
	if w.gate != nil {
		w.gate.noteOutput(p)
	}
	return w.w.Write(p)
}
