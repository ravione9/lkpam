package sshproxy

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/example/pam-platform/internal/policy"
)

// cmdGate evaluates command policy by mirroring the device's visible line.
// It does NOT buffer user keystrokes (so device-side echo, Tab-completion,
// arrow history, paste, and abbreviations all behave normally). When the user
// presses Enter, we look at what the device has on the current line and run
// policy against that. Denied lines are cancelled before Enter is forwarded.
type cmdGate struct {
	up, down    io.Writer
	allow, deny []string
	onDeny      func(cmd string)

	mu         sync.Mutex
	devLine    []byte // visible characters of the device's current line
	ignoreLine bool   // suppress policy check (e.g. after a password prompt)
}

func newCmdGate(up, down io.Writer, allow, deny []string, onDeny func(cmd string)) *cmdGate {
	if len(allow) == 0 && len(deny) == 0 {
		return nil
	}
	return &cmdGate{up: up, down: down, allow: allow, deny: deny, onDeny: onDeny}
}

// noteOutput updates the visible-line mirror from device output.
func (g *cmdGate) noteOutput(p []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, b := range p {
		switch b {
		case '\r', '\n':
			g.devLine = g.devLine[:0]
		case 0x08, 0x7f: // backspace, DEL
			if len(g.devLine) > 0 {
				g.devLine = g.devLine[:len(g.devLine)-1]
			}
		default:
			if b >= 0x20 && b < 0x7f {
				g.devLine = append(g.devLine, b)
			}
		}
	}
	trim := strings.TrimSpace(strings.ToLower(string(g.devLine)))
	if strings.HasSuffix(trim, "password:") ||
		strings.HasSuffix(trim, "passphrase:") ||
		strings.HasSuffix(trim, "secret:") {
		g.ignoreLine = true
	}
}

// currentCommand returns the user-typed portion of the current visible line
// by stripping the device prompt (everything up to the last #, >, or $).
func (g *cmdGate) currentCommand() string {
	line := string(g.devLine)
	if i := strings.LastIndexAny(line, "#>$"); i >= 0 {
		line = line[i+1:]
	}
	return strings.TrimSpace(line)
}

func (g *cmdGate) Write(p []byte) (int, error) {
	n := len(p)
	for _, b := range p {
		switch b {
		case '\n', '\r':
			g.mu.Lock()
			ignore := g.ignoreLine
			if ignore {
				g.ignoreLine = false
			}
			cmd := g.currentCommand()
			g.mu.Unlock()

			if ignore {
				_, _ = g.up.Write([]byte{b})
				continue
			}
			if cmd != "" && !policy.CommandAllowed(cmd, g.allow, g.deny) {
				_, _ = g.up.Write([]byte{0x15})
				_, _ = g.down.Write([]byte(fmt.Sprintf(
					"\r\nPAM: command denied by policy: %s\r\n", cmd)))
				if g.onDeny != nil {
					g.onDeny(cmd)
				}
				continue
			}
			_, _ = g.up.Write([]byte{b})
		default:
			_, _ = g.up.Write([]byte{b})
		}
	}
	return n, nil
}

// gateAwareWriter forwards device output to the user and feeds the cmdGate.
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
