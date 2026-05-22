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

	enableSecret string // privileged-account password (Cisco enable secret in vault)

	mu                  sync.Mutex
	devLine             []byte
	ignoreLine          bool
	skipNextLF          bool
	expectEnablePass    bool // set after user runs enable/en
	injectEnableOnEnter bool
}

func newCmdGate(up, down io.Writer, allow, deny []string, onDeny func(cmd string), enableSecret string) *cmdGate {
	if len(allow) == 0 && len(deny) == 0 && enableSecret == "" {
		return nil
	}
	return &cmdGate{
		up: up, down: down, allow: allow, deny: deny, onDeny: onDeny,
		enableSecret: strings.TrimSpace(enableSecret),
	}
}

func isEnableCommand(cmd string) bool {
	switch policy.NormalizeCLI(cmd) {
	case "enable", "en":
		return true
	default:
		return false
	}
}

// noteOutput updates the visible-line mirror from device output.
func (g *cmdGate) noteOutput(p []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, b := range p {
		switch b {
		case '\r', '\n':
			g.devLine = g.devLine[:0]
		case 0x08, 0x7f:
			if len(g.devLine) > 0 {
				g.devLine = g.devLine[:len(g.devLine)-1]
			}
		case 0x03:
			g.devLine = g.devLine[:0]
		default:
			if b >= 0x20 && b < 0x7f {
				g.devLine = append(g.devLine, b)
			}
		}
	}
	trim := strings.TrimSpace(strings.ToLower(string(g.devLine)))
	if strings.Contains(trim, "password:") ||
		strings.Contains(trim, "passphrase:") ||
		strings.Contains(trim, "secret:") {
		g.ignoreLine = true
		if g.expectEnablePass && g.enableSecret != "" {
			g.injectEnableOnEnter = true
		}
	}
}

func (g *cmdGate) resetLineMirror() {
	g.mu.Lock()
	g.devLine = g.devLine[:0]
	g.ignoreLine = false
	g.injectEnableOnEnter = false
	g.mu.Unlock()
}

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
		if g.handlePasswordKeystroke(b) {
			continue
		}
		switch b {
		case '\n':
			if g.skipNextLF {
				g.skipNextLF = false
				continue
			}
			g.handleLineEnd(b)
		case '\r':
			g.skipNextLF = true
			g.handleLineEnd(b)
		default:
			_, _ = g.up.Write([]byte{b})
		}
	}
	return n, nil
}

// handlePasswordKeystroke swallows user input when injecting the enable secret.
func (g *cmdGate) handlePasswordKeystroke(b byte) bool {
	g.mu.Lock()
	inject := g.injectEnableOnEnter && g.enableSecret != ""
	g.mu.Unlock()
	if !inject {
		return false
	}
	if b == '\r' || b == '\n' {
		if b == '\n' && g.skipNextLF {
			g.skipNextLF = false
			return true
		}
		if b == '\r' {
			g.skipNextLF = true
		}
		g.mu.Lock()
		secret := g.enableSecret
		g.injectEnableOnEnter = false
		g.expectEnablePass = false
		g.ignoreLine = false
		g.mu.Unlock()
		_, _ = g.up.Write([]byte(secret))
		if b == '\r' {
			_, _ = g.up.Write([]byte{'\r'})
		} else {
			_, _ = g.up.Write([]byte{'\n'})
		}
		return true
	}
	// Swallow typed password characters (device may still echo via downstream).
	return true
}

func (g *cmdGate) handleLineEnd(endByte byte) {
	g.mu.Lock()
	ignore := g.ignoreLine
	if ignore {
		g.ignoreLine = false
	}
	inject := g.injectEnableOnEnter && g.enableSecret != ""
	cmd := g.currentCommand()
	g.mu.Unlock()

	if inject {
		return
	}
	if ignore {
		_, _ = g.up.Write([]byte{endByte})
		return
	}
	if cmd != "" && !policy.CommandAllowed(cmd, g.allow, g.deny) {
		g.resetLineMirror()
		_, _ = g.up.Write([]byte{0x03})
		_, _ = g.down.Write([]byte(fmt.Sprintf(
			"\r\nPAM: command denied by policy: %s\r\n", cmd)))
		if g.onDeny != nil {
			g.onDeny(cmd)
		}
		return
	}
	if cmd != "" && isEnableCommand(cmd) && g.enableSecret != "" {
		g.mu.Lock()
		g.expectEnablePass = true
		g.mu.Unlock()
	}
	_, _ = g.up.Write([]byte{endByte})
}

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
