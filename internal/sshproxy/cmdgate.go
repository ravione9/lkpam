package sshproxy

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/example/pam-platform/internal/policy"
)

// cmdGate evaluates command policy by mirroring the device's visible line.
type cmdGate struct {
	up, down    io.Writer
	allow, deny []string
	onDeny      func(cmd string)
	onSessionEnd func()

	enableSecret   string // privileged-account / enable secret from vault
	portalPassword string // passthrough password (includes MFA OTP when enrolled)

	mu                  sync.Mutex
	devLine             []byte
	ignoreLine          bool
	skipNextLF          bool
	expectEnablePass    bool
	injectEnableOnEnter bool
	execPrivileged      bool // true when last prompt ended with #
	enableMaskLen       int
}

func newCmdGate(up, down io.Writer, allow, deny []string, onDeny func(cmd string), enableSecret, portalPassword string, onSessionEnd func()) *cmdGate {
	if len(allow) == 0 && len(deny) == 0 && enableSecret == "" && portalPassword == "" && onSessionEnd == nil {
		return nil
	}
	return &cmdGate{
		up: up, down: down, allow: allow, deny: deny, onDeny: onDeny, onSessionEnd: onSessionEnd,
		enableSecret:   strings.TrimSpace(enableSecret),
		portalPassword: portalPassword,
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

func isSessionEndCommand(cmd string) bool {
	switch policy.NormalizeCLI(cmd) {
	case "logout", "logoff", "quit", "disconnect":
		return true
	default:
		return false
	}
}

func (g *cmdGate) credentialForEnable() string {
	if g.enableSecret != "" {
		return g.enableSecret
	}
	return g.portalPassword
}

func (g *cmdGate) noteOutput(p []byte) {
	var autoInject bool
	g.mu.Lock()
	defer func() {
		g.mu.Unlock()
		if autoInject {
			g.tryAutoInjectEnable()
		}
	}()
	for _, b := range p {
		switch b {
		case '\r', '\n':
			trim := strings.TrimSpace(strings.ToLower(string(g.devLine)))
			if strings.HasSuffix(trim, "#") {
				g.execPrivileged = true
			} else if strings.HasSuffix(trim, ">") {
				g.execPrivileged = false
			}
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
		if g.expectEnablePass && g.credentialForEnable() != "" && !g.injectEnableOnEnter {
			g.injectEnableOnEnter = true
			autoInject = true
		}
	}
}

// tryAutoInjectEnable sends the enable secret upstream and shows only asterisks
// to the user. SSH clients often echo keystrokes locally while we wait for Enter;
// injecting on prompt avoids visible typing and clears the Password: line.
func (g *cmdGate) tryAutoInjectEnable() {
	g.mu.Lock()
	if !g.injectEnableOnEnter {
		g.mu.Unlock()
		return
	}
	secret := g.credentialForEnable()
	g.injectEnableOnEnter = false
	g.expectEnablePass = false
	g.ignoreLine = true
	g.mu.Unlock()
	if secret == "" {
		return
	}
	g.mu.Lock()
	g.enableMaskLen = len(secret)
	g.mu.Unlock()
	// Inject only upstream — do not synthesize a Password line on the user terminal
	// (avoids duplicate Password: lines in browser/guacd viewers).
	_, _ = g.up.Write([]byte(secret + "\r"))
}

func (g *cmdGate) waitingForEnablePassword() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	secret := g.credentialForEnable()
	return secret != "" && (g.expectEnablePass || g.injectEnableOnEnter)
}

// filterDownstream redacts enable/passthrough secrets echoed by the device or client.
func (g *cmdGate) filterDownstream(p []byte) []byte {
	if len(p) == 0 {
		return p
	}
	g.mu.Lock()
	secrets := []string{strings.TrimSpace(g.enableSecret), strings.TrimSpace(g.portalPassword)}
	maskLen := g.enableMaskLen
	g.mu.Unlock()
	if maskLen <= 0 && len(secrets) > 0 {
		maskLen = len(secrets[0])
	}
	out := string(p)
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(out, secret) {
			out = strings.ReplaceAll(out, secret, strings.Repeat("*", len(secret)))
		}
	}
	return []byte(maskPasswordPromptLines(out, maskLen))
}

func maskPasswordPromptLines(s string, maskLen int) string {
	if maskLen <= 0 {
		maskLen = 12
	}
	stars := strings.Repeat("*", maskLen)
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, kw := range []string{"password:", "passphrase:", "secret:"} {
			idx := strings.Index(lower, kw)
			if idx < 0 {
				continue
			}
			rest := strings.TrimSpace(line[idx+len(kw):])
			if rest == "" || rest == stars || strings.Trim(rest, "*") == "" {
				continue
			}
			line = line[:idx] + line[idx:idx+len(kw)] + " " + stars
			break
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
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

func (g *cmdGate) shouldEndSession(cmd string) bool {
	switch policy.NormalizeCLI(cmd) {
	case "logout", "logoff", "quit", "disconnect":
		return true
	case "exit":
		g.mu.Lock()
		priv := g.execPrivileged
		g.mu.Unlock()
		return !priv
	default:
		return false
	}
}

func (g *cmdGate) scheduleSessionEnd() {
	if g.onSessionEnd == nil {
		return
	}
	go func() {
		time.Sleep(400 * time.Millisecond)
		g.onSessionEnd()
	}()
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

func (g *cmdGate) handlePasswordKeystroke(b byte) bool {
	if !g.waitingForEnablePassword() {
		return false
	}
	secret := g.credentialForEnable()
	if b == '\r' || b == '\n' {
		if b == '\n' && g.skipNextLF {
			g.skipNextLF = false
			return true
		}
		if b == '\r' {
			g.skipNextLF = true
		}
		g.mu.Lock()
		g.injectEnableOnEnter = false
		g.expectEnablePass = false
		g.ignoreLine = true
		g.enableMaskLen = len(secret)
		g.mu.Unlock()
		_, _ = g.up.Write([]byte(secret))
		if b == '\r' {
			_, _ = g.up.Write([]byte{'\r'})
		} else {
			_, _ = g.up.Write([]byte{'\n'})
		}
		return true
	}
	// Swallow printable keys so the enable secret is never shown while typing.
	return true
}

func (g *cmdGate) handleLineEnd(endByte byte) {
	g.mu.Lock()
	ignore := g.ignoreLine
	if ignore {
		g.ignoreLine = false
	}
	inject := g.injectEnableOnEnter && g.credentialForEnable() != ""
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
	if cmd != "" && isEnableCommand(cmd) && g.credentialForEnable() != "" {
		g.mu.Lock()
		g.expectEnablePass = true
		g.mu.Unlock()
	}
	if cmd != "" && g.shouldEndSession(cmd) {
		_, _ = g.up.Write([]byte{endByte})
		g.scheduleSessionEnd()
		return
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
		p = w.gate.filterDownstream(p)
	}
	return w.w.Write(p)
}
