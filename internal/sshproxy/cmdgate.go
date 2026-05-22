package sshproxy

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

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
	enableInjected      bool // true after we sent the secret for this enable attempt
	lastEnableInject    time.Time

	// Downstream password masker — survives byte-by-byte writes from upCh→downCh.
	downBuf       []byte // sliding window used to detect "password:" across chunks
	downMasking   bool   // true: mask printable bytes until newline
	downSawColon  bool   // saw colon after keyword; mask everything except spaces
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

func (g *cmdGate) resetEnableFlow() {
	g.expectEnablePass = false
	g.injectEnableOnEnter = false
	g.enableInjected = false
	g.enableMaskLen = 0
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
				g.resetEnableFlow()
			} else if strings.HasSuffix(trim, ">") {
				g.execPrivileged = false
				if g.expectEnablePass {
					g.resetEnableFlow()
				}
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
		// Auto-inject once per enable (first Password: prompt only).
		if g.expectEnablePass && g.credentialForEnable() != "" && !g.enableInjected {
			g.injectEnableOnEnter = true
			autoInject = true
		}
	}
}

// tryAutoInjectEnable sends the enable secret upstream once. Never synthesize
// Password lines on the user terminal — that duplicated prompts (see audit screenshots).
func (g *cmdGate) tryAutoInjectEnable() {
	g.mu.Lock()
	if !g.injectEnableOnEnter {
		g.mu.Unlock()
		return
	}
	g.injectEnableOnEnter = false
	g.mu.Unlock()
	g.sendEnableSecret(false)
}

func (g *cmdGate) sendEnableSecret(force bool) {
	g.mu.Lock()
	if g.execPrivileged {
		g.mu.Unlock()
		return
	}
	secret := g.credentialForEnable()
	if secret == "" {
		g.mu.Unlock()
		return
	}
	if !force {
		if g.enableInjected {
			g.mu.Unlock()
			return
		}
		if time.Since(g.lastEnableInject) < 800*time.Millisecond {
			g.mu.Unlock()
			return
		}
	}
	g.enableInjected = true
	g.lastEnableInject = time.Now()
	g.enableMaskLen = len(secret)
	g.ignoreLine = true
	g.mu.Unlock()
	_, _ = g.up.Write([]byte(secret + "\r"))
}

func (g *cmdGate) waitingForEnablePassword() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	secret := g.credentialForEnable()
	if secret == "" || g.execPrivileged {
		return false
	}
	return g.expectEnablePass
}

// filterDownstream redacts enable/passthrough secrets echoed by the device or client.
// It runs in two passes:
//  1. Whole-string replacement for known secrets (handles single-chunk echoes).
//  2. Streaming state machine that masks anything after "Password:"/"Secret:"/"Passphrase:"
//     until end of line — survives byte-by-byte writes where step 1 cannot match.
func (g *cmdGate) filterDownstream(p []byte) []byte {
	if len(p) == 0 {
		return p
	}
	g.mu.Lock()
	secrets := []string{strings.TrimSpace(g.enableSecret), strings.TrimSpace(g.portalPassword)}
	g.mu.Unlock()
	out := string(p)
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		out = strings.ReplaceAll(out, secret, strings.Repeat("*", len(secret)))
	}
	return g.streamMaskPassword([]byte(out))
}

// streamMaskPassword maintains a sliding window across writes so a password
// streamed one byte at a time still gets replaced with asterisks.
func (g *cmdGate) streamMaskPassword(p []byte) []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]byte, 0, len(p))
	for _, b := range p {
		if g.downMasking {
			switch {
			case b == '\r' || b == '\n':
				out = append(out, b)
				g.downMasking = false
				g.downSawColon = false
				g.downBuf = g.downBuf[:0]
			case b == ' ' || b == '\t':
				out = append(out, b)
			case b >= 0x20 && b < 0x7f:
				out = append(out, '*')
				g.downSawColon = true
			default:
				out = append(out, b)
			}
			continue
		}
		out = append(out, b)
		g.downBuf = append(g.downBuf, b)
		if len(g.downBuf) > 16 {
			g.downBuf = g.downBuf[len(g.downBuf)-16:]
		}
		if b == '\r' || b == '\n' {
			g.downBuf = g.downBuf[:0]
			continue
		}
		lower := strings.ToLower(string(g.downBuf))
		if strings.HasSuffix(lower, "password:") ||
			strings.HasSuffix(lower, "passphrase:") ||
			strings.HasSuffix(lower, "secret:") {
			g.downMasking = true
			g.downSawColon = false
		}
	}
	return out
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

func (g *cmdGate) containsEnableSecret(p []byte) bool {
	secret := g.credentialForEnable()
	return secret != "" && strings.Contains(string(p), secret)
}

func (g *cmdGate) Write(p []byte) (int, error) {
	n := len(p)
	g.mu.Lock()
	privileged := g.execPrivileged
	g.mu.Unlock()
	if privileged && g.containsEnableSecret(p) {
		_, _ = g.down.Write([]byte(
			"\r\nPAM: enable password is sent automatically after en — do not type or paste it.\r\n"))
		return n, nil
	}

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
	if b == '\r' || b == '\n' {
		if b == '\n' && g.skipNextLF {
			g.skipNextLF = false
			return true
		}
		if b == '\r' {
			g.skipNextLF = true
		}
		// Enter at Password: retry after a failed attempt (debounced inside sendEnableSecret).
		g.sendEnableSecret(true)
		return true
	}
	// Swallow printable keys during Password: so the secret is never typed in the browser.
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
		g.enableInjected = false
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
