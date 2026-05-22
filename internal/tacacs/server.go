package tacacs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/authclient"
	"github.com/example/pam-platform/internal/cryptox"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/mfa"
	"github.com/example/pam-platform/internal/policy"
)

// Server speaks TACACS+ over TCP/49.
type Server struct {
	Addr   string
	Secret []byte // shared secret with every device (use per-device in prod)
	DB     *db.DB
	Policy *policy.Engine
	Groups *groups.Service
	Bus    events.Publisher
	// Auth, when set, delegates AAA password checks to auth-service so AD/LDAP
	// users authenticate the same way they do everywhere else. Falls back to
	// the local password hash check when nil.
	Auth *authclient.Client
}

// Run starts the TCP listener and blocks until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("tacacs: listen: %w", err)
	}
	log.Printf("tacacs+ listening on %s", s.Addr)
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("tacacs accept: %v", err)
			continue
		}
		go s.serve(ctx, c)
	}
}

func (s *Server) serve(ctx context.Context, c net.Conn) {
	defer c.Close()
	clientIP := c.RemoteAddr().String()
	for {
		h, err := ReadHeader(c)
		if err != nil {
			return
		}
		body, err := ReadBody(c, h, s.Secret)
		if err != nil {
			log.Printf("tacacs body: %v", err)
			return
		}
		switch h.Type {
		case TypeAuthentication:
			s.handleAuthen(c, h, body, clientIP)
		case TypeAuthorization:
			s.handleAuthor(c, h, body, clientIP)
		case TypeAccounting:
			s.handleAcct(c, h, body, clientIP)
		default:
			log.Printf("tacacs: unsupported type 0x%x from %s", h.Type, clientIP)
			return
		}
	}
}

// ---- Authentication ----

func (s *Server) handleAuthen(c net.Conn, h Header, body []byte, clientIP string) {
	start, err := ParseAuthenStart(body)
	if err != nil {
		log.Printf("tacacs authen parse: %v", err)
		return
	}

	pass := passwordFromAuthenStart(start)
	if pass != "" {
		s.verifyAndReply(c, h, start.User, pass, clientIP)
		return
	}

	// ASCII login: prompt for password, then validate on CONTINUE.
	reply := AuthenReply{Status: AuthenStatusGetPass, ServerMsg: "Password: "}
	h.SeqNo++
	_ = WritePacket(c, h, reply.Bytes(), s.Secret)

	h2, err := ReadHeader(c)
	if err != nil {
		return
	}
	body2, err := ReadBody(c, h2, s.Secret)
	if err != nil {
		return
	}
	cont, err := ParseAuthenContinue(body2)
	if err != nil {
		log.Printf("tacacs continue parse: %v", err)
		return
	}
	s.verifyAndReply(c, h2, start.User, cont.UserMsg, clientIP)
}

// passwordFromAuthenStart extracts the password from PAP/SENDAUTH or ASCII START bodies.
func passwordFromAuthenStart(start *AuthenStart) string {
	if len(start.Data) == 0 {
		return ""
	}
	// PAP and SENDAUTH carry the password in Data (RFC 8907 §5.1).
	if start.AuthenType == AuthenTypePAP || start.Action == AuthenActionSendAuth {
		return string(start.Data)
	}
	// Some clients embed the password in Data for ASCII login too.
	if start.Action == AuthenActionLogin && len(start.Data) > 0 {
		return string(start.Data)
	}
	return ""
}

func (s *Server) verifyAndReply(c net.Conn, h Header, user, pass, clientIP string) {
	h.SeqNo++ // REPLY seq_no must be request seq_no + 1 (RFC 8907 §4.4)
	ok := s.checkPassword(user, pass)
	status := AuthenStatusFail
	msg := "auth failed"
	if ok {
		status = AuthenStatusPass
		msg = "ok"
	} else {
		log.Printf("tacacs authen failed user=%q from %s", user, clientIP)
	}
	s.Bus.Publish(events.Event{
		Source: "tacacs", Kind: "authen", Severity: severity(ok),
		Actor: user, Target: clientIP,
		Detail: map[string]string{"result": msg},
	})
	rep := AuthenReply{Status: status, ServerMsg: msg}
	_ = WritePacket(c, h, rep.Bytes(), s.Secret)
}

func (s *Server) checkPassword(user, pass string) bool {
	user = strings.TrimSpace(user)
	if user == "" || pass == "" {
		return false
	}
	pw, otp := mfa.SplitAppendedOTP(pass)
	if s.Auth != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		res, err := s.Auth.Login(ctx, user, pw, otp, true)
		if err == nil && res != nil && res.User != nil {
			return true
		}
		if err != nil {
			log.Printf("tacacs auth-service login for %q: %v", user, err)
		}
		if res != nil && res.MFARequired {
			log.Printf("tacacs auth-service login for %q: MFA required (append 6-digit code to password)", user)
		}
		return false
	}
	var hash string
	err := s.DB.QueryRow(`
		SELECT password_hash FROM users
		WHERE lower(username)=lower(?) AND disabled=0`, user).Scan(&hash)
	if err != nil || hash == "" {
		return false
	}
	return cryptox.VerifyPassword(pass, hash)
}

// ---- Authorization (per-command) ----

func (s *Server) handleAuthor(c net.Conn, h Header, body []byte, clientIP string) {
	req, err := ParseAuthorRequest(body)
	if err != nil {
		log.Printf("tacacs author parse: %v", err)
		return
	}

	cmd, args := extractCommand(req.Args)
	svc := extractArg(req.Args, "service")
	fullCmd := policy.FullCommand(cmd, args)
	deviceIP := deviceIPFromAuthor(req, clientIP)
	var allow bool
	var role string
	var replyArgs []string

	if fullCmd == "" && isAdminAuthService(svc) {
		// FortiGate / firewall admin login — not per-command authorization.
		allow, role = s.authorizeAdmin(req.User)
		if allow {
			replyArgs = []string{"priv-lvl=15", "service=" + svc}
		}
	} else {
		allow, role = s.authorize(req.User, deviceIP, fullCmd)
	}

	status := AuthorStatusFail
	if allow {
		status = AuthorStatusPassAdd
	}
	log.Printf("tacacs author user=%q nas=%q rem_addr=%q svc=%q cmd=%q allow=%v role=%q",
		req.User, deviceIP, strings.TrimSpace(req.RemAddr), svc, fullCmd, allow, role)
	s.Bus.Publish(events.Event{
		Source: "tacacs", Kind: "authorize", Severity: severity(allow),
		Actor: req.User, Target: deviceIP,
		Detail: map[string]string{
			"cmd":      fullCmd,
			"role":     role,
			"service":  svc,
			"rem_addr": strings.TrimSpace(req.RemAddr),
		},
	})

	h.SeqNo++
	rep := AuthorReply{
		Status:    status,
		Args:      replyArgs,
		ServerMsg: ternary(allow, "ok", "denied by PAM policy"),
	}
	_ = WritePacket(c, h, rep.Bytes(), s.Secret)
}

func (s *Server) authorizeAdmin(user string) (bool, string) {
	var role string
	var disabled int
	err := s.DB.QueryRow(`
		SELECT role, disabled FROM users WHERE lower(username)=lower(?)`, user).
		Scan(&role, &disabled)
	if err != nil || disabled != 0 {
		return false, ""
	}
	return true, role
}

func (s *Server) authorize(user, deviceIP, fullCmd string) (bool, string) {
	var (
		userID int64
		role   string
	)
	err := s.DB.QueryRow(`
		SELECT id, role FROM users WHERE lower(username)=lower(?) AND disabled = 0`, user).
		Scan(&userID, &role)
	if err != nil {
		return false, ""
	}
	roles := []string{role}
	if s.Groups != nil && userID > 0 {
		if eff, err := s.Groups.EffectiveRoles(context.Background(), userID, role); err == nil && len(eff) > 0 {
			roles = eff
		}
	}
	// Map the device IP to a target row to pull its kind/tier.
	var (
		tid  int64
		kind string
		tier int
	)
	host := hostPart(deviceIP)
	err = s.DB.QueryRow(`SELECT id, kind, tier FROM targets WHERE host = ? OR host = ?`,
		host, deviceIP).Scan(&tid, &kind, &tier)
	if err != nil {
		log.Printf("tacacs author: unknown device %q for user=%q cmd=%q", deviceIP, user, fullCmd)
		return false, role
	}
	dec, err := s.Policy.Decide(context.Background(), policy.Input{
		UserID: userID, Role: role, Roles: roles,
		TargetID: tid, TargetKind: kind, TargetTier: tier, Action: "exec",
	})
	if err != nil || !dec.Allow {
		return false, role
	}
	// Empty command = session/shell authorization (Cisco sends service=shell with no cmd= at login).
	if strings.TrimSpace(fullCmd) == "" {
		return true, role
	}
	return policy.CommandAllowed(fullCmd, dec.AllowedCmds, dec.DeniedCmds), role
}

// ---- Accounting ----

func (s *Server) handleAcct(c net.Conn, h Header, body []byte, clientIP string) {
	req, err := ParseAcctRequest(body)
	if err != nil {
		return
	}
	kind := "acct"
	if req.Flags&AcctFlagStart != 0 {
		kind = "acct.start"
	} else if req.Flags&AcctFlagStop != 0 {
		kind = "acct.stop"
	} else if req.Flags&AcctFlagWatchdog != 0 {
		kind = "acct.watchdog"
	}
	s.Bus.Publish(events.Event{
		Source: "tacacs", Kind: kind, Severity: "info",
		Actor: req.User, Target: clientIP,
		Detail: map[string]string{"args": strings.Join(req.Args, ",")},
	})
	h.SeqNo++
	rep := AcctReply{Status: 0x01 /* TAC_PLUS_ACCT_STATUS_SUCCESS */, ServerMsg: "ok"}
	_ = WritePacket(c, h, rep.Bytes(), s.Secret)
}

// ---- helpers ----

func extractCommand(args []string) (cmd string, rest []string) {
	for _, a := range args {
		if strings.HasPrefix(a, "cmd=") {
			cmd = strings.TrimPrefix(a, "cmd=")
		} else if strings.HasPrefix(a, "cmd-arg=") {
			rest = append(rest, strings.TrimPrefix(a, "cmd-arg="))
		}
	}
	return cmd, rest
}

func extractArg(args []string, key string) string {
	prefix := key + "="
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return strings.TrimPrefix(a, prefix)
		}
	}
	return ""
}

func isAdminAuthService(svc string) bool {
	svc = strings.ToLower(strings.TrimSpace(svc))
	switch svc {
	case "administration", "admin", "fortigate", "fortinet", "ftm":
		return true
	}
	return strings.Contains(svc, "forti")
}

func deviceIPFromAuthor(req *AuthorRequest, clientIP string) string {
	// clientIP is the NAS (switch/firewall) TCP connection to TACACS+.
	// req.RemAddr is the end-user client IP on the NAS — not used for target lookup.
	_ = req
	return hostPart(clientIP)
}

func severity(ok bool) string {
	if ok {
		return "info"
	}
	return "warn"
}

func ternary(b bool, a, c string) string {
	if b {
		return a
	}
	return c
}

func hostPart(addrPort string) string {
	if i := strings.LastIndex(addrPort, ":"); i >= 0 {
		return addrPort[:i]
	}
	return addrPort
}

// Sanity to silence unused-import errors during partial editing.
var _ = errors.New
