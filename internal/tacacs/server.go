package tacacs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/example/pam-platform/internal/cryptox"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/policy"
)

// Server speaks TACACS+ over TCP/49.
type Server struct {
	Addr   string
	Secret []byte // shared secret with every device (use per-device in prod)
	DB     *db.DB
	Policy *policy.Engine
	Bus    events.Publisher
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

	// If the START packet already carries the password in Data, validate now.
	if len(start.Data) > 0 {
		s.verifyAndReply(c, h, start.User, string(start.Data), clientIP)
		return
	}

	// Otherwise ask for the password.
	reply := AuthenReply{Status: AuthenStatusGetPass, ServerMsg: "Password: "}
	h.SeqNo++
	_ = WritePacket(c, h, reply.Bytes(), s.Secret)

	// Read CONTINUE.
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
	h2.SeqNo++
	s.verifyAndReply(c, h2, start.User, cont.UserMsg, clientIP)
}

func (s *Server) verifyAndReply(c net.Conn, h Header, user, pass, clientIP string) {
	ok := s.checkPassword(user, pass)
	status := AuthenStatusFail
	msg := "auth failed"
	if ok {
		status = AuthenStatusPass
		msg = "ok"
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
	var hash string
	err := s.DB.QueryRow(`SELECT password_hash FROM users WHERE username = ? AND disabled = 0`, user).Scan(&hash)
	if err != nil {
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
	allow, role := s.authorize(req.User, clientIP, cmd, args)

	status := AuthorStatusFail
	if allow {
		status = AuthorStatusPassAdd
	}
	s.Bus.Publish(events.Event{
		Source: "tacacs", Kind: "authorize", Severity: severity(allow),
		Actor: req.User, Target: clientIP,
		Detail: map[string]string{
			"cmd":  fmt.Sprintf("%s %s", cmd, strings.Join(args, " ")),
			"role": role,
		},
	})

	h.SeqNo++
	rep := AuthorReply{Status: status, ServerMsg: ternary(allow, "ok", "denied by PAM policy")}
	_ = WritePacket(c, h, rep.Bytes(), s.Secret)
}

func (s *Server) authorize(user, deviceIP, cmd string, args []string) (bool, string) {
	var role string
	err := s.DB.QueryRow(`SELECT role FROM users WHERE username = ? AND disabled = 0`, user).Scan(&role)
	if err != nil {
		return false, ""
	}
	// Map the device IP to a target row to pull its kind/tier.
	var (
		tid  int64
		kind string
		tier int
	)
	err = s.DB.QueryRow(`SELECT id, kind, tier FROM targets WHERE host = ?`,
		hostPart(deviceIP)).Scan(&tid, &kind, &tier)
	if err != nil {
		// Unknown device; deny conservatively.
		return false, role
	}
	dec, err := s.Policy.Decide(context.Background(), policy.Input{
		Role: role, TargetID: tid, TargetKind: kind, TargetTier: tier, Action: "exec",
	})
	if err != nil || !dec.Allow {
		return false, role
	}
	return policy.CommandAllowed(cmd, dec.AllowedCmds, dec.DeniedCmds), role
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
