package tacacs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/accounts"
	"github.com/example/pam-platform/internal/authclient"
	"github.com/example/pam-platform/internal/cryptox"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/vault"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/mfa"
	"github.com/example/pam-platform/internal/policy"
)

// UnknownUserDefer controls how non-portal usernames are handled when the
// switch method list is "group PAM local". FAIL stops the list; ERROR (RFC
// 8907) or Drop lets IOS try the device local database next.
type UnknownUserDefer int

const (
	DeferUnknownError UnknownUserDefer = iota // AuthenStatusError / AuthorStatusError
	DeferUnknownDrop                          // close TCP without REPLY (no-response fallback)
)

// Server speaks TACACS+ over TCP/49.
type Server struct {
	Addr   string
	Secret []byte // shared secret with every device (use per-device in prod)
	DB     *db.DB
	Policy *policy.Engine
	Groups *groups.Service
	Bus    events.Publisher
	// UnknownUserDefer applies when the username is not a PAM portal account.
	UnknownUserDefer UnknownUserDefer
	// Auth, when set, delegates AAA password checks to auth-service so AD/LDAP
	// users authenticate the same way they do everywhere else. Falls back to
	// the local password hash check when nil.
	Auth *authclient.Client
	// Vault resolves privileged-account passwords for enable / device-level TACACS auth.
	Vault *vault.Vault
	// FortinetMemberOf is the default memberof= value returned on FortiGate authorization
	// (must match a config user group name on the firewall). Per-role overrides take
	// precedence when FortinetRoleMemberofMap is set.
	FortinetMemberOf string
	// FortinetRoleProfileMap maps PAM role names (lower-cased) to FortiGate admin_prof
	// values. Example: {"admin":"super_admin","netops":"prof_admin","viewer":"no_access"}
	// Falls back to the built-in defaults when a role is absent.
	// Populate from PAM_TACACS_FORTINET_PROFILES ("admin=super_admin,netops=prof_admin,...").
	FortinetRoleProfileMap map[string]string
	// FortinetRoleMemberofMap maps PAM role names (lower-cased) to FortiGate memberof
	// group names. Example: {"admin":"PAM-SuperAdmins","netops":"PAM-NetAdmins"}
	// Falls back to FortinetMemberOf when absent.
	// Populate from PAM_TACACS_FORTINET_MEMBEROF_MAP ("admin=PAM-SuperAdmins,netops=PAM-NetAdmins,...").
	FortinetRoleMemberofMap map[string]string
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
			log.Printf("tacacs: authorization packet from %s", hostPart(clientIP))
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
	if start.AuthenType == AuthenTypeCHAP {
		log.Printf("tacacs authen: CHAP from %s not supported — set authen-type pap on FortiGate", clientIP)
		h.SeqNo++
		_ = WritePacket(c, h, AuthenReply{
			Status:    AuthenStatusFail,
			ServerMsg: "CHAP not supported — use PAP",
		}.Bytes(), s.Secret)
		return
	}

	pass := passwordFromAuthenStart(start)
	if pass != "" {
		s.verifyAndReply(c, h, start.User, pass, clientIP, start)
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
	s.verifyAndReply(c, h2, start.User, cont.UserMsg, clientIP, start)
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

func (s *Server) verifyAndReply(c net.Conn, h Header, user, pass, clientIP string, start *AuthenStart) {
	h.SeqNo++ // REPLY seq_no must be request seq_no + 1 (RFC 8907 §4.4)
	ok := s.checkPassword(user, pass, clientIP, start)
	status, msg := authenStatusForResult(ok, s.portalUserExists(user))
	if !ok {
		if status == AuthenStatusError {
			log.Printf("tacacs authen defer to device local for unknown user=%q from %s", user, clientIP)
		} else {
			log.Printf("tacacs authen failed user=%q from %s", user, clientIP)
		}
	}
	s.Bus.Publish(events.Event{
		Source: "tacacs", Kind: "authen", Severity: severity(ok),
		Actor: user, Target: clientIP,
		Detail: map[string]string{"result": msg, "status": fmt.Sprintf("%#x", status)},
	})
	if ok {
		nas := hostPart(clientIP)
		if s.isFortiGateHost(nas) {
			if _, role, uid := s.authorizeAdmin(user); uid > 0 {
				s.refreshFortinetConfig()
				mapRole := s.fortinetMappingRole(uid, role)
				prof := s.fortinetAdminProfForRole(mapRole)
				log.Printf("tacacs authen ok user=%q role=%q map_role=%q admin_prof=%s nas=%q — if FortiGate still shows wrong profile, enable TACACS authorization on the firewall and accprofile-override on the remote admin template",
					user, role, mapRole, prof, nas)
			}
		}
	}
	if !ok && status == AuthenStatusError && s.UnknownUserDefer == DeferUnknownDrop {
		log.Printf("tacacs authen: closing session (no REPLY) for unknown user=%q from %s", user, clientIP)
		return
	}
	rep := AuthenReply{Status: status, ServerMsg: msg}
	_ = WritePacket(c, h, rep.Bytes(), s.Secret)
}

func (s *Server) checkPassword(user, pass, nasAddr string, start *AuthenStart) bool {
	user = strings.TrimSpace(user)
	if user == "" || pass == "" {
		return false
	}
	enableAuth := start != nil && (start.Action == AuthenActionSendAuth || start.PrivLvl > 0)

	// Enable / SENDAUTH: validate device enable secret first (never treat enable secret as portal password without OTP).
	if enableAuth {
		if s.checkDevicePassword(pass, nasAddr) {
			log.Printf("tacacs authen: enable credential accepted for user=%q nas=%q", user, hostPart(nasAddr))
			return true
		}
		// Some sites use portal creds for enable; MFA users must append OTP in the password field.
		return s.checkPortalPassword(user, pass)
	}

	// Login: device bootstrap password, then portal (+ MFA).
	if s.checkDevicePassword(pass, nasAddr) {
		log.Printf("tacacs authen: device credential accepted for user=%q nas=%q", user, hostPart(nasAddr))
		return true
	}
	return s.checkPortalPassword(user, pass)
}

func (s *Server) checkPortalPassword(user, pass string) bool {
	// Device-local accounts are not in the portal DB; defer via ERROR (see verifyAndReply).
	if !s.portalUserExists(user) {
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

func (s *Server) checkDevicePassword(pass, nasAddr string) bool {
	if s.Vault == nil || s.DB == nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	acctSvc := &accounts.Service{DB: s.DB, Vault: s.Vault}
	devicePW, err := acctSvc.DevicePasswordForHost(ctx, nasAddr)
	if err != nil || devicePW == "" {
		return false
	}
	return pass == devicePW
}

// ---- Authorization (per-command) ----

func (s *Server) handleAuthor(c net.Conn, h Header, body []byte, clientIP string) {
	req, err := ParseAuthorRequest(body)
	if err != nil {
		log.Printf("tacacs author parse: %v", err)
		return
	}

	// Users managed only on the device (LOCAL-TACACS-BOTH) must get ERROR, not
	// FAIL, so Cisco tries "local if-authenticated" after TACACS auth via local.
	if !s.portalUserExists(req.User) {
		log.Printf("tacacs author defer to device local for unknown user=%q nas=%q",
			req.User, deviceIPFromAuthor(req, clientIP))
		h.SeqNo++
		rep := AuthorReply{
			Status:    AuthorStatusError,
			ServerMsg: "user not managed by PAM",
		}
		_ = WritePacket(c, h, rep.Bytes(), s.Secret)
		return
	}

	cmd, args := extractCommand(req.Args)
	svc := serviceFromAuthorRequest(req.Args)
	fullCmd := policy.FullCommand(cmd, args)
	deviceIP := deviceIPFromAuthor(req, clientIP)
	fgNAS := s.isFortiGateHost(deviceIP)
	var allow bool
	var role string
	var mapRole string
	var userID int64
	var replyArgs []string
	fortinet := isFortinetService(svc) || fgNAS || isFortinetAdminService(svc)

	if fortinet {
		s.refreshFortinetConfig()
	}

	// FortiGate admin login: empty cmd + (service=fortigate|administration|…) or NAS is a registered FortiGate.
	adminLogin := fullCmd == "" && (isAdminAuthService(svc) || fgNAS)
	if adminLogin {
		// FortiGate / PAN-OS admin login — not per-command authorization.
		allow, role, userID = s.authorizeAdmin(req.User)
		if allow {
			if fortinet {
				mapRole = s.fortinetMappingRole(userID, role)
				replyArgs = s.fortinetAuthorArgs(mapRole, svc, extractArg(req.Args, "memberof"))
			} else {
				replyArgs = []string{"priv-lvl=15", "service=" + svc}
			}
		}
	} else {
		allow, role = s.authorize(req.User, deviceIP, fullCmd)
	}

	status := AuthorStatusFail
	if allow {
		if fortinet && len(replyArgs) > 0 {
			status = AuthorStatusPassRepl
		} else {
			status = AuthorStatusPassAdd
		}
	}
	logArgs := ""
	if len(replyArgs) > 0 {
		logArgs = strings.Join(replyArgs, " ")
	}
	log.Printf("tacacs author user=%q nas=%q rem_addr=%q svc=%q cmd=%q allow=%v role=%q map_role=%q reply=%q",
		req.User, deviceIP, strings.TrimSpace(req.RemAddr), svc, fullCmd, allow, role, mapRole, logArgs)
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

func (s *Server) authorizeAdmin(user string) (bool, string, int64) {
	var (
		userID   int64
		role     string
		disabled int
	)
	err := s.DB.QueryRow(`
		SELECT id, role, disabled FROM users WHERE lower(username)=lower(?)`, user).
		Scan(&userID, &role, &disabled)
	if err == nil && disabled == 0 {
		return true, role, userID
	}
	// FortiGate may send email/UPN while the portal stores sAMAccountName.
	err = s.DB.QueryRow(`
		SELECT id, role, disabled FROM users WHERE lower(email)=lower(?) AND disabled=0`, user).
		Scan(&userID, &role, &disabled)
	if err != nil {
		return false, "", 0
	}
	return true, role, userID
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

func isFortinetService(svc string) bool {
	svc = strings.ToLower(strings.TrimSpace(svc))
	switch svc {
	case "fortigate", "fortinet", "ftm":
		return true
	}
	return strings.Contains(svc, "forti")
}

// isFortinetAdminService covers FortiOS admin authorization when service= is not "fortigate".
func isFortinetAdminService(svc string) bool {
	switch strings.ToLower(strings.TrimSpace(svc)) {
	case "administration", "admin":
		return true
	}
	return false
}

func isAdminAuthService(svc string) bool {
	svc = strings.ToLower(strings.TrimSpace(svc))
	switch svc {
	case "administration", "admin", "fortigate", "fortinet", "ftm":
		return true
	}
	return isFortinetService(svc)
}

// isFortiGateHost reports whether the NAS IP is a FortiGate registered in PAM inventory.
// Used when FortiOS sends an authorization request without service=fortigate.
func (s *Server) isFortiGateHost(host string) bool {
	if s.DB == nil {
		return false
	}
	host = hostPart(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	var kind string
	err := s.DB.QueryRow(`
		SELECT kind FROM targets WHERE host = ? LIMIT 1`, host).Scan(&kind)
	if err != nil {
		return false
	}
	k := strings.ToLower(kind)
	return strings.Contains(k, "forti")
}

// fortinetAuthorArgs builds VSAs FortiOS expects (admin_prof, memberof, service).
// priv-lvl is ignored by FortiGate; without these attributes authorization fails.
func (s *Server) fortinetAuthorArgs(role, svc, reqMemberof string) []string {
	if strings.TrimSpace(svc) == "" {
		svc = "fortigate"
	}
	return []string{
		"service=" + svc,
		"admin_prof=" + s.fortinetAdminProfLive(role),
		"memberof=" + s.fortinetMemberofLive(role, reqMemberof),
	}
}

// fortinetAdminProfForRole returns the FortiGate admin_prof for a PAM role.
// Checks FortinetRoleProfileMap first; falls back to built-in defaults.
func (s *Server) fortinetAdminProfForRole(role string) string {
	r := strings.ToLower(strings.TrimSpace(role))
	if s.FortinetRoleProfileMap != nil {
		if p, ok := s.FortinetRoleProfileMap[r]; ok && p != "" {
			return p
		}
	}
	return fortinetAdminProf(r)
}

// fortinetMemberofForRole returns the memberof= group for a PAM role.
// Priority: FortinetRoleMemberofMap > FortinetMemberOf > FortiGate request > "PAM-Admins".
func (s *Server) fortinetMemberofForRole(role, reqMemberof string) string {
	r := strings.ToLower(strings.TrimSpace(role))
	if s.FortinetRoleMemberofMap != nil {
		if m, ok := s.FortinetRoleMemberofMap[r]; ok && m != "" {
			return m
		}
	}
	if m := strings.TrimSpace(s.FortinetMemberOf); m != "" {
		return m
	}
	if strings.TrimSpace(reqMemberof) != "" {
		return strings.TrimSpace(reqMemberof)
	}
	return "PAM-Admins"
}

// fortinetMappingRole picks the PAM role with the least-privileged FortiGate profile
// when the user has multiple effective roles (primary + group grants).
func (s *Server) fortinetMappingRole(userID int64, primaryRole string) string {
	roles := []string{strings.TrimSpace(primaryRole)}
	if s.Groups != nil && userID > 0 {
		if eff, err := s.Groups.EffectiveRoles(context.Background(), userID, primaryRole); err == nil && len(eff) > 0 {
			roles = eff
		}
	}
	bestRole := primaryRole
	bestRank := 999
	for _, r := range roles {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		rank := fortinetProfRank(s.fortinetAdminProfForRole(r))
		if rank < bestRank {
			bestRank = rank
			bestRole = r
		}
	}
	return bestRole
}

func fortinetProfRank(prof string) int {
	switch strings.ToLower(strings.TrimSpace(prof)) {
	case "no_access", "noaccess":
		return 0
	case "read_only", "readonly", "read-only":
		return 1
	case "prof_admin":
		return 2
	case "read_write":
		return 3
	case "super_admin":
		return 4
	default:
		return 2
	}
}

func serviceFromAuthorRequest(args []string) string {
	if s := extractArg(args, "service"); s != "" {
		return s
	}
	for _, a := range args {
		lower := strings.ToLower(strings.TrimSpace(a))
		if strings.HasPrefix(lower, "service=") {
			return strings.TrimSpace(a[strings.Index(a, "=")+1:])
		}
	}
	return ""
}

// fortinetAdminProf is the built-in default role → admin_prof mapping.
// Override per-role at runtime via Server.FortinetRoleProfileMap.
func fortinetAdminProf(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin":
		return "super_admin"
	case "secops":
		return "super_admin"
	default:
		return "prof_admin"
	}
}

// ParseRoleMap parses a comma-separated "role=value,role2=value2" string into a map.
// Used for PAM_TACACS_FORTINET_PROFILES and PAM_TACACS_FORTINET_MEMBEROF_MAP env vars.
func ParseRoleMap(s string) map[string]string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	m := make(map[string]string)
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok || strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			continue
		}
		m[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	if len(m) == 0 {
		return nil
	}
	return m
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

// portalUserExists reports whether the username is a PAM portal account (any
// source). Device-local-only accounts are absent so TACACS can defer to the
// switch "local" AAA method instead of returning FAIL (which stops the list).
func (s *Server) portalUserExists(user string) bool {
	if s.DB == nil {
		return false
	}
	user = strings.TrimSpace(user)
	if user == "" {
		return false
	}
	var id int64
	err := s.DB.QueryRow(`
		SELECT id FROM users WHERE lower(username)=lower(?) AND disabled=0`, user).Scan(&id)
	if err == nil && id > 0 {
		return true
	}
	err = s.DB.QueryRow(`
		SELECT id FROM users WHERE lower(email)=lower(?) AND disabled=0`, user).Scan(&id)
	return err == nil && id > 0
}

// ParseUnknownUserDefer reads PAM_TACACS_UNKNOWN_USER ("error" or "drop").
func ParseUnknownUserDefer(s string) UnknownUserDefer {
	if strings.EqualFold(strings.TrimSpace(s), "drop") {
		return DeferUnknownDrop
	}
	return DeferUnknownError
}

// authenStatusForResult maps a password check to the TACACS status Cisco expects.
// FAIL ends the method list; ERROR lets IOS try the next method (e.g. "local").
func authenStatusForResult(ok, pamUser bool) (status uint8, msg string) {
	if ok {
		return AuthenStatusPass, "ok"
	}
	if !pamUser {
		return AuthenStatusError, "user not managed by PAM"
	}
	return AuthenStatusFail, "auth failed"
}

// Sanity to silence unused-import errors during partial editing.
var _ = errors.New

// fortinetAdminProfLive returns the FortiGate admin_prof for a role with a live
// DB read (via refreshFortinetConfig) so Roles UI changes apply without restart.
func (s *Server) fortinetAdminProfLive(role string) string {
	s.refreshFortinetConfig()
	return s.fortinetAdminProfForRole(role)
}

// fortinetMemberofLive returns the memberof group for a role with a live DB read.
func (s *Server) fortinetMemberofLive(role, reqMemberof string) string {
	s.refreshFortinetConfig()
	return s.fortinetMemberofForRole(role, reqMemberof)
}
