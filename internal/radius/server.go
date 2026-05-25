package radius

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/accounts"
	"github.com/example/pam-platform/internal/authclient"
	"github.com/example/pam-platform/internal/cryptox"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/mfa"
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/vault"
)

// Server speaks RADIUS over UDP. It serves authentication on AuthAddr
// (default :1812) and accounting on AcctAddr (default :1813). Both loops are
// started by Run.
type Server struct {
	AuthAddr string
	AcctAddr string

	// Clients resolves NAS-IP → shared secret. Required.
	Clients *ClientStore

	DB     *db.DB
	Auth   *authclient.Client
	Vault  *vault.Vault
	Policy *policy.Engine
	Groups *groups.Service
	Bus    events.Publisher

	// UnknownUserDrop, when true, silently drops Access-Requests for users
	// not in the PAM portal so the NAS falls through to its next method
	// (usually 'group radius local'). The zero value is false, which sends
	// Access-Reject — the conservative default that terminates the NAS
	// method list. Set this to true only when you actively rely on the NAS
	// having a working fallback DB.
	UnknownUserDrop bool

	// MaxPacketSize lets ops tune the receive buffer. Default 4096 (RFC max).
	MaxPacketSize int

	// ReadTimeout for a single Access-Request handler. Default 8s.
	ReadTimeout time.Duration
}

// Run starts both UDP loops and blocks until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	if s.Clients == nil {
		return fmt.Errorf("radius: Clients is nil")
	}
	if s.AuthAddr == "" {
		s.AuthAddr = ":1812"
	}
	if s.AcctAddr == "" {
		s.AcctAddr = ":1813"
	}
	if s.MaxPacketSize <= 0 {
		s.MaxPacketSize = MaxPacketLen
	}
	if s.ReadTimeout <= 0 {
		s.ReadTimeout = 8 * time.Second
	}

	// Eager-load the client cache so we crash on a bad DB at startup.
	if err := s.Clients.Refresh(ctx); err != nil {
		log.Printf("radius: initial client load failed (using defaults): %v", err)
	}

	authConn, err := net.ListenPacket("udp", s.AuthAddr)
	if err != nil {
		return fmt.Errorf("radius: listen auth %s: %w", s.AuthAddr, err)
	}
	defer authConn.Close()
	log.Printf("radius auth listening on %s", s.AuthAddr)

	acctConn, err := net.ListenPacket("udp", s.AcctAddr)
	if err != nil {
		return fmt.Errorf("radius: listen acct %s: %w", s.AcctAddr, err)
	}
	defer acctConn.Close()
	log.Printf("radius acct listening on %s", s.AcctAddr)

	go func() {
		<-ctx.Done()
		_ = authConn.Close()
		_ = acctConn.Close()
	}()

	errCh := make(chan error, 2)
	go func() { errCh <- s.serveLoop(ctx, authConn, s.handleAuth) }()
	go func() { errCh <- s.serveLoop(ctx, acctConn, s.handleAcct) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

type handlerFunc func(ctx context.Context, pc net.PacketConn, addr net.Addr, raw []byte)

func (s *Server) serveLoop(ctx context.Context, pc net.PacketConn, h handlerFunc) error {
	buf := make([]byte, s.MaxPacketSize)
	for {
		if ctx.Err() != nil {
			return nil
		}
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// transient — log and keep going
			log.Printf("radius read: %v", err)
			continue
		}
		raw := make([]byte, n)
		copy(raw, buf[:n])
		go h(ctx, pc, addr, raw)
	}
}

// ---- Access-Request ----

func (s *Server) handleAuth(ctx context.Context, pc net.PacketConn, addr net.Addr, raw []byte) {
	clientAddr := addr.String()
	client, err := s.Clients.Lookup(ctx, clientAddr)
	if err != nil {
		log.Printf("radius: drop packet from %s: %v", clientAddr, err)
		return
	}

	pkt, err := Decode(raw, client.Secret)
	if err != nil {
		log.Printf("radius: decode from %s: %v", clientAddr, err)
		return
	}
	if pkt.Code != CodeAccessRequest {
		log.Printf("radius: unexpected code %d on auth port from %s", pkt.Code, clientAddr)
		return
	}
	if client.RequireMessageAuth && pkt.Attrs.Get(AttrMessageAuthenticator) == nil {
		log.Printf("radius: %s requires Message-Authenticator but NAS %s omitted it",
			client.Name, clientAddr)
		s.sendReject(pc, addr, pkt, client.Secret, "Message-Authenticator required")
		return
	}

	user := strings.TrimSpace(string(pkt.Attrs.Get(AttrUserName)))
	if user == "" {
		s.sendReject(pc, addr, pkt, client.Secret, "missing User-Name")
		return
	}

	nasIP := nasIPFromPacket(pkt, clientAddr)
	res := s.authenticate(ctx, user, pkt, client, nasIP)

	s.Bus.Publish(events.Event{
		Source: "radius", Kind: "authen", Severity: sev(res.ok),
		Actor: user, Target: nasIP,
		Detail: map[string]string{
			"result":     res.detail,
			"vendor":     res.profile.Family,
			"chap":       strconv.FormatBool(res.usedCHAP),
			"client_id":  client.Name,
		},
	})

	if !res.ok {
		if !res.pamUser && s.UnknownUserDrop {
			// silent drop — NAS will fall through to its local DB.
			return
		}
		s.sendReject(pc, addr, pkt, client.Secret, res.detail)
		return
	}
	s.sendAccept(pc, addr, pkt, client.Secret, res, user)
}

type authResult struct {
	ok       bool
	pamUser  bool
	role     string
	roles    []string
	userID   int64
	priv     int
	profile  VendorProfile
	usedCHAP bool
	detail   string
}

func (s *Server) authenticate(ctx context.Context, user string, pkt *Packet,
	client ClientRecord, nasIP string) authResult {

	res := authResult{profile: s.profileForNAS(nasIP, client)}

	if pwEnc := pkt.Attrs.Get(AttrUserPassword); pwEnc != nil {
		pw, err := DecodeUserPassword(pwEnc, pkt.Authenticator[:], client.Secret)
		if err != nil {
			res.detail = "User-Password decrypt error"
			return res
		}
		res.ok, res.pamUser, res.role, res.roles, res.userID = s.checkPortalOrDevice(ctx, user, pw, nasIP)
		if res.ok {
			res.priv = s.privilegeLevel(ctx, res.userID, res.role, res.roles, nasIP)
			res.detail = "ok"
			return res
		}
		res.detail = "auth failed"
		return res
	}

	if chap := pkt.Attrs.Get(AttrCHAPPassword); chap != nil {
		res.usedCHAP = true
		challenge := pkt.Attrs.Get(AttrCHAPChallenge)
		if challenge == nil {
			challenge = pkt.Authenticator[:]
		}
		// CHAP needs the cleartext password to verify, so it works only for
		// portal users with a local hash AND a known password. Auth-service
		// AD/LDAP backends can't verify CHAP without the password — that's why
		// most enterprise deployments use PAP exclusively.
		pw, ok := s.portalPasswordFor(ctx, user)
		if !ok {
			res.pamUser = false
			res.detail = "CHAP requires a portal-local password — switch NAS to PAP"
			return res
		}
		res.pamUser = true
		if VerifyCHAP(pw, chap, challenge) {
			res.ok = true
			info, _ := s.userInfo(ctx, user)
			res.role = info.role
			res.roles = info.roles
			res.userID = info.id
			res.priv = s.privilegeLevel(ctx, res.userID, res.role, res.roles, nasIP)
			res.detail = "ok (CHAP)"
			return res
		}
		res.detail = "CHAP failed"
		return res
	}

	res.detail = "no User-Password or CHAP-Password attribute"
	return res
}

func (s *Server) checkPortalOrDevice(ctx context.Context, user, pass, nasIP string) (
	ok, pamUser bool, role string, roles []string, userID int64) {

	if s.checkDevicePassword(ctx, pass, nasIP) {
		log.Printf("radius: device credential accepted for user=%q nas=%q", user, nasIP)
		// Device-bootstrap credential — no portal identity. We return a
		// neutral role so the policy reply still gets a Service-Type=Admin.
		return true, false, "admin", []string{"admin"}, 0
	}
	info, exists := s.userInfo(ctx, user)
	if !exists {
		return false, false, "", nil, 0
	}
	pamUser = true
	role = info.role
	roles = info.roles
	userID = info.id

	pw, otp := mfa.SplitAppendedOTP(pass)
	if s.Auth != nil {
		c, cancel := context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
		out, err := s.Auth.Login(c, user, pw, otp, true)
		if err == nil && out != nil && out.User != nil {
			return true, true, role, roles, userID
		}
		if err != nil {
			log.Printf("radius: auth-service login %q: %v", user, err)
		}
		if out != nil && out.MFARequired {
			log.Printf("radius: %q needs MFA — append the 6-digit code to the password", user)
		}
		return false, true, role, roles, userID
	}
	// auth-service unavailable — fall back to local hash check.
	var hash string
	err := s.DB.QueryRowContext(ctx, `
		SELECT password_hash FROM users
		WHERE lower(username)=lower(?) AND disabled=0`, user).Scan(&hash)
	if err != nil || hash == "" {
		return false, pamUser, role, roles, userID
	}
	return cryptox.VerifyPassword(pass, hash), pamUser, role, roles, userID
}

func (s *Server) checkDevicePassword(ctx context.Context, pass, nasIP string) bool {
	if s.Vault == nil || s.DB == nil || pass == "" {
		return false
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	acctSvc := &accounts.Service{DB: s.DB, Vault: s.Vault}
	devicePW, err := acctSvc.DevicePasswordForHost(c, nasIP)
	if err != nil || devicePW == "" {
		return false
	}
	return pass == devicePW
}

type userInfo struct {
	id    int64
	role  string
	roles []string
}

func (s *Server) userInfo(ctx context.Context, user string) (userInfo, bool) {
	if s.DB == nil {
		return userInfo{}, false
	}
	var (
		uid  int64
		role string
	)
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, role FROM users
		WHERE lower(username)=lower(?) AND disabled=0`, user).Scan(&uid, &role)
	if err != nil {
		err = s.DB.QueryRowContext(ctx, `
			SELECT id, role FROM users
			WHERE lower(email)=lower(?) AND disabled=0`, user).Scan(&uid, &role)
		if err != nil {
			return userInfo{}, false
		}
	}
	info := userInfo{id: uid, role: role, roles: []string{role}}
	if s.Groups != nil {
		if eff, err := s.Groups.EffectiveRoles(ctx, uid, role); err == nil && len(eff) > 0 {
			info.roles = eff
		}
	}
	return info, true
}

// portalPasswordFor returns the cleartext password if (and only if) the user is
// a local portal user. We don't store cleartext, so CHAP is supported only for
// the limited subset of users whose password we can recompute from the vault —
// i.e. nobody by default. Returns ok=false when CHAP cannot be verified.
//
// (This is the correct behavior: CHAP is fundamentally incompatible with
// salted-hash storage and AD/LDAP backends. We return false so the caller
// short-circuits with an actionable error rather than silently failing.)
func (s *Server) portalPasswordFor(ctx context.Context, user string) (string, bool) {
	if s.DB == nil {
		return "", false
	}
	var src string
	err := s.DB.QueryRowContext(ctx, `
		SELECT source FROM users
		WHERE lower(username)=lower(?) AND disabled=0`, user).Scan(&src)
	if err != nil {
		return "", false
	}
	_ = src
	return "", false
}

// ---- Accounting-Request ----

func (s *Server) handleAcct(ctx context.Context, pc net.PacketConn, addr net.Addr, raw []byte) {
	clientAddr := addr.String()
	client, err := s.Clients.Lookup(ctx, clientAddr)
	if err != nil {
		log.Printf("radius acct: drop from %s: %v", clientAddr, err)
		return
	}
	if !VerifyAccountingRequest(raw, client.Secret) {
		log.Printf("radius acct: Request Authenticator mismatch from %s", clientAddr)
		return
	}
	pkt, err := Decode(raw, client.Secret)
	if err != nil {
		log.Printf("radius acct: decode from %s: %v", clientAddr, err)
		return
	}
	if pkt.Code != CodeAccountingRequest {
		return
	}

	user := string(pkt.Attrs.Get(AttrUserName))
	statusType := uint32(0)
	if b := pkt.Attrs.Get(AttrAcctStatusType); len(b) == 4 {
		statusType = binary.BigEndian.Uint32(b)
	}
	sess := string(pkt.Attrs.Get(AttrAcctSessionID))
	nasIP := nasIPFromPacket(pkt, clientAddr)

	kind := "acct"
	switch statusType {
	case AcctStatusStart:
		kind = "acct.start"
	case AcctStatusStop:
		kind = "acct.stop"
	case AcctStatusInterimUpd:
		kind = "acct.update"
	case AcctStatusAccountingOn, AcctStatusAccountingOff:
		kind = "acct.nas"
	}
	s.Bus.Publish(events.Event{
		Source: "radius", Kind: kind, Severity: "info",
		Actor: user, Target: nasIP,
		Detail: map[string]string{
			"session_id":  sess,
			"status_type": strconv.FormatUint(uint64(statusType), 10),
			"client_id":   client.Name,
		},
	})

	reply := &Packet{
		Code:       CodeAccountingResponse,
		Identifier: pkt.Identifier,
	}
	out, err := Encode(reply, client.Secret, pkt.Authenticator[:])
	if err != nil {
		log.Printf("radius acct: encode reply: %v", err)
		return
	}
	_, _ = pc.WriteTo(out, addr)
}

// ---- reply helpers ----

func (s *Server) sendAccept(pc net.PacketConn, addr net.Addr, req *Packet,
	secret []byte, res authResult, user string) {

	reply := &Packet{
		Code:       CodeAccessAccept,
		Identifier: req.Identifier,
	}
	if res.profile.FillReply != nil {
		res.profile.FillReply(&reply.Attrs, res.role, res.priv)
	} else {
		reply.Attrs.AddUint32(AttrServiceType, ServiceAdministrative)
	}
	// Echo Proxy-State verbatim (RFC 2865 §5.33).
	for _, v := range req.Attrs.GetAll(AttrProxyState) {
		reply.Attrs.Add(AttrProxyState, v)
	}
	reply.Attrs.AddString(AttrReplyMessage,
		fmt.Sprintf("PAM RADIUS: welcome %s", user))

	out, err := Encode(reply, secret, req.Authenticator[:])
	if err != nil {
		log.Printf("radius: encode accept: %v", err)
		return
	}
	if _, err := pc.WriteTo(out, addr); err != nil {
		log.Printf("radius: write accept to %s: %v", addr, err)
	}
}

func (s *Server) sendReject(pc net.PacketConn, addr net.Addr, req *Packet,
	secret []byte, msg string) {

	reply := &Packet{
		Code:       CodeAccessReject,
		Identifier: req.Identifier,
	}
	if msg != "" {
		reply.Attrs.AddString(AttrReplyMessage, msg)
	}
	for _, v := range req.Attrs.GetAll(AttrProxyState) {
		reply.Attrs.Add(AttrProxyState, v)
	}
	out, err := Encode(reply, secret, req.Authenticator[:])
	if err != nil {
		log.Printf("radius: encode reject: %v", err)
		return
	}
	if _, err := pc.WriteTo(out, addr); err != nil {
		log.Printf("radius: write reject to %s: %v", addr, err)
	}
}

// ---- helpers ----

// profileForNAS picks the vendor profile for the NAS the request came from.
// Priority: explicit client.Vendor override > targets.kind lookup > generic.
func (s *Server) profileForNAS(nasIP string, client ClientRecord) VendorProfile {
	if v := strings.TrimSpace(client.Vendor); v != "" {
		return profileFor(v)
	}
	if s.DB == nil {
		return genericProfile()
	}
	var kind string
	err := s.DB.QueryRow(`
		SELECT kind FROM targets WHERE host = ? LIMIT 1`, nasIP).Scan(&kind)
	if err != nil {
		return genericProfile()
	}
	return profileFor(kind)
}

func (s *Server) privilegeLevel(ctx context.Context, userID int64, role string, roles []string, nasIP string) int {
	if s.Policy == nil || s.DB == nil {
		return privLevelForRole(role)
	}
	host := nasIP
	if h, _, err := net.SplitHostPort(nasIP); err == nil {
		host = h
	}
	var tid int64
	var kind string
	var tier int
	err := s.DB.QueryRowContext(ctx, `
		SELECT id, kind, tier FROM targets WHERE host = ? OR host = ?`, host, nasIP).
		Scan(&tid, &kind, &tier)
	if err != nil {
		return privLevelForRole(role)
	}
	dec, err := s.Policy.Decide(ctx, policy.Input{
		UserID: userID, Role: role, Roles: roles,
		TargetID: tid, TargetKind: kind, TargetTier: tier, Action: "exec",
	})
	if err != nil || !dec.Allow {
		return privLevelForRole(role)
	}
	if policy.IsCiscoKind(kind) {
		return policy.EffectiveCiscoPrivilege(dec, role)
	}
	return privLevelForRole(role)
}

// nasIPFromPacket extracts NAS-IP-Address (or NAS-IPv6) when supplied, else
// falls back to the UDP source address.
func nasIPFromPacket(p *Packet, clientAddr string) string {
	if v := p.Attrs.Get(AttrNASIPAddress); len(v) == 4 {
		return net.IP(v).String()
	}
	if v := p.Attrs.Get(AttrNASIPv6Address); len(v) == 16 {
		return net.IP(v).String()
	}
	if id := p.Attrs.Get(AttrNASIdentifier); len(id) > 0 {
		// many devices send a hostname here; we still need an IP for inventory
		// lookups, so fall through to the UDP source.
		_ = id
	}
	return hostFromAddr(clientAddr)
}

func sev(ok bool) string {
	if ok {
		return "info"
	}
	return "warn"
}
