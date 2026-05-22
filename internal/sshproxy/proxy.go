// Package sshproxy is the SSH data-plane. It exposes an SSH server to
// privileged users; once authenticated, it opens a downstream SSH connection
// to the requested target using a short-lived certificate issued by the
// vault, and tees the entire byte stream to a recording file.
//
// In production this would also:
//   - perform per-command policy checks (inspect each \n-terminated line),
//   - allow SOC operators to live-view / terminate sessions,
//   - stream events to Kafka in real time.
package sshproxy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/example/pam-platform/internal/authclient"
	"github.com/example/pam-platform/internal/approval"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/sshlaunch"
	"github.com/example/pam-platform/internal/vault"

	"golang.org/x/crypto/ssh"
)

// Server is the public listener.
type Server struct {
	Vault        *vault.Vault
	DB           *db.DB
	Policy       *policy.Engine
	Bus          events.Publisher
	HostKey      ssh.Signer
	RecordingDir string
	ListenAddr   string
	// Auth delegates credential checks to auth-service so AD/LDAP users and
	// TOTP-enrolled users get the same authentication flow they have in the
	// portal. If nil, falls back to the legacy local-DB password check.
	Auth *authclient.Client
	// Groups resolves effective roles (primary role + group grants) for policy.
	Groups *groups.Service
	// Approval gates SSH when policy requires JIT access.
	Approval *approval.Service
}

// Run starts the proxy. Blocks until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	if err := os.MkdirAll(s.RecordingDir, 0o700); err != nil {
		return fmt.Errorf("sshproxy: mkdir recordings: %w", err)
	}

	cfg := &ssh.ServerConfig{
		PasswordCallback:            s.passwordAuth,
		KeyboardInteractiveCallback: s.keyboardInteractiveAuth,
		MaxAuthTries:                3,
	}
	cfg.AddHostKey(s.HostKey)

	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("sshproxy: listen: %w", err)
	}
	log.Printf("ssh-proxy listening on %s", s.ListenAddr)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		nc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("accept: %v", err)
			continue
		}
		go s.handle(ctx, nc, cfg)
	}
}

// passwordAuth verifies "user@target" SSH login via auth-service (AD/LDAP/local).
// When MFA is enrolled, use keyboard-interactive for a separate MFA code prompt.
func (s *Server) passwordAuth(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
	user, target, ok := splitUserTarget(c.User())
	if !ok {
		return nil, errors.New("login must be user@target")
	}
	if perms, err := s.tryBrowserToken(user, target, string(pw)); err == nil {
		return perms, nil
	}
	authedUser, err := s.authenticate(user, string(pw), "")
	if err != nil {
		if errors.Is(err, errMFANeeded) {
			return nil, errors.New("MFA required — retry with keyboard-interactive")
		}
		return nil, err
	}
	perms, err := s.authorizeAndStash(authedUser, target)
	if err != nil {
		return nil, err
	}
	s.stashPassthrough(perms, string(pw))
	return perms, nil
}

// keyboardInteractiveAuth prompts for portal password and an optional MFA code.
// Leave MFA blank when not enrolled. GUI devices (FortiGate TACACS) use
// password+MFA in one field instead — not this SSH path.
func (s *Server) keyboardInteractiveAuth(c ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	user, target, ok := splitUserTarget(c.User())
	if !ok {
		return nil, errors.New("login must be user@target")
	}
	resolvedHint := target
	if tid, name, kind, host, port, _, rerr := s.resolveTarget(target); rerr == nil {
		resolvedHint = fmt.Sprintf("%s [%s] %s:%d (id %d)", name, kind, host, port, tid)
	} else {
		resolvedHint = target + " — unknown machine (will fail authorization)"
	}
	answers, err := ch(user, fmt.Sprintf("PAM Platform -> %s\r\nAuthenticate with your portal credentials (AD or local).", resolvedHint),
		[]string{"Password: ", "MFA code (leave blank if not enrolled): "},
		[]bool{false, true})
	if err != nil {
		return nil, err
	}
	if len(answers) < 1 || answers[0] == "" {
		return nil, errors.New("no password provided")
	}
	pw := answers[0]
	otp := ""
	if len(answers) > 1 {
		otp = strings.TrimSpace(answers[1])
	}
	authedUser, err := s.authenticate(user, pw, otp)
	if err != nil {
		log.Printf("ssh-proxy: portal auth failed for %q: %v", user, err)
		s.Bus.Publish(events.Event{
			Source: "ssh-proxy", Kind: "auth.fail", Severity: "warn",
			Actor: user, Target: target,
			Detail: map[string]string{"reason": err.Error()},
		})
		return nil, err
	}
	perms, err := s.authorizeAndStash(authedUser, target)
	if err != nil {
		log.Printf("ssh-proxy: access denied for %q → %q: %v", user, target, err)
		s.Bus.Publish(events.Event{
			Source: "ssh-proxy", Kind: "policy.deny", Severity: "warn",
			Actor: user, Target: target,
			Detail: map[string]string{"reason": err.Error()},
		})
		return nil, err
	}
	// Passthrough downstream auth: append OTP so the target's TACACS request
	// (which has a single password field) carries the full credential. Auth-service
	// splits the trailing 6 digits back into the OTP when validating.
	stashedPW := pw
	if otp != "" {
		stashedPW = pw + otp
	}
	s.stashPassthrough(perms, stashedPW)
	return perms, nil
}

// stashPassthrough remembers the password the user just typed so it can be
// re-used downstream when no privileged account is linked to the target. This
// matches the CyberArk PSM "transparent SSO" behaviour where the same AD
// credential authenticates the user to both PAM and the device.
func (s *Server) stashPassthrough(perms *ssh.Permissions, password string) {
	if perms == nil || password == "" {
		return
	}
	if perms.Extensions == nil {
		perms.Extensions = map[string]string{}
	}
	perms.Extensions["pt-password"] = password
}

// errMFANeeded is returned by authenticate when the user has TOTP enrolled and
// we got an HTTP 202 from auth-service.
var errMFANeeded = errors.New("mfa required")

// authedUser is what authenticate returns to authorizeAndStash.
type authedUser struct {
	ID    int64
	Role  string
	Email string
}

// authenticate prefers auth-service (local + LDAP + MFA) and falls back to the
// legacy local-DB hash check if no client is configured.
func (s *Server) authenticate(username, password, otp string) (*authedUser, error) {
	// SSH uses a separate MFA prompt — never strip digits from the password.
	otp = strings.TrimSpace(otp)
	if s.Auth != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		res, err := s.Auth.Login(ctx, username, password, otp, true)
		if err != nil {
			return nil, err
		}
		if res.MFARequired && otp == "" {
			return nil, errMFANeeded
		}
		if res.User == nil {
			return nil, errors.New("invalid credentials")
		}
		return &authedUser{ID: res.User.ID, Role: res.User.Role, Email: res.User.Email}, nil
	}
	// Legacy local-only fallback.
	var (
		uid   int64
		uHash string
		uRole string
	)
	err := s.DB.QueryRow(`SELECT id, password_hash, role FROM users WHERE username = ?`, username).
		Scan(&uid, &uHash, &uRole)
	if err != nil || !verifyPwd(password, uHash) {
		return nil, errors.New("invalid credentials")
	}
	return &authedUser{ID: uid, Role: uRole}, nil
}

// resolveTarget looks up a target by numeric ref (#42 / id:42), by host/IP, or
// by display name. Trying host before name lets users type the IP/hostname of
// the device directly — which is the unambiguous identifier most admins
// already know. ID refs avoid SSH parsing issues when machine names contain
// spaces or @.
func (s *Server) resolveTarget(targetRef string) (tid int64, name, kind, host string, port, tier int, err error) {
	ref := strings.TrimSpace(targetRef)
	if ref == "" {
		return 0, "", "", "", 0, 0, errors.New("target not found")
	}
	if strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "id:") {
		idStr := strings.TrimPrefix(strings.TrimPrefix(ref, "id:"), "#")
		var id int64
		id, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil || id <= 0 {
			return 0, "", "", "", 0, 0, errors.New("target not found")
		}
		err = s.DB.QueryRow(`SELECT id, name, kind, host, port, tier FROM targets WHERE id = ?`, id).
			Scan(&tid, &name, &kind, &host, &port, &tier)
		if err != nil {
			return 0, "", "", "", 0, 0, errors.New("target not found")
		}
		return tid, name, kind, host, port, tier, nil
	}
	// Host/IP match first. Prefer SSH/telnet-style entries when multiple targets
	// share a host (e.g. a Linux server + a console-only Cisco at the same IP).
	row := s.DB.QueryRow(`
		SELECT id, name, kind, host, port, tier FROM targets
		WHERE host = ?
		ORDER BY CASE LOWER(COALESCE(connection_type,''))
		           WHEN 'ssh' THEN 0
		           WHEN 'telnet' THEN 1
		           ELSE 2
		         END, id
		LIMIT 1`, ref)
	if err = row.Scan(&tid, &name, &kind, &host, &port, &tier); err == nil {
		return tid, name, kind, host, port, tier, nil
	}
	// Fallback: lookup by name.
	err = s.DB.QueryRow(`SELECT id, name, kind, host, port, tier FROM targets WHERE name = ?`, ref).
		Scan(&tid, &name, &kind, &host, &port, &tier)
	if err != nil {
		return 0, "", "", "", 0, 0, errors.New("target not found")
	}
	return tid, name, kind, host, port, tier, nil
}

// tryBrowserToken validates a one-time token issued for recorded browser SSH
// (guacd → ssh-proxy → target). Skips portal password auth when the token matches.
func (s *Server) tryBrowserToken(loginUser, targetRef, token string) (*ssh.Permissions, error) {
	if token == "" {
		return nil, errors.New("no token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := s.Vault.GetSecret(ctx, sshlaunch.BrowserTokenVaultKey(token))
	if err != nil {
		return nil, errors.New("invalid token")
	}
	creds, err := sshlaunch.ParseSessionCreds(raw)
	if err != nil || creds.Mode != "browser" {
		return nil, errors.New("invalid token")
	}
	if creds.PortalUser != loginUser || creds.TargetRef != targetRef {
		return nil, errors.New("token mismatch")
	}

	tid, name, kind, host, port, tier, err := s.resolveTarget(targetRef)
	if err != nil {
		return nil, err
	}
	if tid != creds.TargetID {
		return nil, errors.New("target mismatch")
	}

	var role string
	if err := s.DB.QueryRow(`SELECT role FROM users WHERE id = ?`, creds.UserID).Scan(&role); err != nil {
		return nil, errors.New("user not found")
	}
	dec, err := s.evaluateAccess(ctx, creds.UserID, role, tid, kind, tier)
	if err != nil {
		return nil, err
	}
	ext := map[string]string{
		"user-id":            fmt.Sprintf("%d", creds.UserID),
		"role":               role,
		"target-id":          fmt.Sprintf("%d", tid),
		"target":             name,
		"kind":               kind,
		"host":               host,
		"port":               fmt.Sprintf("%d", port),
		"tier":               fmt.Sprintf("%d", tier),
		"allow-csv":          joinCSV(dec.AllowedCmds),
		"deny-csv":           joinCSV(dec.DeniedCmds),
		"linux-privilege":    dec.LinuxPrivilege,
		"browser-session-id": creds.SessionID,
	}
	if creds.PassthroughPW != "" {
		ext["pt-password"] = creds.PassthroughPW
	}
	log.Printf("ssh-proxy: browser token OK user=%s target=%s session=%s passthrough=%t",
		loginUser, targetRef, creds.SessionID, creds.PassthroughPW != "")
	return &ssh.Permissions{Extensions: ext}, nil
}

// evaluateAccess checks policy using effective roles (primary + group grants)
// and enforces JIT approval when required — same rules as browser SSH launch.
func (s *Server) evaluateAccess(ctx context.Context, userID int64, primaryRole string, targetID int64, kind string, tier int) (policy.Decision, error) {
	roles := []string{primaryRole}
	if s.Groups != nil && userID > 0 {
		if eff, err := s.Groups.EffectiveRoles(ctx, userID, primaryRole); err == nil && len(eff) > 0 {
			roles = eff
		}
	}
	dec, err := s.Policy.Decide(ctx, policy.Input{
		UserID: userID, Role: primaryRole, Roles: roles,
		TargetID: targetID, TargetKind: kind, TargetTier: tier, Action: "ssh",
	})
	if err != nil {
		return dec, err
	}
	if !dec.Allow {
		log.Printf("ssh-proxy: policy deny user=%d primary_role=%q effective=%v target=#%d kind=%q tier=%d reasons=%v",
			userID, primaryRole, roles, targetID, kind, tier, dec.Reasons)
		return dec, fmt.Errorf("denied by policy: %v", dec.Reasons)
	}
	if dec.RequireApproval && s.Approval != nil {
		ok, err := s.Approval.IsApproved(ctx, userID, targetID)
		if err != nil {
			return dec, err
		}
		if !ok {
			return dec, errors.New("approved access request required — open the portal, request access to this machine, and wait for approval")
		}
	}
	return dec, nil
}

// authorizeAndStash looks up the target, evaluates policy with the user's
// effective roles, and packages routing info into ssh.Permissions for the
// connection handler to consume.
func (s *Server) authorizeAndStash(u *authedUser, target string) (*ssh.Permissions, error) {
	tid, name, kind, host, port, tier, err := s.resolveTarget(target)
	if err != nil {
		return nil, err
	}

	dec, err := s.evaluateAccess(context.Background(), u.ID, u.Role, tid, kind, tier)
	if err != nil {
		return nil, err
	}
	// Pass tier through in permissions so the handler can build a helpful banner.
	return &ssh.Permissions{
		Extensions: map[string]string{
			"user-id":   fmt.Sprintf("%d", u.ID),
			"role":      u.Role,
			"target-id": fmt.Sprintf("%d", tid),
			"target":    name,
			"kind":      kind,
			"host":      host,
			"port":      fmt.Sprintf("%d", port),
			"tier":      fmt.Sprintf("%d", tier),
			"allow-csv":        joinCSV(dec.AllowedCmds),
			"deny-csv":         joinCSV(dec.DeniedCmds),
			"linux-privilege":  dec.LinuxPrivilege,
		},
	}, nil
}

func (s *Server) handle(ctx context.Context, nc net.Conn, cfg *ssh.ServerConfig) {
	defer nc.Close()
	sconn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		log.Printf("handshake: %v", err)
		return
	}
	defer sconn.Close()

	go ssh.DiscardRequests(reqs)

	host := sconn.Permissions.Extensions["host"]
	port := sconn.Permissions.Extensions["port"]
	targetName := sconn.Permissions.Extensions["target"]
	targetKind := sconn.Permissions.Extensions["kind"]
	targetTier := sconn.Permissions.Extensions["tier"]
	user := sconn.User()
	browserSess := sconn.Permissions.Extensions["browser-session-id"]
	sessionID := browserSess
	if sessionID == "" {
		sessionID = fmt.Sprintf("%d-%s", time.Now().UnixNano(), targetName)
	}

	defer s.Bus.Publish(events.Event{
		Source: "ssh-proxy", Kind: "session.close", Severity: "info",
		Actor: user, Target: targetName,
		Detail: map[string]string{"session_id": sessionID},
	})

	// Build downstream auth in order of preference:
	//   1. Privileged account linked to the target (CyberArk PSM model —
	//      admin stores device credentials in a safe, PAM injects them).
	//   2. Passthrough: re-use the password the user just typed at the
	//      proxy prompt. Works seamlessly when the device shares the same
	//      AD/LDAP backend as PAM ("transparent SSO").
	//   3. Ephemeral SSH cert as user "pam-user" — only works when the
	//      target trusts the PAM CA via TrustedUserCAKeys / sshd_config.
	// portalUsername is just the portal login name (e.g. "admin"), stripped of
	// the "@target-ref" suffix that the SSH client includes in the username field
	// so the proxy can resolve the machine (e.g. "admin@#4" → "admin").
	portalUsername := user
	if i := strings.Index(portalUsername, "@"); i >= 0 {
		portalUsername = portalUsername[:i]
	}

	targetID := mustAtoi(sconn.Permissions.Extensions["target-id"])
	ptPassword := sconn.Permissions.Extensions["pt-password"]
	privUser, privPassword, hasPriv := s.lookupPrivilegedAccount(targetID)

	linuxPriv := sconn.Permissions.Extensions["linux-privilege"]
	linuxPerUser := useLinuxPerUserLogin(targetKind) && ptPassword != ""

	// Build ordered downstream login attempts (network devices / legacy Linux):
	//   1. Privileged account (PSM vault credentials)
	//   2. Passthrough (portal password)
	// Linux with portal password uses dialLinux() — per-user account, bootstrap only for provisioning.
	type loginPlan struct {
		user, password, mode string
	}
	var plans []loginPlan
	if !linuxPerUser {
		if hasPriv {
			plans = append(plans, loginPlan{privUser, privPassword, "priv-account"})
		}
		if ptPassword != "" {
			plans = append(plans, loginPlan{portalUsername, ptPassword, "passthrough"})
		}
	}

	downUser := portalUsername
	var authMethods []ssh.AuthMethod
	if browserSess != "" && len(plans) == 0 && !linuxPerUser {
		log.Printf("ssh-proxy: browser session %s target=%s — no privileged account and no portal password at launch",
			sessionID, targetName)
		s.sendShellError(chans,
			"PAM browser SSH: this target has no privileged account in PAM.\r\n"+
				"Launch again and enter the same portal password you use in PuTTY,\r\n"+
				"or add a Privileged Account for this machine in the Safes tab.\r\n")
		return
	}
	if len(plans) == 0 && !linuxPerUser {
		downUser = "pam-user"
		principals := []string{sconn.Permissions.Extensions["role"], "pam-user"}
		upPriv, upCertAuth, certErr := s.Vault.IssueSSHCert(principals, 30*time.Minute)
		if certErr != nil {
			log.Printf("issue cert: %v", certErr)
			s.sendShellError(chans, "PAM: no privileged account linked to this target.\r\nAdd one in Privileged Accounts (Safes tab) with the device username + password.\r\n")
			return
		}
		upSigner, certErr := buildCertSigner(upPriv, upCertAuth)
		if certErr != nil {
			log.Printf("build cert signer: %v", certErr)
			return
		}
		authMethods = []ssh.AuthMethod{ssh.PublicKeys(upSigner)}
		plans = []loginPlan{{downUser, "", "ssh-cert"}}
	}

	// Dial the target in parallel with accepting the user's session channel.
	// Blocking on ssh.Dial before reading from chans deadlocks the SSH
	// connection: the client cannot open a session until the server reads
	// chans, so dial failures never reach the user and OpenSSH retries auth.
	targetAddr := fmt.Sprintf("%s:%s", host, port)
	type dialOutcome struct {
		client   *ssh.Client
		err      error
		user     string
		authMode string
	}
	dialCh := make(chan dialOutcome, 1)
	go func() {
		if linuxPerUser {
			c, user, mode, err := s.dialLinux(targetAddr, targetKind, portalUsername, ptPassword, privUser, privPassword, linuxPriv, authMethods)
			dialCh <- dialOutcome{client: c, err: err, user: user, authMode: mode}
			return
		}
		var last dialOutcome
		for i, plan := range plans {
			cfg := s.buildDownstreamConfig(plan.user, plan.password, authMethods)
			log.Printf("ssh-proxy: dialing target %s as %q (mode=%s, attempt %d/%d)", targetAddr, plan.user, plan.mode, i+1, len(plans))
			c, err := ssh.Dial("tcp", targetAddr, cfg)
			if err == nil {
				dialCh <- dialOutcome{client: c, user: plan.user, authMode: plan.mode}
				return
			}
			last = dialOutcome{err: err, user: plan.user, authMode: plan.mode}
			log.Printf("ssh-proxy: dial failed for %s as %q (mode=%s): %v", targetAddr, plan.user, plan.mode, err)
			// Only fall back to passthrough when the privileged account was rejected.
			if plan.mode == "priv-account" && i+1 < len(plans) && isDownstreamAuthFailure(err) {
				log.Printf("ssh-proxy: privileged account rejected — trying passthrough as %q", plans[i+1].user)
				continue
			}
			break
		}
		dialCh <- last
	}()

	dialErrMsg := func(out dialOutcome) string {
		kind := strings.ToLower(targetKind)
		isNetworkAppliance := strings.Contains(kind, "forti") || strings.Contains(kind, "cisco") ||
			strings.Contains(kind, "juniper") || strings.Contains(kind, "arista") ||
			strings.Contains(kind, "palo") || strings.Contains(kind, "switch") ||
			strings.Contains(kind, "router") || strings.Contains(kind, "firewall")

		switch out.authMode {
		case "priv-account":
			return fmt.Sprintf("PAM: could not log in to %s as %s (privileged account).\r\nCheck the password in Privileged Accounts, or remove the account to use your portal credentials.\r\nUnderlying error: %v\r\n", host, out.user, out.err)
		case "provision", "provisioned":
			return fmt.Sprintf("PAM: could not open a personal Linux session on %s as %s.\r\nEnsure bootstrap account pam-svc has passwordless sudo (sudo -n): NOPASSWD for useradd, chpasswd, tee /etc/sudoers.d/*.\r\nEnable PasswordAuthentication in sshd_config.\r\nDetails: %v\r\n", host, out.user, out.err)
		case "passthrough":
			hint := fmt.Sprintf("For Linux: PAM logs you in as your own account (%s), not the shared bootstrap user. PasswordAuthentication must be enabled in sshd_config.\r\n", out.user)
			if isNetworkAppliance {
				hint = "This device does not know your portal user. Two options to fix:\r\n" +
					"  1. Add a Privileged Account in the Safes tab with the device admin username/password.\r\n" +
					"     PAM will use that account to log you in (recommended for Cisco/FortiGate).\r\n" +
					"  2. Configure TACACS+ on the device so it asks PAM to authenticate your portal user.\r\n" +
					"     See Machines -> Device Setup for the exact CLI/GUI commands.\r\n"
			}
			return fmt.Sprintf("PAM: could not log in to %s as %s using your portal credentials.\r\n%sUnderlying error: %v\r\n", host, out.user, hint, out.err)
		default:
			return fmt.Sprintf("PAM: could not connect to %s.\r\nAdd a privileged account for this target in the Privileged Accounts tab so PAM can log in for you.\r\nUnderlying error: %v\r\n", host, out.err)
		}
	}

	var upClient *ssh.Client
	var activeMode string

	// Open recording file (browser sessions are recorded by guacd; skip duplicate tee).
	var rec *os.File
	if browserSess == "" {
		recPath := filepath.Join(s.RecordingDir, sessionID+".log")
		rec, err = os.OpenFile(recPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Printf("open recording: %v", err)
			s.sendShellError(chans, fmt.Sprintf("PAM: internal error — could not start session recording.\r\nUnderlying error: %v\r\n", err))
			return
		}
		defer rec.Close()

		for attempt := 0; attempt < 5; attempt++ {
			if _, err := s.DB.Exec(`
			INSERT INTO sessions(id, user_id, target_id, started_at, recording_path, client_ip)
			VALUES(?, ?, ?, ?, ?, ?)`,
				sessionID,
				mustAtoi(sconn.Permissions.Extensions["user-id"]),
				mustAtoi(sconn.Permissions.Extensions["target-id"]),
				time.Now().Unix(), recPath, nc.RemoteAddr().String()); err == nil {
				break
			} else {
				log.Printf("insert session (attempt %d): %v", attempt+1, err)
				if attempt == 4 {
					break
				}
				time.Sleep(time.Duration(200*(attempt+1)) * time.Millisecond)
			}
		}
	} else {
		rec, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if rec != nil {
			defer rec.Close()
		}
	}

	failSession := func(reason string) {
		if browserSess == "" {
			_, _ = s.DB.Exec(`UPDATE sessions SET ended_at = ?, ended_reason = ? WHERE id = ?`,
				time.Now().Unix(), reason, sessionID)
		}
	}

	// Track concurrent shell channels; end the DB row when the last one closes
	// (logout/exit) even if the SSH client keeps the TCP connection open briefly.
	var activePipes int32
	var endSessionOnce sync.Once
	endNativeSession := func() {
		if browserSess != "" {
			return
		}
		endSessionOnce.Do(func() {
			_, _ = s.DB.Exec(`UPDATE sessions SET ended_at = ?, ended_reason = COALESCE(ended_reason, 'closed') WHERE id = ? AND ended_at IS NULL`,
				time.Now().Unix(), sessionID)
		})
	}

	// Each downstream channel from the user is mirrored to the target.
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "only session channels supported")
			continue
		}
		if upClient == nil {
			out := <-dialCh
			if out.err != nil {
				log.Printf("dial target %s as %q (mode=%s): %v", targetAddr, out.user, out.authMode, out.err)
				failSession("failed")
				msg := dialErrMsg(out)
				s.replyChannelError(newChan, msg)
				for extra := range chans {
					if extra.ChannelType() == "session" {
						s.replyChannelError(extra, msg)
					} else {
						extra.Reject(ssh.UnknownChannelType, "only session channels supported")
					}
				}
				return
			}
			upClient = out.client
			activeMode = out.authMode
			downUser = out.user
			defer upClient.Close()
			log.Printf("ssh-proxy: connected to %s as %q (mode=%s)", targetAddr, downUser, activeMode)

			s.Bus.Publish(events.Event{
				Source: "ssh-proxy", Kind: "session.open", Severity: "info",
				Actor: portalUsername, Target: targetName,
				Detail: map[string]string{
					"session_id":  sessionID,
					"client":      nc.RemoteAddr().String(),
					"auth_mode":   activeMode,
					"device_user": downUser,
					"portal_user": portalUsername,
				},
			})

			// Background watcher: poll session_terminations every 5s and tear down
			// this connection if an admin requested termination.
			termCtx, termCancel := context.WithCancel(context.Background())
			defer termCancel()
			go s.watchTermination(termCtx, sessionID, sconn, upClient)
		}
		enableSecret := ""
		if _, privPW, ok := s.lookupPrivilegedAccount(targetID); ok {
			enableSecret = privPW
		}
		atomic.AddInt32(&activePipes, 1)
		go func(ch ssh.NewChannel) {
			defer func() {
				if atomic.AddInt32(&activePipes, -1) == 0 {
					endNativeSession()
				}
			}()
			s.pipeSession(ch, upClient, rec, sessionID, user, targetName, buildSessionBanner(targetName, targetKind, host, port, targetTier, downUser, activeMode),
				parseCSV(sconn.Permissions.Extensions["allow-csv"]),
				parseCSV(sconn.Permissions.Extensions["deny-csv"]),
				enableSecret,
				ptPassword)
		}(newChan)
	}

	// Mark session closed (browser sessions are ended by rdp-proxy when guacd disconnects).
	if browserSess == "" {
		_, _ = s.DB.Exec(`UPDATE sessions SET ended_at = ?, ended_reason = COALESCE(ended_reason, 'closed') WHERE id = ?`,
			time.Now().Unix(), sessionID)
	}
}

// watchTermination polls the session_terminations table for a kill order
// against this session and, on hit, closes the user-side connection.
func (s *Server) watchTermination(ctx context.Context, sessionID string,
	sconn *ssh.ServerConn, upClient *ssh.Client) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			var ack sql.NullInt64
			var reason string
			err := s.DB.QueryRow(
				`SELECT acknowledged_at, COALESCE(reason,'') FROM session_terminations WHERE session_id = ?`,
				sessionID).Scan(&ack, &reason)
			if err != nil {
				continue
			}
			if ack.Valid {
				continue
			}
			log.Printf("ssh-proxy: terminating session %s by admin order (%s)", sessionID, reason)
			_, _ = s.DB.Exec(
				`UPDATE sessions SET ended_at=?, ended_reason='terminated' WHERE id=?`,
				time.Now().Unix(), sessionID)
			_, _ = s.DB.Exec(
				`UPDATE session_terminations SET acknowledged_at=? WHERE session_id=?`,
				time.Now().Unix(), sessionID)
			_ = upClient.Close()
			_ = sconn.Close()
			return
		}
	}
}

// buildSessionBanner returns the bold "Connected to NAME (HOST:PORT)" lines
// shown in the user's terminal before any output from the target so a
// mis-typed target ID is obvious immediately.
func buildSessionBanner(name, kind, host, port, tier, downUser, authMode string) string {
	if name == "" {
		return ""
	}
	tierLabel := "T?"
	if tier != "" {
		tierLabel = "T" + tier
	}
	header := "\r\n\x1b[1;36m── PAM session ──────────────────────────────────────\x1b[0m\r\n"
	body := fmt.Sprintf(
		"  \x1b[1mMachine:\x1b[0m   %s  (%s, %s)\r\n"+
			"  \x1b[1mDevice:\x1b[0m    %s:%s as %s\r\n"+
			"  \x1b[1mAuth mode:\x1b[0m %s\r\n",
		name, kind, tierLabel, host, port, downUser, authMode,
	)
	footer := "\x1b[1;36m─────────────────────────────────────────────────────\x1b[0m\r\n\r\n"
	return header + body + footer
}

func sessionBannerWithEnableHint(banner, enableSecret string) string {
	if enableSecret == "" {
		return banner
	}
	return banner + "  \x1b[33mEnable:\x1b[0m type \x1b[1men\x1b[0m only — PAM injects the enable password (do not type it).\r\n\r\n"
}

func (s *Server) pipeSession(newChan ssh.NewChannel, upClient *ssh.Client, rec *os.File, sessionID, user, target string, banner string, allowCmds, denyCmds []string, enableSecret, portalPassword string) {
	downCh, downReqs, err := newChan.Accept()
	if err != nil {
		log.Printf("accept down chan: %v", err)
		return
	}
	defer downCh.Close()

	upCh, upReqs, err := upClient.OpenChannel("session", nil)
	if err != nil {
		log.Printf("open up chan: %v", err)
		writeUserChannelMessage(downCh, downReqs,
			fmt.Sprintf("PAM: connected to target but could not open a shell session.\r\nUnderlying error: %v\r\n", err))
		return
	}
	defer upCh.Close()

	// Show a one-line confirmation of WHERE the user just landed so a
	// mis-typed target ID is immediately obvious. The banner is written into
	// the user-facing stream only (not forwarded upstream, not recorded as
	// keystroke input).
	if banner != "" {
		_, _ = downCh.Write([]byte(banner))
	}

	// Forward channel requests both ways (pty-req, shell, env, exec, window-change).
	go forwardRequests(downReqs, upCh, "->up")
	go forwardRequests(upReqs, downCh, "->down")

	// Tee user input → upstream, and log it as the keystroke stream.
	var wg sync.WaitGroup
	wg.Add(2)
	var closeOnce sync.Once
	closeSession := func() {
		closeOnce.Do(func() {
			_ = upCh.Close()
			_ = downCh.Close()
		})
	}
	gate := newCmdGate(upCh, downCh, allowCmds, denyCmds, func(cmd string) {
		s.Bus.Publish(events.Event{
			Source: "ssh-proxy", Kind: "cmd.deny", Severity: "warn",
			Actor: user, Target: target,
			Detail: map[string]string{
				"session_id": sessionID,
				"command":    cmd,
			},
		})
	}, enableSecret, portalPassword, closeSession)

	// downstream (user)  ───►   recorder (input)  ───►   upstream (target)
	go func() {
		defer wg.Done()
		up := io.Writer(upCh)
		if gate != nil {
			up = gate
		}
		tee := io.MultiWriter(up, &prefixedWriter{w: rec, prefix: "IN  "})
		_, _ = io.Copy(tee, downCh)
		closeSession()
	}()
	// upstream (target)  ───►   recorder (output) ───►   downstream (user)
	go func() {
		defer wg.Done()
		out := io.Writer(downCh)
		if gate != nil {
			out = &gateAwareWriter{gate: gate, w: downCh}
		}
		tee := io.MultiWriter(out, &prefixedWriter{w: rec, prefix: "OUT "})
		_, _ = io.Copy(tee, upCh)
		closeSession()
	}()

	wg.Wait()

	s.Bus.Publish(events.Event{
		Source: "ssh-proxy", Kind: "session.io_finished", Severity: "info",
		Actor: user, Target: target,
		Detail: map[string]string{"session_id": sessionID},
	})
}

// lookupPrivilegedAccount returns the SSH-capable privileged account linked to
// a target along with its plaintext password fetched from the vault. The third
// return value is true when an account was found and its password retrieved.
// It matches ANY platform that is not windows/rdp — so Ubuntu, Cisco, FortiGate etc.
// all work without needing a specific platform filter.
func (s *Server) lookupPrivilegedAccount(targetID int64) (username, password string, ok bool) {
	if targetID == 0 {
		return "", "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var secretRef string
	err := s.DB.QueryRowContext(ctx, `
		SELECT a.username, a.secret_ref
		FROM privileged_accounts a
		WHERE a.target_id = ?
		  AND LOWER(a.platform) NOT IN ('windows','rdp')
		ORDER BY a.id
		LIMIT 1`, targetID).Scan(&username, &secretRef)
	if err != nil {
		return "", "", false
	}
	pw, err := s.Vault.GetSecret(ctx, secretRef)
	if err != nil || len(pw) == 0 {
		return "", "", false
	}
	return username, string(pw), true
}

// sendShellError accepts the user's first session channel and writes a
// human-readable error message to it, then closes — so the user sees the
// reason in their terminal instead of an opaque connection-closed drop.
func (s *Server) sendShellError(chans <-chan ssh.NewChannel, msg string) {
	log.Printf("ssh-proxy reply: %s", strings.TrimSpace(msg))
	deadline := time.After(5 * time.Second)
	for {
		select {
		case nc, ok := <-chans:
			if !ok {
				return
			}
			if nc.ChannelType() != "session" {
				_ = nc.Reject(ssh.UnknownChannelType, "session channels only")
				continue
			}
			s.replyChannelError(nc, msg)
			return
		case <-deadline:
			return
		}
	}
}

// replyChannelError accepts one session channel and writes msg to the user's
// terminal before closing with a non-zero exit status.
func (s *Server) replyChannelError(nc ssh.NewChannel, msg string) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		log.Printf("accept error chan: %v", err)
		return
	}
	writeUserChannelMessage(ch, reqs, msg)
}

// writeUserChannelMessage waits for the client to request a shell/PTY (as
// OpenSSH does) before writing text. Writing immediately after Accept() races
// the client and the message is often never displayed — which looks like a
// silent hang after a successful PAM login.
func writeUserChannelMessage(ch ssh.Channel, reqs <-chan *ssh.Request, msg string) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		shellStarted := false
		for req := range reqs {
			switch req.Type {
			case "pty-req", "env", "subsystem":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			case "shell", "exec":
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
				if !shellStarted {
					shellStarted = true
					_, _ = ch.Write([]byte(msg))
					_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
					_ = ch.Close()
					return
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
		if !shellStarted {
			_, _ = ch.Write([]byte(msg))
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
			_ = ch.Close()
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_, _ = ch.Write([]byte(msg))
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 1}))
		_ = ch.Close()
	}
}

// buildDownstreamConfig returns an ssh.ClientConfig for logging into the target.
// Network appliances (FortiGate, Cisco, etc.) often present rsa-sha2-512 host
// keys; explicit HostKeyAlgorithms avoids "unknown key algorithm" handshake failures.
func (s *Server) buildDownstreamConfig(user, password string, certMethods []ssh.AuthMethod) *ssh.ClientConfig {
	hostKeyAlgos := []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256,
		ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoRSASHA256,
		ssh.KeyAlgoRSASHA512,
		ssh.KeyAlgoRSA,
	}
	if password == "" && len(certMethods) > 0 {
		return &ssh.ClientConfig{
			User:              user,
			Auth:              certMethods,
			HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
			HostKeyAlgorithms: hostKeyAlgos,
			Timeout:           10 * time.Second,
		}
	}
	pw := password
	return &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, qs []string, _ []bool) ([]string, error) {
				out := make([]string, len(qs))
				for i := range qs {
					out[i] = pw
				}
				return out, nil
			}),
		},
		HostKeyCallback:   ssh.InsecureIgnoreHostKey(),
		HostKeyAlgorithms: hostKeyAlgos,
		Timeout:           10 * time.Second,
	}
}

func isDownstreamAuthFailure(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unable to authenticate") ||
		strings.Contains(msg, "no supported methods") ||
		strings.Contains(msg, "permission denied")
}

// forwardRequests forwards out-of-band ssh requests between sides.
func forwardRequests(in <-chan *ssh.Request, dst ssh.Channel, dir string) {
	for req := range in {
		ok, err := dst.SendRequest(req.Type, req.WantReply, req.Payload)
		if err != nil {
			log.Printf("forward req (%s): %v", dir, err)
		}
		if req.WantReply {
			req.Reply(ok, nil)
		}
	}
}

// prefixedWriter prepends a timestamp + direction tag to each chunk written to
// the recording file. Good enough for forensic replay; production should use
// the asciinema cast v2 format.
type prefixedWriter struct {
	w      io.Writer
	prefix string
}

func (p *prefixedWriter) Write(b []byte) (int, error) {
	header := fmt.Sprintf("[%s %s] ", time.Now().UTC().Format(time.RFC3339Nano), p.prefix)
	if _, err := p.w.Write([]byte(header)); err != nil {
		return 0, err
	}
	if _, err := p.w.Write(b); err != nil {
		return 0, err
	}
	if _, err := p.w.Write([]byte{'\n'}); err != nil {
		return 0, err
	}
	return len(b), nil
}

// ---- small helpers ----

func splitUserTarget(s string) (user, target string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '@' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func joinCSV(in []string) string {
	out := ""
	for i, s := range in {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func mustAtoi(s string) int64 {
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int64(r-'0')
	}
	return n
}

// buildCertSigner wraps a fresh user privkey + signed cert into an ssh.Signer
// suitable for outbound auth.
func buildCertSigner(privPEM, certAuth []byte) (ssh.Signer, error) {
	priv, err := ssh.ParsePrivateKey(privPEM)
	if err != nil {
		return nil, fmt.Errorf("parse user priv: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(certAuth)
	if err != nil {
		return nil, fmt.Errorf("parse user cert: %w", err)
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("expected ssh certificate")
	}
	cs, err := ssh.NewCertSigner(cert, priv)
	if err != nil {
		return nil, fmt.Errorf("new cert signer: %w", err)
	}
	return cs, nil
}

// verifyPwd re-implements the cryptox.VerifyPassword check here so this
// package doesn't import auth. Calls the cryptox API directly.
func verifyPwd(pw, encoded string) bool {
	return cryptoxVerify(pw, encoded)
}
