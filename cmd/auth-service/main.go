// auth-service exposes /login, /verify, user CRUD, group management, MFA
// enrollment, and (when configured) LDAP/AD authentication. It signs the
// short-lived JWTs every other service trusts.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/accounts"
	"github.com/example/pam-platform/internal/approval"
	"github.com/example/pam-platform/internal/auth"
	"github.com/example/pam-platform/internal/ccp"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/httpx"
	ldappkg "github.com/example/pam-platform/internal/ldap"
	"github.com/example/pam-platform/internal/mfa"
	"github.com/example/pam-platform/internal/policy"
	"github.com/example/pam-platform/internal/rdp"
	"github.com/example/pam-platform/internal/reports"
	"github.com/example/pam-platform/internal/roles"
	"github.com/example/pam-platform/internal/safes"
	"github.com/example/pam-platform/internal/sessions"
	"github.com/example/pam-platform/internal/sshlaunch"
	"github.com/example/pam-platform/internal/weblaunch"
	samlpkg "github.com/example/pam-platform/internal/saml"
	"github.com/example/pam-platform/internal/settings"
	"github.com/example/pam-platform/internal/threat"
	"github.com/example/pam-platform/internal/vault"
)

const (
	settingsKeyLDAP       = "ldap"
	settingsKeyLDAPSync   = "ldap_sync"
	settingsKeySAML       = "saml"
	settingsKeyMFAPolicy  = "mfa_policy"
	vaultLDAPBindPassword = "_ldap_bind_password"
	vaultSAMLCert         = "_saml_sp_cert"
	vaultSAMLKey          = "_saml_sp_key"

	// userPassthroughPWTTL bounds how long an AD/local password kept for
	// browser SSH passthrough remains usable. Refreshed on every login.
	userPassthroughPWTTL = 12 * time.Hour
)

// vaultUserPassthroughKey returns the vault key used to cache the portal
// password for a user. The password is encrypted with the vault master key
// just like every other secret and is removed on sign-out.
func vaultUserPassthroughKey(uid int64) string {
	return "_user_passthrough_pw_" + strconv.FormatInt(uid, 10)
}

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("auth: open db: %v", err)
	}
	defer d.Close()

	v, err := vault.New(d, config.Get("PAM_MASTER_KEY", ""))
	if err != nil {
		log.Fatalf("auth: vault: %v", err)
	}

	svc := &auth.Service{
		DB:          d,
		JWTSecret:   []byte(config.Get("PAM_JWT_SECRET", "dev-only-change-me")),
		JWTTTL:      config.GetDuration("PAM_JWT_TTL", 30*time.Minute),
		JWTIssuer:   "pam-platform",
		JWTAudience: "pam-services",
	}
	groupSvc := &groups.Service{DB: d}
	roleSvc := &roles.Service{DB: d}
	safeSvc := &safes.Service{DB: d}
	accountSvc := &accounts.Service{DB: d, Vault: v}
	ccpSvc := &ccp.Service{DB: d}
	threatSvc := &threat.Service{DB: d}
	reportsSvc := &reports.Service{DB: d}
	settingsStore := &settings.Store{DB: d}
	policyEng := &policy.Engine{DB: d}
	approvalSvc := &approval.Service{DB: d}
	rdpSvc := &rdp.Service{
		DB: d, Policy: policyEng, Approval: approvalSvc,
		Accounts: accountSvc, Groups: groupSvc,
		Vault:        &rdp.VaultAdapter{V: v},
		RecordingDir: config.Get("PAM_REC_DIR", "/recordings"),
		BrowserBase:  config.Get("PAM_PORTAL_URL", ""),
	}
	sshLaunchSvc := &sshlaunch.Service{
		DB: d, Policy: policyEng, Approval: approvalSvc, Groups: groupSvc,
		Vault: v, RecordingDir: config.Get("PAM_REC_DIR", "/recordings"),
		BrowserBase: config.Get("PAM_PORTAL_URL", ""),
	}
	webLaunchSvc := &weblaunch.Service{
		DB: d, Policy: policyEng, Approval: approvalSvc, Groups: groupSvc,
		Vault: v, BrowserBase: config.Get("PAM_PORTAL_URL", ""),
	}
	bus := events.NewForwarder(events.New(), config.Get("PAM_AUDIT_URL", "http://audit:8085"))

	bootstrap(svc, groupSvc, roleSvc, safeSvc)
	bootstrapSettings(settingsStore)

	mux := http.NewServeMux()
	httpx.RegisterHealth(mux)

	mux.HandleFunc("POST /login", loginHandler(svc, groupSvc, settingsStore, v, bus, threatSvc))
	mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Token string }
		if err := httpx.ReadJSON(r, &req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		c, err := svc.VerifyToken(req.Token)
		if err != nil {
			httpx.Error(w, http.StatusUnauthorized, err)
			return
		}
		httpx.JSON(w, http.StatusOK, c)
	})

	mux.HandleFunc("GET /users", func(w http.ResponseWriter, r *http.Request) {
		out, err := svc.ListUsers(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("POST /users", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := httpx.ReadJSON(r, &req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		id, err := svc.CreateUser(r.Context(), req.Username, req.Email, req.Password, req.Role)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "user.create", Severity: "info", Actor: req.Username})
		httpx.JSON(w, http.StatusCreated, map[string]int64{"id": id})
	})

	mux.HandleFunc("PUT /users/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var in auth.UpdateUserInput
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if err := svc.UpdateUser(r.Context(), id, in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("DELETE /users/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		actorID, _ := strconv.ParseInt(r.Header.Get("X-PAM-UID"), 10, 64)
		username, err := svc.DeleteUser(r.Context(), id, actorID)
		if err != nil {
			code := http.StatusBadRequest
			if err.Error() == "user not found" {
				code = http.StatusNotFound
			}
			httpx.Error(w, code, err)
			return
		}
		bus.Publish(events.Event{
			Source: "auth", Kind: "user.delete", Severity: "warn",
			Actor: r.Header.Get("X-PAM-User"), Target: username,
		})
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// --- Groups ---
	mux.HandleFunc("GET /groups", func(w http.ResponseWriter, r *http.Request) {
		out, err := groupSvc.List(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /groups", func(w http.ResponseWriter, r *http.Request) {
		var g groups.Group
		if err := httpx.ReadJSON(r, &g); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		id, err := groupSvc.Create(r.Context(), g)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "group.create", Severity: "info", Actor: g.Name})
		httpx.JSON(w, http.StatusCreated, map[string]int64{"id": id})
	})
	mux.HandleFunc("PUT /groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var g groups.Group
		if err := httpx.ReadJSON(r, &g); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		g.ID = id
		if err := groupSvc.Update(r.Context(), g); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("DELETE /groups/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := groupSvc.Delete(r.Context(), id); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})
	mux.HandleFunc("GET /groups/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		out, err := groupSvc.ListMembers(r.Context(), id)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /groups/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		gid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var req struct{ UserID int64 `json:"user_id"` }
		if err := httpx.ReadJSON(r, &req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if err := groupSvc.AddMember(r.Context(), req.UserID, gid); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("DELETE /groups/{id}/members/{userId}", func(w http.ResponseWriter, r *http.Request) {
		gid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		uid, _ := strconv.ParseInt(r.PathValue("userId"), 10, 64)
		if err := groupSvc.RemoveMember(r.Context(), uid, gid); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /users/{id}/groups", func(w http.ResponseWriter, r *http.Request) {
		uid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		out, err := groupSvc.UserGroups(r.Context(), uid)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	// --- Roles ---
	mux.HandleFunc("GET /roles", func(w http.ResponseWriter, r *http.Request) {
		out, err := roleSvc.List(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /roles", func(w http.ResponseWriter, r *http.Request) {
		var in roles.Role
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		id, err := roleSvc.Create(r.Context(), in)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "role.create", Severity: "info", Actor: in.Name})
		httpx.JSON(w, http.StatusCreated, map[string]int64{"id": id})
	})
	mux.HandleFunc("PUT /roles/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var in struct {
			Description string `json:"description"`
		}
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if err := roleSvc.Update(r.Context(), id, in.Description); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("DELETE /roles/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := roleSvc.Delete(r.Context(), id); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})

	mux.HandleFunc("GET /users/{id}/effective-roles", func(w http.ResponseWriter, r *http.Request) {
		uid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var role string
		if err := d.QueryRowContext(r.Context(), `SELECT role FROM users WHERE id=?`, uid).Scan(&role); err != nil {
			httpx.Error(w, http.StatusNotFound, err)
			return
		}
		roles, err := groupSvc.EffectiveRoles(r.Context(), uid, role)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"roles": roles})
	})

	// --- MFA ---
	mux.HandleFunc("POST /users/{id}/mfa/enroll", func(w http.ResponseWriter, r *http.Request) {
		uid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := checkMFAAccess(r, uid, true); err != nil {
			httpx.Error(w, http.StatusForbidden, err)
			return
		}
		u, err := svc.GetUserByID(r.Context(), uid)
		if err != nil {
			httpx.Error(w, http.StatusNotFound, err)
			return
		}
		if u.MFAEnabled {
			httpx.Error(w, http.StatusBadRequest, errors.New("MFA already enabled — use Reset MFA if re-enrollment is needed"))
			return
		}
		secret, err := svc.GetMFASecret(r.Context(), uid)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		if secret == "" {
			secret, err = mfa.NewSecret()
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, err)
				return
			}
			if err := svc.SetMFASecret(r.Context(), uid, secret); err != nil {
				httpx.Error(w, http.StatusInternalServerError, err)
				return
			}
		}
		uri := mfa.OtpAuthURI("PAM Platform", u.Username, secret)
		qr, err := mfa.QRPNGDataURI(uri, 256)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{
			"secret":       secret,
			"otpauth_uri":  uri,
			"qr_data_uri":  qr,
		})
	})
	mux.HandleFunc("POST /users/{id}/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		uid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := checkMFAAccess(r, uid, true); err != nil {
			httpx.Error(w, http.StatusForbidden, err)
			return
		}
		var req struct{ Code string `json:"code"` }
		if err := httpx.ReadJSON(r, &req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		secret, err := svc.GetMFASecret(r.Context(), uid)
		if err != nil || secret == "" {
			httpx.Error(w, http.StatusBadRequest, errors.New("no MFA enrollment in progress"))
			return
		}
		if !mfa.Verify(secret, mfa.NormalizeOTP(req.Code)) {
			httpx.Error(w, http.StatusUnauthorized, errors.New("invalid code — use the current code from your authenticator app"))
			return
		}
		if err := svc.EnableMFA(r.Context(), uid); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "mfa.enabled", Severity: "info", Actor: strconv.FormatInt(uid, 10)})
		if r.Header.Get("X-PAM-Scope") == "mfa_enroll" {
			u, err := svc.GetUserByID(r.Context(), uid)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, err)
				return
			}
			roles, _ := groupSvc.EffectiveRoles(r.Context(), u.ID, u.Role)
			_ = svc.RecordLogin(r.Context(), u.ID)
			tok, err := svc.IssueToken(u)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, err)
				return
			}
			httpx.JSON(w, http.StatusOK, map[string]any{
				"status": "ok",
				"token":  tok,
				"user":   u,
				"roles":  roles,
			})
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("DELETE /users/{id}/mfa", func(w http.ResponseWriter, r *http.Request) {
		uid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		actorID, _ := strconv.ParseInt(r.Header.Get("X-PAM-UID"), 10, 64)
		actorRole := r.Header.Get("X-PAM-Role")
		if actorRole != "admin" {
			if actorID != uid {
				httpx.Error(w, http.StatusForbidden, errors.New("forbidden"))
				return
			}
			pol, _ := settingsStore.Get(r.Context(), settingsKeyMFAPolicy)
			if auth.EffectiveMFAPolicy(pol) == "required" {
				httpx.Error(w, http.StatusForbidden, errors.New("MFA is required by policy — contact an administrator"))
				return
			}
		}
		exempt := actorRole == "admin"
		if err := svc.DisableMFA(r.Context(), uid, exempt); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		bus.Publish(events.Event{
			Source: "auth", Kind: "mfa.disabled", Severity: "warn",
			Actor: r.Header.Get("X-PAM-User"), Target: strconv.FormatInt(uid, 10),
		})
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "disabled"})
	})
	mux.HandleFunc("POST /users/{id}/mfa/reset", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PAM-Role") != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin role required"))
			return
		}
		uid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := svc.ResetMFA(r.Context(), uid); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		bus.Publish(events.Event{
			Source: "auth", Kind: "mfa.reset", Severity: "warn",
			Actor: r.Header.Get("X-PAM-User"), Target: strconv.FormatInt(uid, 10),
		})
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "reset"})
	})

	// --- Settings & LDAP ---
	mux.HandleFunc("GET /settings/ldap", func(w http.ResponseWriter, r *http.Request) {
		cfg := loadLDAPConfig(r.Context(), settingsStore, v)
		httpx.JSON(w, http.StatusOK, cfg)
	})
	mux.HandleFunc("PUT /settings/ldap", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ldappkg.Config
			BindPassword string `json:"bind_password,omitempty"`
		}
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		cfg := in.Config
		if in.BindPassword != "" {
			if err := v.PutSecret(r.Context(), vaultLDAPBindPassword, []byte(in.BindPassword), nil); err != nil {
				httpx.Error(w, http.StatusInternalServerError, err)
				return
			}
			cfg.BindPasswordSet = true
		}
		// Preserve flag if password not being updated.
		if !cfg.BindPasswordSet {
			if _, err := v.GetSecret(r.Context(), vaultLDAPBindPassword); err == nil {
				cfg.BindPasswordSet = true
			}
		}
		if err := settingsStore.SetJSON(r.Context(), settingsKeyLDAP, cfg); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "ldap.config.updated", Severity: "info"})
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /settings/ldap/test", func(w http.ResponseWriter, r *http.Request) {
		cfg := loadLDAPConfig(r.Context(), settingsStore, v)
		pw, _ := v.GetSecret(r.Context(), vaultLDAPBindPassword)
		client := &ldappkg.Client{Cfg: cfg, Password: string(pw)}
		if err := client.TestConnection(r.Context()); err != nil {
			httpx.JSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("GET /settings/ldap/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PAM-Role") != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin required"))
			return
		}
		sel := loadLDAPSyncSelection(r.Context(), settingsStore)
		httpx.JSON(w, http.StatusOK, sel)
	})
	mux.HandleFunc("PUT /settings/ldap/sync", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PAM-Role") != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin required"))
			return
		}
		var sel ldappkg.SyncSelection
		if err := httpx.ReadJSON(r, &sel); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if err := settingsStore.SetJSON(r.Context(), settingsKeyLDAPSync, sel); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "ldap.sync.selection.updated", Severity: "info"})
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /settings/ldap/browse", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PAM-Role") != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin required"))
			return
		}
		cfg := loadLDAPConfig(r.Context(), settingsStore, v)
		if !cfg.Enabled {
			httpx.Error(w, http.StatusBadRequest, errors.New("ldap is not enabled"))
			return
		}
		pw, _ := v.GetSecret(r.Context(), vaultLDAPBindPassword)
		client := &ldappkg.Client{Cfg: cfg, Password: string(pw)}
		q := r.URL.Query().Get("q")
		typ := r.URL.Query().Get("type")
		var (
			out []ldappkg.DirectoryEntry
			err error
		)
		switch typ {
		case "groups":
			out, err = client.SearchGroups(q, 100)
		default:
			out, err = client.SearchUsers(q, 100)
		}
		if err != nil {
			httpx.Error(w, http.StatusBadGateway, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /settings/ldap/sync/run", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-PAM-Role") != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin required"))
			return
		}
		res, err := executeLDAPSync(r.Context(), svc, groupSvc, settingsStore, v)
		if err != nil {
			if errors.Is(err, errLDAPSyncNothingSelected) {
				httpx.Error(w, http.StatusBadRequest, err)
				return
			}
			if errors.Is(err, errLDAPSyncDisabled) {
				httpx.Error(w, http.StatusBadRequest, err)
				return
			}
			httpx.Error(w, http.StatusBadGateway, err)
			return
		}
		bus.Publish(events.Event{
			Source: "auth", Kind: "ldap.sync.completed", Severity: "info",
			Detail: map[string]string{
				"users":  strconv.Itoa(res.UsersSynced),
				"groups": strconv.Itoa(res.GroupsSynced),
			},
		})
		httpx.JSON(w, http.StatusOK, res)
	})

	// --- SAML ---
	mux.HandleFunc("GET /settings/saml", func(w http.ResponseWriter, r *http.Request) {
		cfg := loadSAMLConfig(r.Context(), settingsStore, v)
		httpx.JSON(w, http.StatusOK, cfg)
	})
	mux.HandleFunc("PUT /settings/saml", func(w http.ResponseWriter, r *http.Request) {
		var cfg samlpkg.Config
		if err := httpx.ReadJSON(r, &cfg); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if cfg.Enabled && cfg.RootURL == "" {
			httpx.Error(w, http.StatusBadRequest, errors.New("root_url is required when SAML is enabled"))
			return
		}
		// Auto-generate SP keypair on first save (or when missing).
		if cfg.Enabled {
			if _, err := v.GetSecret(r.Context(), vaultSAMLCert); err != nil {
				cert, key, err := samlpkg.GenerateSPKeypair("pam-platform-saml-sp")
				if err != nil {
					httpx.Error(w, http.StatusInternalServerError, err)
					return
				}
				if err := v.PutSecret(r.Context(), vaultSAMLCert, cert, nil); err != nil {
					httpx.Error(w, http.StatusInternalServerError, err)
					return
				}
				if err := v.PutSecret(r.Context(), vaultSAMLKey, key, nil); err != nil {
					httpx.Error(w, http.StatusInternalServerError, err)
					return
				}
			}
			cfg.SPCertSet = true
		}
		if err := settingsStore.SetJSON(r.Context(), settingsKeySAML, cfg); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "saml.config.updated", Severity: "info"})
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /saml/metadata", func(w http.ResponseWriter, r *http.Request) {
		p, err := buildSAMLProvider(r.Context(), settingsStore, v)
		if err != nil {
			httpx.Error(w, http.StatusServiceUnavailable, err)
			return
		}
		md, err := p.Metadata()
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
		w.Header().Set("Content-Disposition", `attachment; filename="pam-sp-metadata.xml"`)
		w.Write(md)
	})
	mux.HandleFunc("GET /saml/login", func(w http.ResponseWriter, r *http.Request) {
		p, err := buildSAMLProvider(r.Context(), settingsStore, v)
		if err != nil {
			httpx.Error(w, http.StatusServiceUnavailable, err)
			return
		}
		u, err := p.MakeAuthnRequestURL(r.URL.Query().Get("next"))
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		http.Redirect(w, r, u, http.StatusFound)
	})
	mux.HandleFunc("POST /saml/acs", func(w http.ResponseWriter, r *http.Request) {
		samlACSHandler(w, r, svc, groupSvc, settingsStore, v, bus)
	})

	mux.HandleFunc("GET /sso/status", func(w http.ResponseWriter, r *http.Request) {
		s := loadSAMLConfig(r.Context(), settingsStore, v)
		httpx.JSON(w, http.StatusOK, map[string]any{
			"saml_enabled":   s.Enabled && s.IdPMetadataXML != "" && s.SPCertSet,
			"saml_login_url": "/api/auth/saml/login",
		})
	})
	mux.HandleFunc("GET /settings", func(w http.ResponseWriter, r *http.Request) {
		all, err := settingsStore.All(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		// Don't leak the LDAP password (it's never stored here anyway).
		httpx.JSON(w, http.StatusOK, all)
	})
	mux.HandleFunc("PUT /settings/{key}", func(w http.ResponseWriter, r *http.Request) {
		key := r.PathValue("key")
		if strings.HasPrefix(key, "_") {
			httpx.Error(w, http.StatusBadRequest, errors.New("reserved key"))
			return
		}
		var req struct{ Value string `json:"value"` }
		if err := httpx.ReadJSON(r, &req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if err := settingsStore.Set(r.Context(), key, req.Value); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// --- Safes ---
	mux.HandleFunc("GET /safes", func(w http.ResponseWriter, r *http.Request) {
		out, err := safeSvc.List(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /safes", func(w http.ResponseWriter, r *http.Request) {
		var in safes.Safe
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		id, err := safeSvc.Create(r.Context(), in)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "safe.create", Severity: "info", Actor: in.Name})
		httpx.JSON(w, http.StatusCreated, map[string]int64{"id": id})
	})
	mux.HandleFunc("PUT /safes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var in safes.Safe
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		in.ID = id
		if err := safeSvc.Update(r.Context(), in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("DELETE /safes/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := safeSvc.Delete(r.Context(), id); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})
	mux.HandleFunc("GET /safes/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		out, err := safeSvc.ListMembers(r.Context(), id)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /safes/{id}/members", func(w http.ResponseWriter, r *http.Request) {
		safeID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var in struct {
			PrincipalType string `json:"principal_type"`
			PrincipalID   int64  `json:"principal_id"`
			Permissions   string `json:"permissions"`
		}
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if err := safeSvc.AddMember(r.Context(), safeID, in.PrincipalType, in.PrincipalID, in.Permissions); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("DELETE /safes/{id}/members/{ptype}/{pid}", func(w http.ResponseWriter, r *http.Request) {
		safeID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		pid, _ := strconv.ParseInt(r.PathValue("pid"), 10, 64)
		if err := safeSvc.RemoveMember(r.Context(), safeID, r.PathValue("ptype"), pid); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// --- Privileged Accounts ---
	mux.HandleFunc("GET /accounts", func(w http.ResponseWriter, r *http.Request) {
		safeID, _ := strconv.ParseInt(r.URL.Query().Get("safe_id"), 10, 64)
		out, err := accountSvc.List(r.Context(), safeID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /accounts", func(w http.ResponseWriter, r *http.Request) {
		var in accounts.CreateInput
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		id, err := accountSvc.Create(r.Context(), in)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "account.create", Severity: "info", Target: in.Name})
		httpx.JSON(w, http.StatusCreated, map[string]int64{"id": id})
	})
	mux.HandleFunc("PUT /accounts/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var in accounts.PrivilegedAccount
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		in.ID = id
		if err := accountSvc.Update(r.Context(), in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("DELETE /accounts/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := accountSvc.Delete(r.Context(), id); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})
	mux.HandleFunc("POST /accounts/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		actor := r.Header.Get("X-PAM-User")
		if actor == "" {
			actor = "admin"
		}
		if err := accountSvc.Rotate(r.Context(), id, actor); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "account.rotate", Severity: "info", Actor: actor, Target: strconv.FormatInt(id, 10)})
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "rotated"})
	})
	mux.HandleFunc("GET /accounts/{id}/history", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		out, err := accountSvc.History(r.Context(), id, 50)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /accounts/{id}/checkout", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		uidStr := r.Header.Get("X-PAM-UID")
		uid, _ := strconv.ParseInt(uidStr, 10, 64)
		var in struct {
			Reason     string `json:"reason"`
			BreakGlass bool   `json:"break_glass"`
		}
		_ = httpx.ReadJSON(r, &in)
		res, err := accountSvc.Checkout(r.Context(), id, uid, in.Reason, in.BreakGlass)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		sev := "info"
		if in.BreakGlass {
			sev = "warn"
		}
		bg := "false"
		if in.BreakGlass {
			bg = "true"
		}
		bus.Publish(events.Event{Source: "auth", Kind: "credential.checkout", Severity: sev,
			Actor: r.Header.Get("X-PAM-User"), Target: strconv.FormatInt(id, 10),
			Detail: map[string]string{"reason": in.Reason, "break_glass": bg}})
		httpx.JSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("POST /checkouts/{id}/return", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := accountSvc.Return(r.Context(), id); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /checkouts", func(w http.ResponseWriter, r *http.Request) {
		userID, _ := strconv.ParseInt(r.URL.Query().Get("user_id"), 10, 64)
		out, err := accountSvc.ListCheckouts(r.Context(), userID, 100)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	// --- RDP launch (CyberArk-style PSM-lite) ---
	mux.HandleFunc("POST /targets/{id}/rdp-launch", func(w http.ResponseWriter, r *http.Request) {
		targetID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		uid, _ := strconv.ParseInt(r.Header.Get("X-PAM-UID"), 10, 64)
		role := r.Header.Get("X-PAM-Role")
		user := r.Header.Get("X-PAM-User")
		var in struct {
			Reason string `json:"reason"`
		}
		_ = httpx.ReadJSON(r, &in)
		clientIP := r.Header.Get("X-Forwarded-For")
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		res, err := rdpSvc.Launch(r.Context(), targetID, uid, role, in.Reason, clientIP)
		if err != nil {
			switch {
			case errors.Is(err, rdp.ErrTargetNotFound):
				httpx.Error(w, http.StatusNotFound, err)
			case errors.Is(err, rdp.ErrNotRDP):
				httpx.Error(w, http.StatusBadRequest, err)
			case errors.Is(err, rdp.ErrPolicyDenied):
				httpx.Error(w, http.StatusForbidden, err)
			case errors.Is(err, rdp.ErrApprovalRequired), errors.Is(err, rdp.ErrDualControl):
				httpx.Error(w, http.StatusForbidden, err)
			case errors.Is(err, accounts.ErrNoAccountForTarget):
				httpx.Error(w, http.StatusPreconditionFailed, err)
			default:
				httpx.Error(w, http.StatusBadRequest, err)
			}
			return
		}
		bus.Publish(events.Event{
			Source: "auth", Kind: "rdp.launch", Severity: "info",
			Actor: user, Target: strconv.FormatInt(targetID, 10),
			Detail: map[string]string{
				"session_id": res.SessionID, "account": res.AccountName,
				"checkout_id": strconv.FormatInt(res.CheckoutID, 10),
			},
		})
		httpx.JSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("GET /sessions/{id}/rdp-native", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("id")
		uid, _ := strconv.ParseInt(r.Header.Get("X-PAM-UID"), 10, 64)
		out, err := rdpSvc.NativeArtifactsForSession(r.Context(), sessionID, uid)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("POST /targets/{id}/ssh-launch", func(w http.ResponseWriter, r *http.Request) {
		targetID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		uid, _ := strconv.ParseInt(r.Header.Get("X-PAM-UID"), 10, 64)
		role := r.Header.Get("X-PAM-Role")
		user := r.Header.Get("X-PAM-User")
		var in struct {
			Reason         string `json:"reason"`
			PortalPassword string `json:"portal_password"`
			MFACode        string `json:"mfa_code"`
		}
		_ = httpx.ReadJSON(r, &in)
		// Fall back to the cached portal password stored at login. The browser
		// usually omits the password now and lets the server use this cache so
		// the user doesn't have to re-enter it.
		if in.PortalPassword == "" && uid > 0 {
			if pw, err := v.GetSecret(r.Context(), vaultUserPassthroughKey(uid)); err == nil && len(pw) > 0 {
				in.PortalPassword = string(pw)
			}
		}
		// MFA gate: if the user has MFA enabled they must supply a valid TOTP
		// code with every browser SSH launch. If no code was sent, return 202
		// so the portal can show the MFA prompt and retry.
		if uid > 0 {
			u, err := svc.GetUserByID(r.Context(), uid)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, err)
				return
			}
			if u.MFAEnabled && !u.MFAExempt {
				if in.MFACode == "" {
					httpx.JSON(w, http.StatusAccepted, map[string]any{"mfa_required": true})
					return
				}
				secret, err := svc.GetMFASecret(r.Context(), uid)
				if err != nil || secret == "" {
					httpx.Error(w, http.StatusUnauthorized, errors.New("MFA secret not found — re-enroll MFA"))
					return
				}
				if !mfa.Verify(secret, mfa.NormalizeOTP(in.MFACode)) {
					httpx.Error(w, http.StatusUnauthorized, errors.New("invalid MFA code — check your authenticator app"))
					return
				}
			}
		}
		clientIP := r.Header.Get("X-Forwarded-For")
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		res, err := sshLaunchSvc.Launch(r.Context(), targetID, uid, role, in.Reason, clientIP, in.PortalPassword)
		if err != nil {
			switch {
			case errors.Is(err, sshlaunch.ErrTargetNotFound):
				httpx.Error(w, http.StatusNotFound, err)
			case errors.Is(err, sshlaunch.ErrNotSSH):
				httpx.Error(w, http.StatusBadRequest, err)
			case errors.Is(err, sshlaunch.ErrPolicyDenied):
				httpx.Error(w, http.StatusForbidden, err)
			case errors.Is(err, sshlaunch.ErrApprovalRequired):
				httpx.Error(w, http.StatusForbidden, err)
			default:
				httpx.Error(w, http.StatusBadRequest, err)
			}
			return
		}
		bus.Publish(events.Event{
			Source: "auth", Kind: "ssh.launch", Severity: "info",
			Actor: user, Target: strconv.FormatInt(targetID, 10),
			Detail: map[string]string{"session_id": res.SessionID, "target": res.TargetName},
		})
		httpx.JSON(w, http.StatusOK, res)
	})

	// --- End web session (viewer close / End button; owner or admin) ---
	mux.HandleFunc("POST /web-session/{id}/end", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("id")
		uid, _ := strconv.ParseInt(r.Header.Get("X-PAM-UID"), 10, 64)
		role := r.Header.Get("X-PAM-Role")
		var in struct {
			Reason string `json:"reason"`
		}
		_ = httpx.ReadJSON(r, &in)
		var ownerID int64
		var protocol string
		err := d.QueryRowContext(r.Context(), `
			SELECT user_id, COALESCE(protocol,'') FROM sessions WHERE id = ?`, sessionID).
			Scan(&ownerID, &protocol)
		if err != nil {
			httpx.Error(w, http.StatusNotFound, errors.New("session not found"))
			return
		}
		if protocol != "web" {
			httpx.Error(w, http.StatusBadRequest, errors.New("not a web session"))
			return
		}
		if role != "admin" && (uid <= 0 || ownerID != uid) {
			httpx.Error(w, http.StatusForbidden, errors.New("session belongs to another user"))
			return
		}
		reason := in.Reason
		if reason == "" {
			reason = "closed"
		}
		ok, err := sessions.End(r.Context(), d, v, sessionID, reason)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		if !ok {
			httpx.Error(w, http.StatusConflict, errors.New("session already ended"))
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ended"})
	})

	// --- Web session info (used by web-viewer.html to show target name + creds) ---
	mux.HandleFunc("GET /web-session/{id}", func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.PathValue("id")
		uid, _ := strconv.ParseInt(r.Header.Get("X-PAM-UID"), 10, 64)
		var (
			userID   int64
			targetID int64
			tName    string
			webURL   string
			ended    interface{}
		)
		err := d.QueryRowContext(r.Context(), `
			SELECT s.user_id, s.target_id, t.name, COALESCE(t.web_url,''), s.ended_at
			FROM sessions s JOIN targets t ON t.id = s.target_id
			WHERE s.id = ?`, sessionID).
			Scan(&userID, &targetID, &tName, &webURL, &ended)
		if err != nil {
			httpx.Error(w, http.StatusNotFound, errors.New("session not found"))
			return
		}
		if uid > 0 && userID != uid {
			httpx.Error(w, http.StatusForbidden, errors.New("session belongs to another user"))
			return
		}
		creds, _ := weblaunch.LoadSessionCreds(r.Context(), v, sessionID)
		httpx.JSON(w, http.StatusOK, map[string]interface{}{
			"session_id":  sessionID,
			"target_name": tName,
			"web_url":     webURL,
			"username":    creds.Username,
			"password":    creds.Password,
			"active":      ended == nil,
		})
	})

	// --- Web launch (recorded browser-proxy session for web consoles) ---
	mux.HandleFunc("POST /targets/{id}/web-launch", func(w http.ResponseWriter, r *http.Request) {
		targetID, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		uid, _ := strconv.ParseInt(r.Header.Get("X-PAM-UID"), 10, 64)
		role := r.Header.Get("X-PAM-Role")
		user := r.Header.Get("X-PAM-User")
		var in struct {
			Reason string `json:"reason"`
		}
		_ = httpx.ReadJSON(r, &in)
		clientIP := r.Header.Get("X-Forwarded-For")
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		res, err := webLaunchSvc.Launch(r.Context(), targetID, uid, role, in.Reason, clientIP)
		if err != nil {
			switch {
			case errors.Is(err, weblaunch.ErrTargetNotFound):
				httpx.Error(w, http.StatusNotFound, err)
			case errors.Is(err, weblaunch.ErrNotWeb):
				httpx.Error(w, http.StatusBadRequest, err)
			case errors.Is(err, weblaunch.ErrPolicyDenied):
				httpx.Error(w, http.StatusForbidden, err)
			case errors.Is(err, weblaunch.ErrApprovalRequired):
				httpx.Error(w, http.StatusForbidden, err)
			default:
				httpx.Error(w, http.StatusBadRequest, err)
			}
			return
		}
		bus.Publish(events.Event{
			Source: "auth", Kind: "web.launch", Severity: "info",
			Actor: user, Target: strconv.FormatInt(targetID, 10),
			Detail: map[string]string{"session_id": res.SessionID, "target": res.TargetName, "url": res.WebURL},
		})
		httpx.JSON(w, http.StatusOK, res)
	})

	// --- App credentials (CCP) ---
	mux.HandleFunc("GET /apps", func(w http.ResponseWriter, r *http.Request) {
		out, err := ccpSvc.List(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /apps", func(w http.ResponseWriter, r *http.Request) {
		var in ccp.App
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		res, err := ccpSvc.Create(r.Context(), in)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "app.create", Severity: "info", Actor: in.Name})
		httpx.JSON(w, http.StatusCreated, res)
	})
	mux.HandleFunc("PUT /apps/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var in ccp.App
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		in.ID = id
		if err := ccpSvc.Update(r.Context(), in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /apps/{id}/rotate", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		res, err := ccpSvc.Rotate(r.Context(), id)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "app.rotate", Severity: "warn",
			Target: strconv.FormatInt(id, 10)})
		httpx.JSON(w, http.StatusOK, res)
	})
	mux.HandleFunc("DELETE /apps/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := ccpSvc.Delete(r.Context(), id); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})

	// --- Reports ---
	mux.HandleFunc("GET /reports/summary", func(w http.ResponseWriter, r *http.Request) {
		sum, err := reportsSvc.Summary(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, sum)
	})
	mux.HandleFunc("GET /reports/access-by-user", func(w http.ResponseWriter, r *http.Request) {
		days, _ := strconv.Atoi(r.URL.Query().Get("days"))
		out, err := reportsSvc.AccessByUser(r.Context(), days)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("GET /reports/password-age", func(w http.ResponseWriter, r *http.Request) {
		out, err := reportsSvc.PasswordAge(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	// --- Threat alerts ---
	mux.HandleFunc("GET /alerts", func(w http.ResponseWriter, r *http.Request) {
		incAck := r.URL.Query().Get("all") == "1"
		out, err := threatSvc.List(r.Context(), 200, incAck)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /alerts/{id}/ack", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := threatSvc.Acknowledge(r.Context(), id); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	addr := config.Get("PAM_AUTH_ADDR", ":8081")
	go runLDAPSyncWorker(svc, groupSvc, settingsStore, v, bus)
	log.Printf("auth-service listening on %s", addr)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

// loginHandler is split out because the login flow now has three branches:
// local password, LDAP bind, and an MFA challenge step.
func loginHandler(
	svc *auth.Service,
	groupSvc *groups.Service,
	settingsStore *settings.Store,
	v *vault.Vault,
	bus events.Publisher,
	threatSvc *threat.Service,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username, Password, OTP string
			DeviceAuth              bool `json:"device_auth"`
		}
		if err := httpx.ReadJSON(r, &req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if req.Username == "" || req.Password == "" {
			httpx.Error(w, http.StatusBadRequest, errors.New("username and password required"))
			return
		}
		password := req.Password
		otp := mfa.NormalizeOTP(req.OTP)
		if otp == "" {
			if base, appended := mfa.SplitAppendedOTP(password); appended != "" {
				password = base
				otp = appended
			}
		}
		// Internal data-plane callers (SSH proxy, TACACS) set device_auth.
		deviceAuth := req.DeviceAuth || r.Header.Get("X-PAM-Device-Auth") == "1"

		ctx := r.Context()
		loginID := strings.TrimSpace(req.Username)
		ldapCfg := loadLDAPConfig(ctx, settingsStore, v)
		ldapEnabled := ldapCfg.Enabled && ldapCfg.URL != ""

		u, err := authenticateLogin(ctx, svc, groupSvc, settingsStore, v, loginID, password, ldapEnabled)
		if err != nil {
			bus.Publish(events.Event{Source: "auth", Kind: "login.failed", Severity: "warn", Actor: req.Username, Detail: map[string]string{"error": err.Error()}})
			msg := loginErrorMessage(err)
			httpx.Error(w, http.StatusUnauthorized, errors.New(msg))
			return
		}
		if u.Disabled {
			bus.Publish(events.Event{Source: "auth", Kind: "login.failed", Severity: "warn", Actor: req.Username, Detail: map[string]string{"error": "account disabled"}})
			httpx.Error(w, http.StatusUnauthorized, errors.New("account disabled"))
			return
		}

		mfaPolicy, _ := settingsStore.Get(ctx, settingsKeyMFAPolicy)
		effectivePolicy := auth.EffectiveMFAPolicy(mfaPolicy)
		var dec auth.MFALoginDecision
		if deviceAuth {
			dec, err = svc.LoginMFADecisionForDevice(ctx, u)
		} else {
			dec, err = svc.LoginMFADecisionForUser(ctx, u, mfaPolicy)
		}
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		if dec.RequireEnrollment {
			tok, err := svc.IssueEnrollmentToken(u)
			if err != nil {
				httpx.Error(w, http.StatusInternalServerError, err)
				return
			}
			httpx.JSON(w, http.StatusAccepted, map[string]any{
				"mfa_enrollment_required": true,
				"enrollment_token":        tok,
				"user":                    u,
				"mfa_policy":              effectivePolicy,
			})
			return
		}
		if dec.RequireOTP {
			secret, _ := svc.GetMFASecret(ctx, u.ID)
			if secret == "" {
				httpx.Error(w, http.StatusUnauthorized, errors.New("MFA required but not enrolled"))
				return
			}
			if otp == "" {
				if deviceAuth {
					httpx.Error(w, http.StatusUnauthorized, errors.New("MFA required — enter the code in the SSH MFA prompt, or append it to the password on FortiGate/web GUI login"))
					return
				}
				httpx.JSON(w, http.StatusAccepted, map[string]any{
					"mfa_required": true,
					"user_id":      u.ID,
					"mfa_policy":   effectivePolicy,
				})
				return
			}
			if !mfa.Verify(secret, otp) {
				bus.Publish(events.Event{Source: "auth", Kind: "mfa.failed", Severity: "warn", Actor: u.Username})
				httpx.Error(w, http.StatusUnauthorized, errors.New("invalid MFA code — use the current 6-digit code from your authenticator app (check device time is synced)"))
				return
			}
		}

		// Resolve effective roles for the token claim.
		roles, _ := groupSvc.EffectiveRoles(ctx, u.ID, u.Role)
		_ = svc.RecordLogin(ctx, u.ID)
		tok, err := svc.IssueToken(u)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		// Cache the password so browser SSH launches do not re-prompt the
		// user. Encrypted in vault, refreshed on each login, cleared on
		// sign-out and on rotation.
		if !deviceAuth && password != "" {
			due := time.Now().Add(userPassthroughPWTTL)
			_ = v.PutSecret(ctx, vaultUserPassthroughKey(u.ID), []byte(password), &due)
		}
		clientIP := r.Header.Get("X-Forwarded-For")
		if clientIP == "" {
			clientIP = r.RemoteAddr
		}
		bus.Publish(events.Event{Source: "auth", Kind: "login.ok", Severity: "info",
			Actor: u.Username, Detail: map[string]string{"ip": clientIP}})
		// Run threat analytics off the request path — anomalies become alerts
		// surfaced on the Threats tab.
		go threatSvc.EvaluateLogin(context.Background(), u.ID, u.Username, clientIP, time.Now())
		httpx.JSON(w, http.StatusOK, map[string]any{
			"token":      tok,
			"user":       u,
			"roles":      roles,
			"mfa_policy": effectivePolicy,
		})
	}
}

func tryLocal(ctx context.Context, svc *auth.Service, loginID, password string) (*auth.User, error) {
	return svc.AuthenticateByLoginID(ctx, loginID, password)
}

func authenticateLogin(
	ctx context.Context,
	svc *auth.Service,
	groupSvc *groups.Service,
	settingsStore *settings.Store,
	v *vault.Vault,
	loginID, password string,
	ldapEnabled bool,
) (*auth.User, error) {
	existing, _ := svc.FindByLoginID(ctx, loginID)
	if existing != nil && existing.Source == "saml" {
		return nil, errors.New("use SSO to sign in")
	}

	if ldapEnabled {
		u, ldapErr := tryLDAP(ctx, svc, groupSvc, settingsStore, v, loginID, password)
		if u != nil {
			return u, nil
		}
		if existing != nil && existing.Source == "ldap" {
			return nil, ldapErr
		}
	}

	u, _ := tryLocal(ctx, svc, loginID, password)
	if u != nil {
		return u, nil
	}
	return nil, errors.New("invalid credentials")
}

func loginErrorMessage(err error) string {
	if err == nil {
		return "invalid credentials"
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not imported from AD"):
		return msg
	case strings.Contains(msg, "LDAP bind password"):
		return msg
	case strings.Contains(msg, "ldap: service bind"):
		return "LDAP service account failed — re-save LDAP settings with the bind password (Settings → LDAP)"
	case strings.Contains(msg, "ldap: dial"):
		return "Cannot reach LDAP server — check URL, firewall, and TLS settings"
	case msg == "use SSO to sign in":
		return msg
	case msg == "account disabled":
		return msg
	default:
		return "invalid credentials"
	}
}

func tryLDAP(
	ctx context.Context,
	svc *auth.Service,
	groupSvc *groups.Service,
	settingsStore *settings.Store,
	v *vault.Vault,
	username, password string,
) (*auth.User, error) {
	cfg := loadLDAPConfig(ctx, settingsStore, v)
	if !cfg.Enabled || cfg.URL == "" {
		return nil, errors.New("ldap disabled")
	}
	bindPW, bindErr := v.GetSecret(ctx, vaultLDAPBindPassword)
	if cfg.BindDN != "" && (bindErr != nil || len(bindPW) == 0) {
		return nil, errors.New("LDAP bind password missing or unreadable — open Settings → LDAP, re-enter the bind password, and save")
	}
	client := &ldappkg.Client{Cfg: cfg, Password: string(bindPW)}
	lu, err := client.Authenticate(ctx, username, password)
	if err != nil {
		return nil, err
	}
	imported, _ := svc.FindByLoginID(ctx, username)
	if imported == nil {
		imported, _ = svc.FindByLoginID(ctx, lu.Username)
	}
	if imported == nil && lu.Email != "" {
		imported, _ = svc.FindByLoginID(ctx, lu.Email)
	}
	if imported == nil {
		return nil, errors.New("account not imported from AD — ask an admin to sync this user")
	}
	// Map LDAP groups → first matching local group's role, else default.
	role := cfg.DefaultRole
	if role == "" {
		role = "user"
	}
	var matchedGroupIDs []int64
	for _, dn := range lu.Groups {
		g, _ := groupSvc.FindByLDAPDN(ctx, dn)
		if g != nil {
			matchedGroupIDs = append(matchedGroupIDs, g.ID)
			if g.Role == "admin" {
				role = "admin"
			} else if role != "admin" {
				role = g.Role
			}
		}
	}
	u, err := svc.UpsertLDAPUser(ctx, lu.Username, lu.Email, role, lu.DN)
	if err != nil {
		return nil, err
	}
	if len(matchedGroupIDs) > 0 {
		_ = groupSvc.MergeMemberships(ctx, u.ID, matchedGroupIDs)
	}
	return u, nil
}

func loadLDAPSyncSelection(ctx context.Context, settingsStore *settings.Store) ldappkg.SyncSelection {
	var sel ldappkg.SyncSelection
	_ = settingsStore.GetJSON(ctx, settingsKeyLDAPSync, &sel)
	return sel
}

var (
	errLDAPSyncDisabled        = errors.New("ldap is not enabled")
	errLDAPSyncNothingSelected = errors.New("no users or groups selected for sync")
)

func executeLDAPSync(
	ctx context.Context,
	svc *auth.Service,
	groupSvc *groups.Service,
	settingsStore *settings.Store,
	v *vault.Vault,
) (*ldappkg.SyncResult, error) {
	cfg := loadLDAPConfig(ctx, settingsStore, v)
	if !cfg.Enabled {
		return nil, errLDAPSyncDisabled
	}
	sel := loadLDAPSyncSelection(ctx, settingsStore)
	if len(sel.UserDNs) == 0 && len(sel.GroupDNs) == 0 {
		return nil, errLDAPSyncNothingSelected
	}
	pw, _ := v.GetSecret(ctx, vaultLDAPBindPassword)
	syncSvc := &ldappkg.SyncService{
		Client: &ldappkg.Client{Cfg: cfg, Password: string(pw)},
		Auth:   svc, Groups: groupSvc, Cfg: cfg,
	}
	return syncSvc.Run(ctx, sel)
}

// runLDAPSyncWorker re-imports the saved AD sync selection on a fixed interval.
func runLDAPSyncWorker(
	svc *auth.Service,
	groupSvc *groups.Service,
	settingsStore *settings.Store,
	v *vault.Vault,
	bus events.Publisher,
) {
	interval := config.GetDuration("PAM_LDAP_SYNC_INTERVAL", 5*time.Minute)
	t := time.NewTicker(interval)
	defer t.Stop()
	log.Printf("ldap-sync: auto worker started (interval=%s)", interval)
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		res, err := executeLDAPSync(ctx, svc, groupSvc, settingsStore, v)
		cancel()
		if err != nil {
			if errors.Is(err, errLDAPSyncDisabled) || errors.Is(err, errLDAPSyncNothingSelected) {
				continue
			}
			log.Printf("ldap-sync: auto run failed: %v", err)
			continue
		}
		if res.UsersSynced == 0 && res.GroupsSynced == 0 && len(res.Errors) == 0 {
			continue
		}
		log.Printf("ldap-sync: auto synced %d user(s), %d group(s)", res.UsersSynced, res.GroupsSynced)
		if len(res.Errors) > 0 {
			log.Printf("ldap-sync: auto run warnings: %s", strings.Join(res.Errors, "; "))
		}
		bus.Publish(events.Event{
			Source: "auth", Kind: "ldap.sync.completed", Severity: "info",
			Detail: map[string]string{
				"users":  strconv.Itoa(res.UsersSynced),
				"groups": strconv.Itoa(res.GroupsSynced),
				"auto":   "1",
			},
		})
	}
}

// loadLDAPConfig returns the persisted LDAP config (or sane defaults) merged
// with the bind-password-set indicator.
func loadLDAPConfig(ctx context.Context, settingsStore *settings.Store, v *vault.Vault) ldappkg.Config {
	cfg := ldappkg.DefaultConfig()
	_ = settingsStore.GetJSON(ctx, settingsKeyLDAP, &cfg)
	if _, err := v.GetSecret(ctx, vaultLDAPBindPassword); err == nil {
		cfg.BindPasswordSet = true
	}
	return cfg
}

// loadSAMLConfig returns the persisted SAML config with the cert-set flag.
func loadSAMLConfig(ctx context.Context, settingsStore *settings.Store, v *vault.Vault) samlpkg.Config {
	cfg := samlpkg.DefaultConfig()
	_ = settingsStore.GetJSON(ctx, settingsKeySAML, &cfg)
	if _, err := v.GetSecret(ctx, vaultSAMLCert); err == nil {
		cfg.SPCertSet = true
	}
	return cfg
}

// buildSAMLProvider materializes a SAML SP from settings + vaulted keypair.
func buildSAMLProvider(ctx context.Context, settingsStore *settings.Store, v *vault.Vault) (*samlpkg.Provider, error) {
	cfg := loadSAMLConfig(ctx, settingsStore, v)
	if !cfg.Enabled {
		return nil, errors.New("saml: not enabled")
	}
	certPEM, err := v.GetSecret(ctx, vaultSAMLCert)
	if err != nil {
		return nil, errors.New("saml: SP cert missing — save settings to generate")
	}
	keyPEM, err := v.GetSecret(ctx, vaultSAMLKey)
	if err != nil {
		return nil, errors.New("saml: SP key missing — save settings to generate")
	}
	return samlpkg.NewProvider(cfg, certPEM, keyPEM)
}

// samlACSHandler validates the SAMLResponse from the IdP, upserts the local
// user, syncs group memberships, mints a JWT, and redirects to the SPA with
// the token in the URL hash (HTML-meta refresh + JS for safety).
func samlACSHandler(
	w http.ResponseWriter, r *http.Request,
	svc *auth.Service, groupSvc *groups.Service,
	settingsStore *settings.Store, v *vault.Vault,
	bus events.Publisher,
) {
	p, err := buildSAMLProvider(r.Context(), settingsStore, v)
	if err != nil {
		httpx.Error(w, http.StatusServiceUnavailable, err)
		return
	}
	cfg := p.Cfg

	claims, err := p.ParseACS(r)
	if err != nil {
		bus.Publish(events.Event{Source: "auth", Kind: "saml.failed", Severity: "warn", Detail: map[string]string{"err": err.Error()}})
		httpx.Error(w, http.StatusUnauthorized, err)
		return
	}
	if claims.Email == "" {
		httpx.Error(w, http.StatusUnauthorized, errors.New("saml: no email/nameID returned by IdP"))
		return
	}

	username := claims.Email
	role := cfg.DefaultRole
	if role == "" {
		role = "user"
	}
	// Map SAML group claims to local groups by name.
	var matchedGroupIDs []int64
	allGroups, _ := groupSvc.List(r.Context())
	for _, gname := range claims.Groups {
		for _, g := range allGroups {
			if strings.EqualFold(g.Name, gname) || g.LDAPDN == gname {
				matchedGroupIDs = append(matchedGroupIDs, g.ID)
				if g.Role == "admin" {
					role = "admin"
				} else if role != "admin" {
					role = g.Role
				}
			}
		}
	}

	u, err := svc.UpsertSAMLUser(r.Context(), username, claims.Email, role, claims.NameID)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err)
		return
	}
	if len(matchedGroupIDs) > 0 {
		_ = groupSvc.MergeMemberships(r.Context(), u.ID, matchedGroupIDs)
	}
	_ = svc.RecordLogin(r.Context(), u.ID)
	tok, err := svc.IssueToken(u)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err)
		return
	}
	bus.Publish(events.Event{Source: "auth", Kind: "login.ok", Severity: "info", Actor: u.Username, Detail: map[string]string{"method": "saml"}})

	// Redirect the browser to the SPA with the token in the URL fragment so it
	// never hits the server logs or referer headers.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `<!doctype html><meta charset=utf-8><title>Signing in…</title>
<script>
  var tok = %q;
  window.location.replace('/#sso=' + encodeURIComponent(tok));
</script>
<p>Signing in… if you are not redirected, <a href="/#sso=%s">click here</a>.</p>`, tok, tok)
}

func bootstrapSettings(s *settings.Store) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if v, _ := s.Get(ctx, settingsKeyMFAPolicy); v == "" {
		_ = s.Set(ctx, settingsKeyMFAPolicy, "required")
		log.Printf("bootstrap: default MFA policy set to required")
	}
}

func checkMFAAccess(r *http.Request, targetUID int64, enrollOK bool) error {
	actorUID, _ := strconv.ParseInt(r.Header.Get("X-PAM-UID"), 10, 64)
	if r.Header.Get("X-PAM-Role") == "admin" {
		return nil
	}
	if actorUID != targetUID {
		return errors.New("forbidden")
	}
	if r.Header.Get("X-PAM-Scope") == "mfa_enroll" && !enrollOK {
		return errors.New("forbidden")
	}
	return nil
}

func bootstrap(svc *auth.Service, groupSvc *groups.Service, roleSvc *roles.Service, safeSvc *safes.Service) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Seed built-in roles before anything else references them.
	if err := roleSvc.SeedBuiltins(ctx); err != nil {
		log.Printf("bootstrap roles: %v", err)
	}

	var n int
	_ = svc.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	if n == 0 {
		adminUser := config.Get("PAM_ADMIN_USER", "admin")
		adminPass := config.Get("PAM_ADMIN_PASS", "admin")
		if _, err := svc.CreateUser(ctx, adminUser, "admin@example.com", adminPass, "admin"); err != nil {
			log.Printf("bootstrap admin failed: %v", err)
			os.Exit(1)
		}
		log.Printf("bootstrap: created initial admin user %q (please change password)", adminUser)
	}

	// Seed default groups if none exist.
	var ng int
	_ = svc.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM groups`).Scan(&ng)
	if ng == 0 {
		for _, g := range []groups.Group{
			{Name: "Administrators", Description: "Full PAM access", Role: "admin"},
			{Name: "Network Operators", Description: "Manage network devices", Role: "netops"},
			{Name: "Security Operators", Description: "Security appliance access", Role: "secops"},
			{Name: "Sysadmins", Description: "Linux/Windows server admins", Role: "sysadmin"},
			{Name: "Auditors", Description: "Read-only access", Role: "viewer"},
		} {
			_, _ = groupSvc.Create(ctx, g)
		}
		log.Printf("bootstrap: seeded default groups")
	}

	// Seed a default "General" safe so the Accounts UI works out of the box.
	var ns int
	_ = svc.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM safes`).Scan(&ns)
	if ns == 0 {
		_, _ = safeSvc.Create(ctx, safes.Safe{
			Name: "General", Description: "Default safe for shared privileged accounts",
			CPMEnabled: false, RotationDays: 90,
		})
		log.Printf("bootstrap: seeded default safe 'General'")
	}
}

// AsJSON is a small helper to keep error logs structured.
func AsJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
