// auth-service exposes /login, /verify, user CRUD, group management, MFA
// enrollment, and (when configured) LDAP/AD authentication. It signs the
// short-lived JWTs every other service trusts.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/example/pam-platform/internal/auth"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/httpx"
	ldappkg "github.com/example/pam-platform/internal/ldap"
	"github.com/example/pam-platform/internal/mfa"
	"github.com/example/pam-platform/internal/settings"
	"github.com/example/pam-platform/internal/vault"
)

const (
	settingsKeyLDAP       = "ldap"
	settingsKeyMFAPolicy  = "mfa_policy"  // "off" | "optional" | "required"
	vaultLDAPBindPassword = "_ldap_bind_password"
)

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
	settingsStore := &settings.Store{DB: d}
	bus := events.New()

	bootstrap(svc, groupSvc)

	mux := http.NewServeMux()
	httpx.RegisterHealth(mux)

	mux.HandleFunc("POST /login", loginHandler(svc, groupSvc, settingsStore, v, bus))
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
		secret, err := mfa.NewSecret()
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		if err := svc.SetMFASecret(r.Context(), uid, secret); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		// Resolve username for the otpauth label.
		var username string
		_ = d.QueryRowContext(r.Context(), `SELECT username FROM users WHERE id=?`, uid).Scan(&username)
		uri := mfa.OtpAuthURI("PAM Platform", username, secret)
		httpx.JSON(w, http.StatusOK, map[string]string{
			"secret":       secret,
			"otpauth_uri":  uri,
		})
	})
	mux.HandleFunc("POST /users/{id}/mfa/verify", func(w http.ResponseWriter, r *http.Request) {
		uid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
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
		if !mfa.Verify(secret, req.Code) {
			httpx.Error(w, http.StatusUnauthorized, errors.New("invalid code"))
			return
		}
		if err := svc.EnableMFA(r.Context(), uid); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "mfa.enabled", Severity: "info", Actor: strconv.FormatInt(uid, 10)})
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("DELETE /users/{id}/mfa", func(w http.ResponseWriter, r *http.Request) {
		uid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := svc.DisableMFA(r.Context(), uid); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "disabled"})
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

	addr := config.Get("PAM_AUTH_ADDR", ":8081")
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
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Username, Password, OTP string }
		if err := httpx.ReadJSON(r, &req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if req.Username == "" || req.Password == "" {
			httpx.Error(w, http.StatusBadRequest, errors.New("username and password required"))
			return
		}

		ctx := r.Context()
		u, err := tryLocal(ctx, svc, req.Username, req.Password)
		if err != nil {
			// Try LDAP if configured.
			u, err = tryLDAP(ctx, svc, groupSvc, settingsStore, v, req.Username, req.Password)
		}
		if err != nil {
			bus.Publish(events.Event{Source: "auth", Kind: "login.failed", Severity: "warn", Actor: req.Username, Detail: map[string]string{"error": err.Error()}})
			httpx.Error(w, http.StatusUnauthorized, errors.New("invalid credentials"))
			return
		}

		mfaPolicy, _ := settingsStore.Get(ctx, settingsKeyMFAPolicy)
		mfaRequired := u.MFAEnabled || mfaPolicy == "required"
		if mfaRequired && u.MFAEnabled {
			secret, _ := svc.GetMFASecret(ctx, u.ID)
			if secret == "" {
				httpx.Error(w, http.StatusUnauthorized, errors.New("MFA required but not enrolled"))
				return
			}
			if req.OTP == "" {
				httpx.JSON(w, http.StatusAccepted, map[string]any{
					"mfa_required": true,
					"user_id":      u.ID,
				})
				return
			}
			if !mfa.Verify(secret, req.OTP) {
				bus.Publish(events.Event{Source: "auth", Kind: "mfa.failed", Severity: "warn", Actor: u.Username})
				httpx.Error(w, http.StatusUnauthorized, errors.New("invalid OTP"))
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
		bus.Publish(events.Event{Source: "auth", Kind: "login.ok", Severity: "info", Actor: u.Username})
		httpx.JSON(w, http.StatusOK, map[string]any{
			"token": tok,
			"user":  u,
			"roles": roles,
		})
	}
}

func tryLocal(ctx context.Context, svc *auth.Service, username, password string) (*auth.User, error) {
	return svc.Authenticate(ctx, username, password)
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
	pw, _ := v.GetSecret(ctx, vaultLDAPBindPassword)
	client := &ldappkg.Client{Cfg: cfg, Password: string(pw)}
	lu, err := client.Authenticate(ctx, username, password)
	if err != nil {
		return nil, err
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
		_ = groupSvc.ReplaceMemberships(ctx, u.ID, matchedGroupIDs)
	}
	return u, nil
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

func bootstrap(svc *auth.Service, groupSvc *groups.Service) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
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
}

// AsJSON is a small helper to keep error logs structured.
func AsJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
