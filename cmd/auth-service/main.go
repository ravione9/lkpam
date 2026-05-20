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

	"github.com/example/pam-platform/internal/auth"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/httpx"
	ldappkg "github.com/example/pam-platform/internal/ldap"
	"github.com/example/pam-platform/internal/mfa"
	samlpkg "github.com/example/pam-platform/internal/saml"
	"github.com/example/pam-platform/internal/settings"
	"github.com/example/pam-platform/internal/vault"
)

const (
	settingsKeyLDAP       = "ldap"
	settingsKeySAML       = "saml"
	settingsKeyMFAPolicy  = "mfa_policy"
	vaultLDAPBindPassword = "_ldap_bind_password"
	vaultSAMLCert         = "_saml_sp_cert"
	vaultSAMLKey          = "_saml_sp_key"
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
		_ = groupSvc.ReplaceMemberships(r.Context(), u.ID, matchedGroupIDs)
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
