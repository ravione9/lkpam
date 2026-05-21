// api-gateway is the only externally-exposed HTTP service. It:
//   - serves the embedded admin / user web UI at /
//   - proxies REST calls to the internal services after JWT verification
//   - enforces role-based access on admin-only write endpoints (a non-admin
//     hitting POST/PUT/DELETE on management resources gets a 403 even if
//     they hand-craft the request)
//
// In production this would be replaced with Kong/Envoy with custom plugins;
// the Go implementation here keeps the reference stack small.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"

	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/httpx"
)

//go:embed web/*
var webFS embed.FS

// claims is the verified JWT payload we get back from auth-service /verify.
type claims struct {
	UID  int64  `json:"uid"`
	User string `json:"u"`
	Role string `json:"r"`
}

type ctxKey struct{}

// adminWriteMatchers gates write methods on admin-only resources. Each entry
// matches by method + path prefix. Add new admin routes here and they'll be
// automatically protected for non-admins.
var adminWriteMatchers = []struct {
	method string
	prefix string
}{
	{"POST", "/api/policy/policies"},
	{"PUT", "/api/policy/policies/"},
	{"DELETE", "/api/policy/policies/"},
	{"POST", "/api/policy/targets"},
	{"PUT", "/api/policy/targets/"},
	{"DELETE", "/api/policy/targets/"},
	{"POST", "/api/auth/users"},
	{"POST", "/api/auth/groups"},
	{"PUT", "/api/auth/groups/"},
	{"DELETE", "/api/auth/groups/"},
	{"POST", "/api/auth/groups/"}, // member add
	{"DELETE", "/api/auth/groups/"},
	{"POST", "/api/auth/roles"},
	{"PUT", "/api/auth/roles/"},
	{"DELETE", "/api/auth/roles/"},
	{"PUT", "/api/auth/settings/"},
	{"POST", "/api/auth/settings/"},
	{"POST", "/api/vault/secrets"},
	{"DELETE", "/api/vault/secrets/"},
	{"POST", "/api/approval/matrix"},
	{"PUT", "/api/approval/matrix/"},
	{"DELETE", "/api/approval/matrix/"},
	{"POST", "/api/auth/safes"},
	{"PUT", "/api/auth/safes/"},
	{"DELETE", "/api/auth/safes/"},
	{"POST", "/api/auth/accounts"},
	{"PUT", "/api/auth/accounts/"},
	{"DELETE", "/api/auth/accounts/"},
	{"POST", "/api/auth/apps"},
	{"PUT", "/api/auth/apps/"},
	{"DELETE", "/api/auth/apps/"},
	{"POST", "/api/auth/alerts/"},
	{"POST", "/api/audit/sessions/"}, // terminate
}

func main() {
	authURL := mustURL(config.Get("PAM_AUTH_URL", "http://localhost:8081"))
	vaultURL := mustURL(config.Get("PAM_VAULT_URL", "http://localhost:8082"))
	policyURL := mustURL(config.Get("PAM_POLICY_URL", "http://localhost:8083"))
	approvalURL := mustURL(config.Get("PAM_APPROVAL_URL", "http://localhost:8084"))
	auditURL := mustURL(config.Get("PAM_AUDIT_URL", "http://localhost:8085"))

	mux := http.NewServeMux()
	httpx.RegisterHealth(mux)

	// Public endpoints (no JWT)
	mux.Handle("POST /api/auth/login", forwardTo(authURL, "/login"))
	mux.Handle("POST /api/auth/verify", forwardTo(authURL, "/verify"))
	mux.Handle("GET /api/auth/saml/login", forwardTo(authURL, "/saml/login"))
	mux.Handle("POST /api/auth/saml/acs", forwardTo(authURL, "/saml/acs"))
	mux.Handle("GET /api/auth/saml/metadata", forwardTo(authURL, "/saml/metadata"))
	mux.Handle("GET /api/auth/sso/status", forwardTo(authURL, "/sso/status"))
	// Central Credential Provider (uses X-API-Key, not Bearer JWT).
	mux.Handle("GET /api/ccp/accounts", forwardTo(vaultURL, "/ccp/accounts"))

	// Authenticated + role-gated
	mux.Handle("/api/auth/", gated(http.StripPrefix("/api/auth", reverse(authURL)), authURL))
	mux.Handle("/api/vault/", gated(http.StripPrefix("/api/vault", reverse(vaultURL)), authURL))
	mux.Handle("/api/policy/", gated(http.StripPrefix("/api/policy", reverse(policyURL)), authURL))
	mux.Handle("/api/approval/", gated(http.StripPrefix("/api/approval", reverse(approvalURL)), authURL))
	mux.Handle("/api/audit/", gated(http.StripPrefix("/api/audit", reverse(auditURL)), authURL))

	// Static UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		b, err := webFS.ReadFile("web/" + path)
		if err != nil {
			b, err = webFS.ReadFile("web/index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
		}
		if strings.HasSuffix(path, ".html") || path == "index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		w.Write(b)
	})

	addr := config.Get("PAM_GATEWAY_ADDR", ":8080")
	log.Printf("api-gateway listening on %s — open http://localhost%s/", addr, addr)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

func reverse(target *url.URL) http.Handler {
	return httputil.NewSingleHostReverseProxy(target)
}

// gated wraps a handler with JWT verification AND role enforcement. The JWT
// claims live on the request context as a *claims for downstream introspection;
// non-admins are blocked from any path/method pair listed in adminWriteMatchers.
func gated(next http.Handler, authBase *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := httpx.BearerToken(r)
		if err != nil {
			httpx.Error(w, http.StatusUnauthorized, err)
			return
		}
		c, status, err := verifyToken(r.Context(), authBase, tok)
		if err != nil {
			httpx.Error(w, status, err)
			return
		}
		if requiresAdmin(r.Method, r.URL.Path) && c.Role != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin role required"))
			return
		}
		// Forward identity to downstream services in case they want to log /
		// enforce on top.
		r2 := r.Clone(context.WithValue(r.Context(), ctxKey{}, c))
		r2.Header.Set("X-PAM-User", c.User)
		r2.Header.Set("X-PAM-Role", c.Role)
		r2.Header.Set("X-PAM-UID", strconv.FormatInt(c.UID, 10))
		next.ServeHTTP(w, r2)
	})
}

func requiresAdmin(method, path string) bool {
	for _, m := range adminWriteMatchers {
		if m.method == method && strings.HasPrefix(path, m.prefix) {
			// Per-user actions that authenticated users may take on themselves
			// or their own checkouts. These bypass the admin gate.
			switch {
			case strings.HasPrefix(path, "/api/auth/users/") && strings.Contains(path, "/mfa"):
				return false
			case strings.HasSuffix(path, "/checkout"):
				return false
			case strings.HasSuffix(path, "/rdp-launch"):
				return false
			case strings.HasPrefix(path, "/api/auth/checkouts/") && strings.HasSuffix(path, "/return"):
				return false
			}
			return true
		}
	}
	return false
}

func verifyToken(ctx context.Context, authBase *url.URL, tok string) (*claims, int, error) {
	body := strings.NewReader(`{"Token":"` + tok + `"}`)
	req, _ := http.NewRequestWithContext(ctx, "POST", authBase.String()+"/verify", body)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return nil, resp.StatusCode, errors.New(strings.TrimSpace(string(raw)))
	}
	var c claims
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return nil, http.StatusBadGateway, err
	}
	return &c, http.StatusOK, nil
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		log.Fatalf("bad url %q: %v", s, err)
	}
	return u
}

// forwardTo proxies a request to target host, rewriting the path to dstPath.
func forwardTo(target *url.URL, dstPath string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r2 := r.Clone(r.Context())
		r2.URL.Path = dstPath
		r2.URL.RawPath = dstPath
		reverse(target).ServeHTTP(w, r2)
	})
}
