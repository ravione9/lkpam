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
	"bytes"
	"context"
	"crypto/tls"
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
	"github.com/example/pam-platform/internal/weblaunch"
)

type tlsConfig = tls.Config

//go:embed web/*
var webFS embed.FS

// claims is the verified JWT payload we get back from auth-service /verify.
type claims struct {
	UID   int64  `json:"uid"`
	User  string `json:"u"`
	Role  string `json:"r"`
	Scope string `json:"scope,omitempty"`
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
	{"DELETE", "/api/auth/users/"},
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

// weblaunch is imported for the SessionCreds type used in the web proxy.
var _ = weblaunch.SessionCreds{}

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
	// RDP proxy validates JWT via token query param on WebSocket connect.
	rdpURL := mustURL(config.Get("PAM_RDP_PROXY_URL", "http://localhost:8086"))
	mux.Handle("/api/rdp/", http.StripPrefix("/api/rdp", reverse(rdpURL)))

	// Session viewer pages must never fall back to index.html (that shows the login UI).
	for _, page := range []string{"rdp-viewer.html", "ssh-viewer.html", "web-viewer.html"} {
		name := page
		mux.HandleFunc("GET /"+name, serveWebFile(name))
	}

	// Web console reverse-proxy: /web/{sessionID}/{*path}
	// Validates the portal JWT (header, ?token=, or session cookie), loads session
	// credentials from vault, and transparently proxies to the target web console.
	vaultSvc := mustURL(config.Get("PAM_VAULT_URL", "http://localhost:8082"))
	webProxy := webGated(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webConsoleProxy(w, r, authURL, vaultSvc)
	}), authURL, vaultSvc)
	mux.Handle("/web/", webProxy)

	// Static UI (SPA fallback only for non-file routes).
	mux.HandleFunc("/", serveStaticUI)

	addr := config.Get("PAM_GATEWAY_ADDR", ":8080")
	log.Printf("api-gateway listening on %s — open http://localhost%s/", addr, addr)
	// Bridge root-absolute SPA paths (/static/, /api/v2/, runtime.js, …) through the
	// active web-console session when pam_web_sid cookie is set.
	handler := webBridgeMiddleware(mux, webProxy)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(handler)); err != nil {
		log.Fatal(err)
	}
}

func reverse(target *url.URL) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	orig := proxy.Director
	proxy.Director = func(r *http.Request) {
		orig(r)
		if r.Header.Get("X-Forwarded-Host") == "" {
			r.Header.Set("X-Forwarded-Host", r.Host)
		}
		if r.Header.Get("X-Forwarded-Proto") == "" {
			if r.TLS != nil {
				r.Header.Set("X-Forwarded-Proto", "https")
			} else {
				r.Header.Set("X-Forwarded-Proto", "http")
			}
		}
	}
	return proxy
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
		serveAuthed(w, r, next, authBase, tok, "", false)
	})
}

// webGated authenticates web-console proxy requests. Browser iframes cannot set
// Authorization headers, so the viewer passes ?token= on first load; we store it
// in an HttpOnly cookie scoped to /web/{sessionID}/ for subsequent assets.
// Asset/API sub-requests may omit the JWT — an active vault session is enough.
func webGated(next http.Handler, authBase, vaultBase *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sessionID := webSessionIDFromPath(r.URL.Path)
		tok, err := httpx.BearerTokenFromRequest(r)
		if err == nil {
			setCookie := sessionID != "" && (r.URL.Query().Get("token") != "" || r.Header.Get("Authorization") != "")
			serveAuthed(w, r, next, authBase, tok, sessionID, setCookie)
			return
		}
		if sessionID != "" && webSessionActive(r.Context(), vaultBase, sessionID) {
			serveWebSession(w, r, next, sessionID)
			return
		}
		httpx.Error(w, http.StatusUnauthorized, err)
	})
}

func serveWebSession(w http.ResponseWriter, r *http.Request, next http.Handler, sessionID string) {
	r2 := r.Clone(r.Context())
	r2.Header.Set("X-PAM-Web-Session", sessionID)
	next.ServeHTTP(w, r2)
}

func webSessionActive(ctx context.Context, vaultBase *url.URL, sessionID string) bool {
	if !strings.HasPrefix(sessionID, "web-") {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, "GET", vaultBase.String()+"/internal/web-session/"+sessionID, nil)
	if err != nil {
		return false
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func serveAuthed(w http.ResponseWriter, r *http.Request, next http.Handler, authBase *url.URL, tok, webSessionID string, setWebCookie bool) {
	c, status, err := verifyToken(r.Context(), authBase, tok)
	if err != nil {
		httpx.Error(w, status, err)
		return
	}
	if setWebCookie && webSessionID != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "pam_web_tok",
			Value:    tok,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   7200,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "pam_web_sid",
			Value:    webSessionID,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   7200,
		})
	}
	if requiresAdmin(r.Method, r.URL.Path) && c.Role != "admin" {
		httpx.Error(w, http.StatusForbidden, errors.New("admin role required"))
		return
	}
	r2 := r.Clone(context.WithValue(r.Context(), ctxKey{}, c))
	r2.Header.Set("X-PAM-User", c.User)
	r2.Header.Set("X-PAM-Role", c.Role)
	r2.Header.Set("X-PAM-UID", strconv.FormatInt(c.UID, 10))
	if c.Scope != "" {
		r2.Header.Set("X-PAM-Scope", c.Scope)
	}
	next.ServeHTTP(w, r2)
}

func webSessionIDFromPath(path string) string {
	path = strings.TrimPrefix(path, "/web/")
	if path == "" {
		return ""
	}
	if i := strings.IndexByte(path, '/'); i >= 0 {
		return path[:i]
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i]
	}
	return path
}

func requiresAdmin(method, path string) bool {
	for _, m := range adminWriteMatchers {
		if m.method == method && strings.HasPrefix(path, m.prefix) {
			// Per-user actions that authenticated users may take on themselves
			// or their own checkouts. These bypass the admin gate.
			switch {
			case strings.Contains(path, "/mfa/reset"):
				// admin-only: reset another user's TOTP enrollment
			case strings.HasPrefix(path, "/api/auth/users/") && strings.Contains(path, "/mfa"):
				return false
			case strings.HasSuffix(path, "/checkout"):
				return false
			case strings.HasSuffix(path, "/rdp-launch"):
				return false
			case strings.HasSuffix(path, "/ssh-launch"):
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

func serveWebFile(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := webFS.ReadFile("web/" + name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		log.Fatalf("bad url %q: %v", s, err)
	}
	return u
}

// webConsoleProxy reverse-proxies a browser to a web-console target.
// URL format:  /web/{sessionID}/{*rest}
// On first load the session token is validated. The vault is queried for the
// stored credentials; they are injected as a Basic Auth header on every request
// to the target. All relative links work as-is because the browser path prefix
// /web/{sessionID}/ acts as the session namespace.
func webConsoleProxy(w http.ResponseWriter, r *http.Request, authBase, vaultBase *url.URL) {
	// Parse /web/{sessionID}/{*rest}
	path := strings.TrimPrefix(r.URL.Path, "/web/")
	slash := strings.IndexByte(path, '/')
	var sessionID, rest string
	if slash < 0 {
		sessionID = path
		rest = "/"
	} else {
		sessionID = path[:slash]
		rest = path[slash:]
	}
	if sessionID == "" {
		http.Error(w, "missing session ID", http.StatusBadRequest)
		return
	}

	// Load session credentials from vault via internal vault-service.
	credsURL := vaultBase.String() + "/internal/web-session/" + sessionID
	req, _ := http.NewRequestWithContext(r.Context(), "GET", credsURL, nil)
	// Forward the user's identity headers so the vault service can check ownership.
	req.Header.Set("X-PAM-UID", r.Header.Get("X-PAM-UID"))
	req.Header.Set("X-PAM-Role", r.Header.Get("X-PAM-Role"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			resp.Body.Close()
		}
		http.Error(w, "session not found or expired", http.StatusNotFound)
		return
	}
	var creds weblaunch.SessionCreds
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		resp.Body.Close()
		http.Error(w, "invalid session credentials", http.StatusInternalServerError)
		return
	}
	resp.Body.Close()

	if creds.TargetURL == "" {
		http.Error(w, "session has no target URL", http.StatusBadRequest)
		return
	}

	targetURL, err := url.Parse(creds.TargetURL)
	if err != nil {
		http.Error(w, "invalid target URL", http.StatusBadRequest)
		return
	}

	// Build the upstream request (strip PAM ?token= from query — never forward to target).
	upQ := r.URL.Query()
	upQ.Del("token")
	upstream, _ := http.NewRequestWithContext(r.Context(), r.Method,
		targetURL.Scheme+"://"+targetURL.Host+rest+"?"+upQ.Encode(), r.Body)
	upstream.Header = r.Header.Clone()
	upstream.Header.Del("X-PAM-UID")
	upstream.Header.Del("X-PAM-Role")
	upstream.Header.Del("X-PAM-User")
	upstream.Header.Del("Authorization")
	upstream.Host = targetURL.Host

	if creds.Username != "" && creds.Password != "" {
		upstream.SetBasicAuth(creds.Username, creds.Password)
	}

	// Skip TLS verification for self-signed appliance certs (common on firewalls/switches).
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // let browser follow redirects
		},
	}

	upResp, err := httpClient.Do(upstream)
	if err != nil {
		http.Error(w, "proxy error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	// Copy response headers, rewriting Location redirects to go through proxy.
	for k, vs := range upResp.Header {
		if strings.EqualFold(k, "Location") {
			for _, v := range vs {
				v = rewriteLocation(v, targetURL, sessionID)
				w.Header().Add(k, v)
			}
			continue
		}
		// Strip security headers that block iframe embedding in our viewer.
		if strings.EqualFold(k, "X-Frame-Options") ||
			strings.EqualFold(k, "Content-Security-Policy") {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}

	// Rewrite HTML/JS/CSS bodies so root-absolute SPA paths go through the proxy.
	ct := upResp.Header.Get("Content-Type")
	if shouldRewriteWebBody(ct) {
		body, _ := io.ReadAll(upResp.Body)
		body = rewriteHTML(body, targetURL, sessionID)
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(upResp.StatusCode)
		w.Write(body)
	} else {
		w.WriteHeader(upResp.StatusCode)
		io.Copy(w, upResp.Body)
	}
}

func shouldRewriteWebBody(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "text/css")
}

func serveStaticUI(w http.ResponseWriter, r *http.Request) {
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
		if strings.Contains(path, ".") {
			http.NotFound(w, r)
			return
		}
		b, err = webFS.ReadFile("web/index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}
	switch {
	case strings.HasSuffix(path, ".html") || path == "index.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case strings.HasSuffix(path, ".js"):
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	}
	w.Write(b)
}

// webBridgeMiddleware forwards root-absolute paths from embedded SPAs (e.g. /static/,
// /api/v2/, /runtime.js) through the active web-console session. The <base> tag does
// not rewrite paths that start with /, so firewalls would otherwise hit the PAM UI.
func webBridgeMiddleware(inner http.Handler, webProxy http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isReservedPAMPath(r.URL.Path) {
			inner.ServeHTTP(w, r)
			return
		}
		sid := webBridgeSessionID(r)
		if sid == "" {
			inner.ServeHTTP(w, r)
			return
		}
		bridged := r.Clone(r.Context())
		u := *r.URL
		u.Path = "/web/" + sid + r.URL.Path
		bridged.URL = &u
		webProxy.ServeHTTP(w, bridged)
	})
}

// webBridgeSessionID resolves the active web-console session from cookie or Referer.
func webBridgeSessionID(r *http.Request) string {
	if c, err := r.Cookie("pam_web_sid"); err == nil {
		if sid := strings.TrimSpace(c.Value); sid != "" {
			return sid
		}
	}
	return webSessionFromReferer(r)
}

func webSessionFromReferer(r *http.Request) string {
	ref := r.Header.Get("Referer")
	if ref == "" {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	const pfx = "/web/"
	i := strings.Index(u.Path, pfx)
	if i < 0 {
		return ""
	}
	rest := u.Path[i+len(pfx):]
	if rest == "" {
		return ""
	}
	if j := strings.IndexByte(rest, '/'); j >= 0 {
		return rest[:j]
	}
	return rest
}

func isReservedPAMPath(path string) bool {
	if path == "/" || path == "/index.html" || strings.HasPrefix(path, "/web/") {
		return true
	}
	if path == "/health" {
		return true
	}
	for _, p := range []string{
		"/api/auth/", "/api/vault/", "/api/policy/", "/api/approval/", "/api/audit/", "/api/rdp/", "/api/ccp/",
	} {
		if strings.HasPrefix(path, p) || path == strings.TrimSuffix(p, "/") {
			return true
		}
	}
	for _, p := range []string{"/web-viewer.html", "/rdp-viewer.html", "/ssh-viewer.html"} {
		if path == p {
			return true
		}
	}
	return false
}

func rewriteLocation(loc string, target *url.URL, sessionID string) string {
	if strings.HasPrefix(loc, "http://"+target.Host) ||
		strings.HasPrefix(loc, "https://"+target.Host) {
		u, err := url.Parse(loc)
		if err == nil {
			return "/web/" + sessionID + u.RequestURI()
		}
	}
	if strings.HasPrefix(loc, "/") {
		return "/web/" + sessionID + loc
	}
	return loc
}

func rewriteHTML(body []byte, target *url.URL, sessionID string) []byte {
	pfx := "/web/" + sessionID
	// Inject a <base> tag so relative links resolve through the proxy automatically.
	baseTag := []byte(`<base href="` + pfx + `/">`)
	if idx := bytes.Index(body, []byte("<head>")); idx >= 0 {
		body = append(body[:idx+6], append(baseTag, body[idx+6:]...)...)
	} else if idx := bytes.Index(body, []byte("<HEAD>")); idx >= 0 {
		body = append(body[:idx+6], append(baseTag, body[idx+6:]...)...)
	}
	// Rewrite absolute target host URLs.
	for _, scheme := range []string{"https://", "http://"} {
		old := []byte(scheme + target.Host)
		body = bytes.ReplaceAll(body, old, []byte(pfx))
	}
	// Root-absolute paths (/static/, /api/v2/, …) ignore <base> — prefix them.
	return rewriteRootPaths(body, pfx)
}

// rewriteRootPaths prefixes root-absolute URL paths inside HTML/JS/CSS so they
// route through /web/{sessionID}/ instead of the PAM gateway root.
func rewriteRootPaths(body []byte, pfx string) []byte {
	if len(pfx) == 0 {
		return body
	}
	// Common SPA string literals in bundled JS.
	for _, pair := range [][2]string{
		{`"/api/`, `"` + pfx + `/api/`},
		{`'/api/`, `'` + pfx + `/api/`},
		{`"/static/`, `"` + pfx + `/static/`},
		{`'/static/`, `'` + pfx + `/static/`},
		{`"/assets/`, `"` + pfx + `/assets/`},
		{`'/assets/`, `'` + pfx + `/assets/`},
		{`"/ng/`, `"` + pfx + `/ng/`},
		{`'/ng/`, `'` + pfx + `/ng/`},
		{`"/login`, `"` + pfx + `/login`},
		{`'/login`, `'` + pfx + `/login`},
		{`"/logout`, `"` + pfx + `/logout`},
		{`'/logout`, `'` + pfx + `/logout`},
	} {
		body = bytes.ReplaceAll(body, []byte(pair[0]), []byte(pair[1]))
	}
	// HTML attributes: href="/…", src="/…", action="/…" (skip protocol-relative //).
	for _, attr := range []string{"href=", "src=", "action="} {
		for _, q := range []byte{'"', '\''} {
			body = rewriteRootAttr(body, attr, q, pfx)
		}
	}
	return body
}

func rewriteRootAttr(body []byte, attr string, quote byte, pfx string) []byte {
	needle := append(append([]byte(attr), quote), '/')
	repl := append(append([]byte(attr), quote), []byte(pfx)...)
	repl = append(repl, '/')

	var out bytes.Buffer
	i := 0
	for i < len(body) {
		idx := bytes.Index(body[i:], needle)
		if idx < 0 {
			out.Write(body[i:])
			break
		}
		idx += i
		absStart := idx + len(needle)
		// Skip protocol-relative URLs (href="//cdn…").
		if absStart < len(body) && body[absStart] == '/' {
			out.Write(body[i:absStart])
			i = absStart
			continue
		}
		// Skip paths already routed through /web/{sessionID}/.
		if absStart+4 <= len(body) && bytes.HasPrefix(body[absStart:], []byte("web/")) {
			out.Write(body[i:absStart])
			i = absStart
			continue
		}
		out.Write(body[i:idx])
		out.Write(repl)
		i = absStart
	}
	return out.Bytes()
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
