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
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
	"strconv"
	"strings"

	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/httpx"
	"github.com/example/pam-platform/internal/weblaunch"
)

type tlsConfig = tls.Config

//go:embed all:web
var webFS embed.FS

// claims is the verified JWT payload we get back from auth-service /verify.
type claims struct {
	UID   int64  `json:"uid"`
	User  string `json:"u"`
	Role  string `json:"r"`
	Scope string `json:"scope,omitempty"`
}

type ctxKey struct{}

// authHTTPClient verifies JWTs against auth-service. A timeout prevents one
// stuck /verify from blocking every gated API call (dashboard, sessions, etc.).
var authHTTPClient = &http.Client{Timeout: 10 * time.Second}

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
	{"POST", "/api/policy/locations"},
	{"PUT", "/api/policy/locations/"},
	{"DELETE", "/api/policy/locations/"},
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
	mux.Handle("/api/rdp/", http.StripPrefix("/api/rdp", reverseWebSocket(rdpURL)))

	// Session viewer pages must never fall back to index.html (that shows the login UI).
	for _, page := range []string{"rdp-viewer.html", "ssh-viewer.html", "web-viewer.html", "guac-player.html"} {
		name := page
		mux.HandleFunc("GET /"+name, serveWebFile(name))
	}
	// Guacamole client (must not be handled by webBridgeMiddleware or SPA fallback).
	mux.HandleFunc("GET /vendor/{path...}", serveWebVendor)

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
	return configureReverseProxy(httputil.NewSingleHostReverseProxy(target))
}

// reverseWebSocket proxies to rdp-proxy with HTTP/1.1 (required for WebSocket upgrade).
func reverseWebSocket(target *url.URL) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = -1 // stream Guacamole frames immediately (no reverse-proxy buffering)
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return configureReverseProxy(proxy)
}

func configureReverseProxy(proxy *httputil.ReverseProxy) http.Handler {
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
		// Recorded web-console traffic: session IDs are unguessable (web-<ns>-<target>).
		// Do not return 401 for /static/* inside the iframe — that breaks FortiGate and
		// similar SPAs (CSS/JS get text/plain errors). Vault lookup in webConsoleProxy
		// still gates expired/invalid sessions (404).
		if sessionID != "" && strings.HasPrefix(sessionID, "web-") {
			if tok, err := httpx.BearerTokenFromRequest(r); err == nil {
				setCookie := r.URL.Query().Get("token") != "" || r.Header.Get("Authorization") != ""
				serveAuthed(w, r, next, authBase, tok, sessionID, setCookie)
				return
			}
			serveWebSession(w, r, next, sessionID)
			return
		}
		tok, err := httpx.BearerTokenFromRequest(r)
		if err == nil {
			setCookie := sessionID != "" && (r.URL.Query().Get("token") != "" || r.Header.Get("Authorization") != "")
			serveAuthed(w, r, next, authBase, tok, sessionID, setCookie)
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
	// verifyTokenCached short-circuits to a 60-second cache for the same
	// token, and falls back to a 5-minute stale-cache window when auth-service
	// is unreachable. This keeps Proxy Log / Session History / every other
	// dashboard usable across transient auth-service restarts.
	c, status, err := verifyTokenCached(r.Context(), authBase, tok)
	if err != nil {
		httpx.Error(w, status, err)
		return
	}
	if setWebCookie && webSessionID != "" {
		cookiePath := "/web/" + webSessionID + "/"
		http.SetCookie(w, &http.Cookie{
			Name:     "pam_web_tok",
			Value:    tok,
			Path:     cookiePath,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   7200,
		})
		http.SetCookie(w, &http.Cookie{
			Name:     "pam_web_sid",
			Value:    webSessionID,
			Path:     cookiePath,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   7200,
		})
		// Also scope to / so webBridgeMiddleware can route root-absolute /static/…
		// requests when the Referer is missing (some browsers on favicon/manifest).
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
			case path == "/api/auth/birthright/mine":
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
	body, err := json.Marshal(map[string]string{"Token": tok})
	if err != nil {
		return nil, http.StatusBadGateway, err
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", authBase.String()+"/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := authHTTPClient.Do(req)
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
		serveWebPath(w, r, "web/"+name)
	}
}

func serveWebVendor(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimPrefix(r.URL.Path, "/vendor/")
	if rel == "" || strings.Contains(rel, "..") {
		http.NotFound(w, r)
		return
	}
	serveWebPath(w, r, "web/vendor/"+rel)
}

func serveWebPath(w http.ResponseWriter, r *http.Request, fsPath string) {
	b, err := webFS.ReadFile(fsPath)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if ct := mimeForWebPath(fsPath); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if strings.HasSuffix(fsPath, "index.html") {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	}
	w.Write(b)
}

func mimeForWebPath(path string) string {
	path = strings.ToLower(webPathOnly(path))
	switch {
	case strings.HasSuffix(path, ".html"):
		return "text/html; charset=utf-8"
	case strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".mjs"):
		return "application/javascript; charset=utf-8"
	case strings.HasSuffix(path, ".css"):
		return "text/css; charset=utf-8"
	case strings.HasSuffix(path, ".webmanifest"):
		return "application/manifest+json; charset=utf-8"
	case strings.HasSuffix(path, ".json"):
		return "application/json; charset=utf-8"
	case strings.HasSuffix(path, ".svg"):
		return "image/svg+xml"
	case strings.HasSuffix(path, ".png"):
		return "image/png"
	case strings.HasSuffix(path, ".ico"):
		return "image/x-icon"
	default:
		return ""
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
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			dropUpstreamClient(sessionID)
		}
		writeWebProxyError(w, rest, "session not found or expired", http.StatusNotFound)
		return
	}
	var creds weblaunch.SessionCreds
	if err := json.NewDecoder(resp.Body).Decode(&creds); err != nil {
		resp.Body.Close()
		writeWebProxyError(w, rest, "invalid session credentials", http.StatusInternalServerError)
		return
	}
	resp.Body.Close()

	if creds.TargetURL == "" {
		http.Error(w, "session has no target URL", http.StatusBadRequest)
		return
	}
	creds.TargetKind = inferTargetKind(creds)

	targetURL, err := url.Parse(creds.TargetURL)
	if err != nil {
		http.Error(w, "invalid target URL", http.StatusBadRequest)
		return
	}

	// Build the upstream request (strip PAM ?token= from query — never forward to target).
	upQ := r.URL.Query()
	upQ.Del("token")
	state := upstreamSessionState(sessionID)
	httpClient := state.client
	if ap := loginAssetPrefixFromTarget(creds.TargetURL); ap != "" {
		state.mu.Lock()
		if state.assetPrefix == "" {
			state.assetPrefix = ap
		}
		state.mu.Unlock()
	}

	// FortiGate TACACS: browser form login encrypts the password client-side and
	// often never reaches TACACS. POST /pam-forti-login performs the same plain
	// /logincheck the CLI "diagnose test authserver" uses, then syncs cookies.
	if r.Method == http.MethodPost && rest == "/pam-forti-login" {
		handleFortiPortalLogin(w, r, sessionID, creds, targetURL, state)
		return
	}

	// FortiGate manifest is cosmetic; skip upstream fetch to avoid parse errors in DevTools.
	if r.Method == http.MethodGet && isWebManifestPath(rest) {
		w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(minimalWebManifest)
		return
	}

	// FortiGate NG SPA requires fweb_build.json with results.CONFIG_GUI_PUBLIC_PATH.
	// Upstream often returns 401 even with a valid admin session — always serve stub.
	if r.Method == http.MethodGet && isFortiBuildManifestPath(rest) && isFortinetSession(creds, state) {
		log.Printf("web-proxy: fortigate fweb_build.json stub session=%s", sessionID)
		fortigateWriteBuildStub(w, state, sessionID, httpClient.Jar, targetURL)
		return
	}

	// FortiGate /logout from inside the iframe is almost always an SPA crash
	// recovery navigation, not a user-initiated end-session click. Forwarding it
	// kills the upstream admin session and loops the iframe to /login. Treat as
	// a no-op — the PAM viewer "End Session" button has its own teardown path.
	if r.Method == http.MethodGet && isFortinetSession(creds, state) {
		p := strings.ToLower(strings.Split(rest, "?")[0])
		if p == "/logout" || p == "/login/logout" {
			log.Printf("web-proxy: fortigate blocking iframe /logout session=%s rest=%s", sessionID, rest)
			http.Redirect(w, r, fortigatePostLoginPath(sessionID, ""), http.StatusFound)
			return
		}
	}

	portalTokEarly := strings.TrimSpace(r.URL.Query().Get("token"))
	if portalTokEarly == "" {
		if c, err := r.Cookie("pam_web_tok"); err == nil {
			portalTokEarly = strings.TrimSpace(c.Value)
		}
	}

	// FortiGate: server-side login before authenticated SPA/API paths (TACACS uses portal creds).
	if isFortinetSession(creds, state) && !isFortinetPreAuthRequest(rest) {
		state.mu.Lock()
		needLogin := !state.fortiLoginDone
		assetPrefix := state.assetPrefix
		state.mu.Unlock()
		if needLogin {
			if ensureFortiGateAuthenticated(r.Context(), httpClient, targetURL, creds, state, assetPrefix) {
				syncUpstreamCookiesToBrowser(w, httpClient.Jar, targetURL, sessionID)
			}
		}
	}

	jarAuthed := fortigateJarAuthed(state, httpClient.Jar, targetURL, r)
	if jarAuthed && isFortinetSession(creds, state) && r.Method == http.MethodGet && shouldBounceFortinetAuthedToNG(rest) {
		if fortigateWriteJarDocument(w, r, state, targetURL, sessionID, "/ng/", upQ, creds, portalTokEarly, httpClient) {
			return
		}
		log.Printf("web-proxy: fortigate authed bounce session=%s path=%s -> /ng/", sessionID, rest)
		http.Redirect(w, r, fortigatePostLoginPath(sessionID, portalTokEarly), http.StatusFound)
		return
	}

	// Apply a previously-discovered asset prefix
	// static assets, so we don't repeat the 404+retry for every asset.
	effectiveRest := rest
	var triedPrefix string
	if isPublicWebAsset(rest) {
		state.mu.Lock()
		ap := state.assetPrefix
		strip := state.assetStrip
		state.mu.Unlock()
		// Strip first (the appliance referenced this prefix in its HTML but
		// doesn't actually serve assets there).
		if strip != "" && strings.HasPrefix(effectiveRest, strip+"/") {
			effectiveRest = strings.TrimPrefix(effectiveRest, strip)
		}
		if ap != "" && !strings.HasPrefix(effectiveRest, ap+"/") && effectiveRest != ap {
			effectiveRest = ap + effectiveRest
			triedPrefix = ap
		}
		primeUpstreamSession(r.Context(), httpClient, targetURL)
	}

	preferJarCookies := jarAuthed

	if jarAuthed && isFortinetSession(creds, state) && isFortiJarAPIPath(rest) {
		fortigateWriteJarAPIResponse(w, r, httpClient, targetURL, sessionID, rest, upQ, state)
		return
	}

	if jarAuthed && isFortinetSession(creds, state) && r.Method == http.MethodGet && isFortinetSPAEntryPath(rest) {
		if fortigateWriteJarDocument(w, r, state, targetURL, sessionID, rest, upQ, creds, portalTokEarly, httpClient) {
			return
		}
	}

	upstream, upstreamURL, err := buildWebUpstreamRequest(r, targetURL, effectiveRest, upQ, sessionID, creds, httpClient.Jar, preferJarCookies)
	if err != nil {
		writeWebProxyError(w, rest, "proxy build error: "+err.Error(), http.StatusBadGateway)
		return
	}

	debugf("upstream req session=%s method=%s url=%s asset=%v basic=%v",
		sessionID, upstream.Method, upstreamURL, isPublicWebAsset(rest), upstream.Header.Get("Authorization") != "")

	isLogincheck := r.Method == http.MethodPost && strings.Contains(strings.ToLower(rest), "logincheck")
	if isLogincheck {
		log.Printf("web-proxy: logincheck POST session=%s url=%s", sessionID, upstreamURL)
	}

	upResp, err := httpClient.Do(upstream)
	if err != nil {
		writeWebProxyError(w, rest, "proxy error: "+err.Error(), http.StatusBadGateway)
		return
	}

	// FortiGate: SPA API 401 — authenticate with portal/TACACS creds and retry once.
	if upResp.StatusCode == http.StatusUnauthorized &&
		strings.HasPrefix(strings.ToLower(rest), "/api/") &&
		isFortinetSession(creds, state) {
		importBrowserFortiCookiesIntoJar(r, httpClient.Jar, targetURL)
		state.mu.Lock()
		needLogin := !state.fortiLoginDone || !fortigateHasSessionCookies(httpClient.Jar, targetURL)
		if needLogin {
			state.fortiLoginDone = false
		}
		assetPrefix := state.assetPrefix
		state.mu.Unlock()
		if needLogin {
			io.Copy(io.Discard, upResp.Body)
			upResp.Body.Close()
			if ensureFortiGateAuthenticated(r.Context(), httpClient, targetURL, creds, state, assetPrefix) {
				syncUpstreamCookiesToBrowser(w, httpClient.Jar, targetURL, sessionID)
				preferJarCookies = true
				upstream, upstreamURL, err = buildWebUpstreamRequest(r, targetURL, effectiveRest, upQ, sessionID, creds, httpClient.Jar, true)
				if err != nil {
					writeWebProxyError(w, rest, "proxy retry build error: "+err.Error(), http.StatusBadGateway)
					return
				}
				upResp, err = httpClient.Do(upstream)
				if err != nil {
					writeWebProxyError(w, rest, "proxy retry error: "+err.Error(), http.StatusBadGateway)
					return
				}
			}
		}
	}

	if isLogincheck {
		// FortiOS encodes the auth result in the body (small JS payload or
		// "retcode=0/1" message). Sniff it so the operator can see why a
		// login failed without having to capture the network tab.
		body, _ := io.ReadAll(upResp.Body)
		upResp.Body.Close()
		upResp.Body = io.NopCloser(bytes.NewReader(body))
		log.Printf("web-proxy: logincheck result session=%s status=%d ct=%q body=%q",
			sessionID, upResp.StatusCode, upResp.Header.Get("Content-Type"), truncate(string(body), 240))
	}

	// On 404 for a static asset, try common appliance asset prefixes until one
	// serves it. FortiOS for example serves login-page assets under /login/, not /.
	if upResp.StatusCode == http.StatusNotFound && isPublicWebAsset(rest) && r.Method == http.MethodGet {
		log.Printf("web-proxy: upstream 404 session=%s url=%s — trying fallback prefixes (skip=%q)",
			sessionID, upstreamURL, triedPrefix)
		if alt, altURL, ok := retryAssetWithFallback(r, state, targetURL, rest, upQ, sessionID, creds, upResp, triedPrefix); ok {
			upResp = alt
			upstreamURL = altURL
		}
	}

	// MIME-mismatch fallback: FortiOS (and other SPA appliances) often return
	// HTTP 200 with the login HTML body for ANY unknown path under /login/.
	// That breaks the browser because <script src=login.js> ends up parsing
	// HTML as JavaScript ("Unexpected token '<'"). Detect this — an asset
	// request whose response Content-Type is text/html — and retry with the
	// fallback prefixes so we can find the file under /login/static/ etc.
	if upResp.StatusCode < 400 && isPublicWebAsset(rest) && r.Method == http.MethodGet {
		if assetExpectsScriptStyle(rest) && responseIsHTML(upResp) {
			log.Printf("web-proxy: mime mismatch session=%s url=%s ct=%q — appliance returned HTML for asset request, retrying fallback prefixes (skip=%q)",
				sessionID, upstreamURL, upResp.Header.Get("Content-Type"), triedPrefix)
			if alt, altURL, ok := retryAssetWithFallback(r, state, targetURL, rest, upQ, sessionID, creds, upResp, triedPrefix); ok {
				upResp = alt
				upstreamURL = altURL
			}
		}
	}
	defer upResp.Body.Close()

	if upResp.StatusCode == http.StatusNotFound && isPublicWebAsset(rest) {
		log.Printf("web-proxy: final 404 session=%s url=%s cookies=%d",
			sessionID, upstreamURL, len(httpClient.Jar.Cookies(upstream.URL)))
	} else {
		debugf("upstream resp session=%s url=%s status=%d", sessionID, upstreamURL, upResp.StatusCode)
	}

	// FortiGate: auto-detect from Server header (works when web_url is an IP).
	if srv := strings.ToLower(upResp.Header.Get("Server")); strings.Contains(srv, "forti") {
		state.mu.Lock()
		state.detectedFortinet = true
		state.mu.Unlock()
		creds.TargetKind = "fortinet-fortigate"
	}

	portalTok := strings.TrimSpace(r.URL.Query().Get("token"))
	if portalTok == "" {
		if c, err := r.Cookie("pam_web_tok"); err == nil {
			portalTok = strings.TrimSpace(c.Value)
		}
	}

	state.mu.Lock()
	fortiDone := state.fortiLoginDone
	state.mu.Unlock()
	if isFortinetSession(creds, state) {
		if upResp.StatusCode == http.StatusUnauthorized && strings.HasPrefix(strings.ToLower(rest), "/api/") {
			log.Printf("web-proxy: fortigate api 401 session=%s url=%s forti_done=%v jar_cookies=%d portal_pw=%v",
				sessionID, upstreamURL, fortiDone, len(collectJarCookies(httpClient.Jar, targetURL, rest)), creds.PortalPassword != "")
		}
		// fweb_build.json: upstream 401 or invalid body — serve synthetic stub.
		if isFortiBuildManifestPath(rest) && r.Method == http.MethodGet {
			if upResp.StatusCode == http.StatusUnauthorized {
				io.Copy(io.Discard, upResp.Body)
				upResp.Body.Close()
				log.Printf("web-proxy: fortigate fweb_build.json upstream 401 — serving stub session=%s", sessionID)
				fortigateWriteBuildStub(w, state, sessionID, httpClient.Jar, targetURL)
				return
			}
			if upResp.StatusCode == http.StatusOK {
				rawBody, _ := io.ReadAll(upResp.Body)
				upResp.Body.Close()
				body, err := decompressUpstreamBody(rawBody, upResp.Header.Get("Content-Encoding"))
				if err != nil {
					body = rawBody
				}
				if !fortigateStubHasGUIConfig(body) {
					log.Printf("web-proxy: fortigate fweb_build.json invalid body — serving stub session=%s", sessionID)
					fortigateWriteBuildStub(w, state, sessionID, httpClient.Jar, targetURL)
					return
				}
				upResp.Body = io.NopCloser(bytes.NewReader(body))
			}
		}
		if fortiDone {
			syncUpstreamCookiesToBrowser(w, httpClient.Jar, targetURL, sessionID)
		}
	}

	// Copy response headers, rewriting Location redirects to go through proxy.
	for k, vs := range upResp.Header {
		if strings.EqualFold(k, "Location") {
			for _, v := range vs {
				v = rewriteLocation(v, targetURL, sessionID, portalTok)
				if fortiDone && isFortinetSession(creds, state) && fortinetLocationShouldNG(v, sessionID) {
					v = fortigatePostLoginPath(sessionID, portalTok)
				}
				w.Header().Add(k, v)
			}
			continue
		}
		// Content-Type is set below from the path / body type (appliances often send text/plain).
		if strings.EqualFold(k, "Content-Type") {
			continue
		}
		if strings.EqualFold(k, "Set-Cookie") {
			for _, v := range vs {
				w.Header().Add(k, rewriteProxySetCookie(v, sessionID))
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
	mimeByPath := mimeForWebPath(rest)
	if isWebManifestPath(rest) {
		rawBody, _ := io.ReadAll(upResp.Body)
		body, err := decompressUpstreamBody(rawBody, upResp.Header.Get("Content-Encoding"))
		if err != nil {
			body = rawBody
		}
		body = coerceWebManifestBody(body, upResp.StatusCode)
		w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
		stripResponseEncoding(w.Header())
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		w.Write(body)
		return
	}
	rewriteBody := shouldRewriteWebBody(ct) || shouldRewriteWebPath(rest)
	if rewriteBody {
		rawBody, _ := io.ReadAll(upResp.Body)
		body, err := decompressUpstreamBody(rawBody, upResp.Header.Get("Content-Encoding"))
		if err != nil {
			log.Printf("web-proxy: decompress session=%s url=%s: %v", sessionID, upstreamURL, err)
			writeWebProxyError(w, rest, "proxy decode error", http.StatusBadGateway)
			return
		}
		// Asset path (.js/.css/.json/.woff…) with HTML body = appliance SPA
		// fallback (FortiOS returns its login page for any unknown asset).
		// Returning that HTML to the browser causes "Unexpected token '<'"
		// when it parses JS, "Failed to parse JSON" when it parses JSON, etc.
		// Serve an empty stub with the correct MIME and 404 status instead —
		// the page may render with reduced styling but won't hard-crash on
		// undefined globals (`try_login is not defined`).
		if assetExpectsScriptStyle(rest) && (responseIsHTML(upResp) || looksLikeHTMLBody(body)) {
			log.Printf("web-proxy: returning empty stub for asset session=%s url=%s (upstream sent HTML for asset path)",
				sessionID, upstreamURL)
			if mimeByPath != "" {
				w.Header().Set("Content-Type", mimeByPath)
			}
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body = rewriteHTML(body, targetURL, sessionID, portalTok, creds)
		// Only inject the FortiGate login bridge into actual HTML documents.
		// Path-based check guards against upstreams that mis-label JS as HTML.
		if isHTMLDocumentResponse(rest, ct) || (isFortinetSPAEntryPath(rest) && looksLikeHTMLBody(body)) {
			body = injectFortinetLoginAssist(body, creds, sessionID)
		}
		if mimeByPath != "" {
			w.Header().Set("Content-Type", mimeByPath)
		} else if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		stripResponseEncoding(w.Header())
		w.Header().Del("Content-Length")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(upResp.StatusCode)
		w.Write(body)
	} else {
		if mimeByPath != "" && (mimeByPath != ct || mimeNeedsFix(ct)) {
			w.Header().Set("Content-Type", mimeByPath)
		} else if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
		w.WriteHeader(upResp.StatusCode)
		io.Copy(w, upResp.Body)
	}
}

// buildWebUpstreamRequest constructs the outbound request to the device,
// stripping internal PAM headers/cookies and conditionally attaching Basic Auth.
func buildWebUpstreamRequest(r *http.Request, targetURL *url.URL, rest string, upQ url.Values, sessionID string, creds weblaunch.SessionCreds, jar http.CookieJar, preferJarCookies bool) (*http.Request, string, error) {
	upstreamURL := buildUpstreamURL(targetURL, rest, upQ)
	upstream, err := http.NewRequestWithContext(r.Context(), r.Method, upstreamURL, r.Body)
	if err != nil {
		return nil, upstreamURL, err
	}
	upstream.Header = r.Header.Clone()
	upstream.Header.Del("X-PAM-UID")
	upstream.Header.Del("X-PAM-Role")
	upstream.Header.Del("X-PAM-User")
	upstream.Header.Del("X-PAM-Web-Session")
	upstream.Header.Del("Authorization")
	rewriteUpstreamReferer(upstream.Header, targetURL, sessionID)
	tuneUpstreamRequest(upstream, targetURL, rest)
	mergeUpstreamCookies(upstream, r, jar, targetURL, preferJarCookies)
	if preferJarCookies && isFortinetTarget(creds) && strings.HasPrefix(strings.ToLower(rest), "/api/") {
		fortigateAttachCSRF(upstream, jar, targetURL)
	}

	// FortiGate/PAN-OS use form POST /logincheck — never attach Basic Auth on GET login paths.
	if shouldUseBasicAuth(r, rest, creds) {
		upstream.SetBasicAuth(creds.Username, creds.Password)
	}
	return upstream, upstreamURL, nil
}

// retryAssetWithFallback closes prevResp and tries the request under candidate
// URL paths until one returns a non-HTML, < 400 response. Strategies tried:
//
//  1. each prefix from assetFallbackPrefixes prepended to rest
//     (e.g. "/login/login.js" -> "/login/login/login.js" — skipped if it
//     would double an existing prefix)
//  2. stripping a leading prefix from rest (so "/login/login.js" is tried
//     as "/login.js" — covers FortiOS firmwares that serve login assets at
//     root instead of under /login/)
//  3. the original path (so the caller gets a real Response to render the
//     final 404 with)
//
// A successful prefix is cached on the session so subsequent assets skip
// the probing dance. skipPrefix is the prefix already attempted by the
// caller (the session's cached prefix, if any) so we don't retry it.
func retryAssetWithFallback(r *http.Request, state *webSessionState, targetURL *url.URL, rest string, upQ url.Values, sessionID string, creds weblaunch.SessionCreds, prevResp *http.Response, skipPrefix string) (*http.Response, string, bool) {
	httpClient := state.client
	io.Copy(io.Discard, prevResp.Body)
	prevResp.Body.Close()

	type candidate struct {
		path        string
		addPrefix   string // cache this as state.assetPrefix on success
		stripPrefix string // cache this as state.assetStrip on success
	}
	var tries []candidate
	// Strategy 1: try stripping known leading prefixes from `rest` FIRST.
	// FortiOS 7.x firmwares reference assets at /static/<path> in HTML but
	// actually serve them at /<path>. Stripping is more likely to succeed
	// than blindly prepending another wrong prefix.
	for _, prefix := range assetFallbackPrefixes {
		if !strings.HasPrefix(rest, prefix+"/") {
			continue
		}
		stripped := strings.TrimPrefix(rest, prefix)
		if stripped != rest && stripped != "" && stripped != "/" {
			tries = append(tries, candidate{path: stripped, stripPrefix: prefix})
		}
	}
	// Strategy 2: try prepending known appliance prefixes.
	for _, prefix := range assetFallbackPrefixes {
		if prefix == skipPrefix {
			continue
		}
		if strings.HasPrefix(rest, prefix+"/") || rest == prefix {
			continue // would double the prefix
		}
		tries = append(tries, candidate{path: prefix + rest, addPrefix: prefix})
	}

	wantNonHTML := assetExpectsScriptStyle(rest)
	state.mu.Lock()
	preferJar := state.fortiLoginDone
	state.mu.Unlock()
	for _, c := range tries {
		altReq, altURL, err := buildWebUpstreamRequest(r, targetURL, c.path, upQ, sessionID, creds, httpClient.Jar, preferJar)
		if err != nil {
			continue
		}
		debugf("upstream retry session=%s url=%s", sessionID, altURL)
		altResp, err := httpClient.Do(altReq)
		if err != nil {
			continue
		}
		if altResp.StatusCode < 400 && (!wantNonHTML || !responseIsHTML(altResp)) {
			log.Printf("web-proxy: fallback success session=%s path=%s url=%s add=%q strip=%q",
				sessionID, c.path, altURL, c.addPrefix, c.stripPrefix)
			state.mu.Lock()
			if c.addPrefix != "" {
				state.assetPrefix = c.addPrefix
			}
			if c.stripPrefix != "" {
				state.assetStrip = c.stripPrefix
			}
			state.mu.Unlock()
			return altResp, altURL, true
		}
		io.Copy(io.Discard, altResp.Body)
		altResp.Body.Close()
	}
	finalReq, finalURL, err := buildWebUpstreamRequest(r, targetURL, rest, upQ, sessionID, creds, httpClient.Jar, preferJar)
	if err != nil {
		return nil, "", false
	}
	finalResp, err := httpClient.Do(finalReq)
	if err != nil {
		return nil, finalURL, false
	}
	return finalResp, finalURL, true
}

// assetExpectsScriptStyle reports whether the request path is for a JS, CSS,
// JSON, font, or similar non-HTML asset that the browser will try to parse
// as a specific MIME type. Used to detect appliances that return their
// login HTML as a SPA fallback for unknown asset paths.
func assetExpectsScriptStyle(path string) bool {
	p := strings.ToLower(webPathOnly(path))
	switch {
	case strings.HasSuffix(p, ".js"),
		strings.HasSuffix(p, ".mjs"),
		strings.HasSuffix(p, ".css"),
		strings.HasSuffix(p, ".json"),
		strings.HasSuffix(p, ".map"),
		strings.HasSuffix(p, ".woff"),
		strings.HasSuffix(p, ".woff2"),
		strings.HasSuffix(p, ".ttf"),
		strings.HasSuffix(p, ".otf"):
		return true
	}
	return false
}

// responseIsHTML reports whether the upstream response Content-Type advertises
// an HTML document (so we can flag MIME mismatches for asset requests).
func responseIsHTML(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Type")))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return ct == "text/html" || ct == "application/xhtml+xml"
}

func mimeNeedsFix(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	return ct == "" || ct == "text/plain" || ct == "application/octet-stream"
}

func shouldRewriteWebPath(path string) bool {
	path = strings.ToLower(webPathOnly(path))
	switch {
	case strings.HasSuffix(path, ".html"), strings.HasSuffix(path, ".htm"):
		return true
	case strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".mjs"):
		return true
	case strings.HasSuffix(path, ".css"):
		return true
	}
	switch path {
	case "/", "/index.html", "/ng", "/ng/", "/ui", "/ui/", "/login", "/login/":
		return true
	}
	return strings.HasPrefix(path, "/ng/") || strings.HasPrefix(path, "/ui/") || strings.HasPrefix(path, "/login/")
}

// isHTMLWebResponse reports whether the upstream response is an HTML document
// (FortiGate login assist must not be injected into JSON/manifest bodies).
func isHTMLWebResponse(path, ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if strings.Contains(ct, "text/html") {
		return true
	}
	p := strings.ToLower(strings.Split(path, "?")[0])
	return strings.HasSuffix(p, ".html") || strings.HasSuffix(p, ".htm")
}

// isHTMLDocumentResponse reports true only when the response truly contains
// HTML (path is an HTML document OR path is non-asset AND CT is text/html).
// Unlike isHTMLWebResponse this returns FALSE for JS/CSS/JSON paths even when
// the upstream mislabels them as text/html — preventing us from injecting
// <script> tags into JS bundles and corrupting them.
func isHTMLDocumentResponse(path, ct string) bool {
	p := strings.ToLower(webPathOnly(path))
	switch {
	case strings.HasSuffix(p, ".html"), strings.HasSuffix(p, ".htm"):
		return true
	}
	if assetExpectsScriptStyle(p) {
		return false
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml")
}

// looksLikeHTMLBody returns true when the response payload starts with a tag
// that browsers treat as HTML. Used as a backup signal when the upstream
// Content-Type is missing or wrong (FortiOS sometimes serves login HTML as
// application/octet-stream).
func looksLikeHTMLBody(body []byte) bool {
	trim := bytes.TrimLeft(body, " \t\r\n\xef\xbb\xbf")
	if len(trim) < 5 {
		return false
	}
	prefix := strings.ToLower(string(trim[:min(64, len(trim))]))
	for _, p := range []string{"<!doctype html", "<html", "<head", "<body", "<meta", "<script"} {
		if strings.HasPrefix(prefix, p) {
			return true
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isApplianceEntryPath reports whether the path stored in target.Path is a
// well-known appliance LANDING page (FortiOS /login, PAN-OS /php/login.php,
// SSL-VPN portals) and should NOT be treated as a URL mount-point that gets
// auto-prepended to every proxied request.
func isApplianceEntryPath(p string) bool {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "", "/", "/login", "/logon", "/p", "/php/login.php",
		"/sslvpn", "/sslvpn/portal", "/remote", "/remote/login":
		return true
	}
	return false
}

// buildUpstreamURL joins the target base URL (including any path prefix in web_url)
// with the proxied request path and query string.
func buildUpstreamURL(target *url.URL, rest string, query url.Values) string {
	if target == nil {
		return rest
	}
	if !strings.HasPrefix(rest, "/") {
		rest = "/" + rest
	}
	// Split rest into path + optional embedded query so the caller can pass
	// "/foo?x=1" and have the query survive.
	embeddedQuery := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		embeddedQuery = rest[i+1:]
		rest = rest[:i]
	}
	// Preserve the target's base path (e.g. FortiOS "/ui", PAN-OS "/php") so
	// requests for "/static/x" reach "/ui/static/x" on the device instead of
	// the host root (which 404s on every appliance that runs its admin UI
	// behind a mount point).
	//
	// EXCEPTION: well-known appliance entry paths (FortiOS /login, PAN-OS
	// /php/login.php, SSL-VPN /sslvpn) are LANDING pages, not URL prefixes
	// the rest of the appliance lives under. Prepending /login to every
	// request like /api/v2/cmdb breaks the admin UI. Treat these like an
	// empty base — the request path is used as-is. Apps that legitimately
	// run behind a mount point (target_url like https://fw/ui) still get
	// the prefix applied.
	base := strings.TrimSuffix(target.Path, "/")
	if isApplianceEntryPath(base) {
		base = ""
	}
	if base != "" && !strings.HasPrefix(rest, base+"/") && rest != base {
		rest = base + rest
	}
	// upstreamHost strips :443 / :80 from the host so the rewritten URL has a
	// canonical origin — SPAs that compare window.location.host against the
	// served URL (FortiOS legacy login, F5 LTM) reject the page otherwise.
	u := &url.URL{
		Scheme:   target.Scheme,
		Host:     upstreamHost(target),
		Path:     rest,
		RawQuery: embeddedQuery,
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	return u.String()
}

func rewriteUpstreamReferer(h http.Header, target *url.URL, sessionID string) {
	base := target.Scheme + "://" + target.Host
	if target.Path != "" && target.Path != "/" {
		base += strings.TrimSuffix(target.Path, "/")
	}
	for _, key := range []string{"Referer", "Origin"} {
		v := strings.TrimSpace(h.Get(key))
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil {
			continue
		}
		if strings.Contains(u.Path, "/web/"+sessionID) {
			suffix := strings.TrimPrefix(u.Path, "/web/"+sessionID)
			u.Scheme = target.Scheme
			u.Host = target.Host
			u.Path = strings.TrimSuffix(target.Path, "/") + suffix
			q := u.Query()
			q.Del("token")
			u.RawQuery = q.Encode()
			h.Set(key, u.String())
			continue
		}
		if strings.HasPrefix(strings.ToLower(u.Host), strings.ToLower(target.Host)) {
			continue
		}
		h.Set(key, base)
	}
}

// writeWebProxyError returns an error body with the correct MIME type for static
// assets so browsers do not reject CSS/JS with "text/plain" on proxy failures.
func writeWebProxyError(w http.ResponseWriter, rest, msg string, code int) {
	if isWebManifestPath(rest) {
		w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(minimalWebManifest)
		return
	}
	if m := mimeForWebPath(rest); m != "" {
		w.Header().Set("Content-Type", m)
		w.WriteHeader(code)
		switch {
		case strings.HasSuffix(rest, ".css"):
			_, _ = w.Write([]byte("/* PAM: " + msg + " */"))
		case strings.HasSuffix(rest, ".js"), strings.HasSuffix(rest, ".mjs"):
			_, _ = w.Write([]byte("/* PAM: " + msg + " */"))
		default:
			_, _ = w.Write([]byte(msg))
		}
		return
	}
	http.Error(w, msg, code)
}

func pamTokenSuffix(tok string) string {
	if tok == "" {
		return ""
	}
	return "token=" + url.QueryEscape(tok)
}

func appendPortalToken(uri, tok string) string {
	if tok == "" {
		return uri
	}
	s := pamTokenSuffix(tok)
	if strings.Contains(uri, "?") {
		return uri + "&" + s
	}
	return uri + "?" + s
}

func shouldRewriteWebBody(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if strings.Contains(ct, "manifest") || strings.HasSuffix(ct, "+json") || ct == "application/json" {
		return false
	}
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
	fsPath := "web/" + path
	b, err := webFS.ReadFile(fsPath)
	if err != nil {
		if strings.Contains(path, ".") {
			http.NotFound(w, r)
			return
		}
		fsPath = "web/index.html"
		b, err = webFS.ReadFile(fsPath)
		if err != nil {
			http.NotFound(w, r)
			return
		}
	}
	if ct := mimeForWebPath(fsPath); ct != "" {
		w.Header().Set("Content-Type", ct)
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
		if u.Query().Get("token") == "" {
			if ref := r.Header.Get("Referer"); ref != "" {
				if ru, err := url.Parse(ref); err == nil {
					if t := strings.TrimSpace(ru.Query().Get("token")); t != "" {
						q := u.Query()
						q.Set("token", t)
						u.RawQuery = q.Encode()
					}
				}
			}
		}
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
	for _, p := range []string{"/web-viewer.html", "/rdp-viewer.html", "/ssh-viewer.html", "/guac-player.html"} {
		if path == p {
			return true
		}
	}
	if strings.HasPrefix(path, "/vendor/") {
		return true
	}
	return false
}

func rewriteLocation(loc string, target *url.URL, sessionID, portalToken string) string {
	sessionPfx := "/web/" + sessionID
	for _, host := range targetHostVariants(target) {
		for _, scheme := range []string{"http://", "https://"} {
			pref := scheme + host
			if !strings.HasPrefix(loc, pref) {
				continue
			}
			u, err := url.Parse(loc)
			if err != nil {
				break
			}
			ru := u.RequestURI()
			if strings.HasPrefix(ru, sessionPfx+"/") || ru == sessionPfx {
				return appendPortalToken(ru, portalToken)
			}
			return appendPortalToken(sessionPfx+ru, portalToken)
		}
	}
	if strings.HasPrefix(loc, "/") {
		if strings.HasPrefix(loc, sessionPfx+"/") || loc == sessionPfx {
			return appendPortalToken(loc, portalToken)
		}
		return appendPortalToken(sessionPfx+loc, portalToken)
	}
	return loc
}

func rewriteHTML(body []byte, target *url.URL, sessionID, portalToken string, creds weblaunch.SessionCreds) []byte {
	pfx := "/web/" + sessionID
	// Browsers honour only the FIRST <base> tag in document order. Some appliances
	// (FortiOS uses <base href="/login/">) emit their own — injecting ours would
	// stomp on it and make relative assets (styles.css, login.js…) 404. Only
	// inject when the upstream HTML has no <base href="…"> of its own; the root
	// path rewriter below will prefix any existing one with /web/{sessionID}/.
	if !containsBaseHref(body) {
		baseTag := []byte(`<base href="` + pfx + `/">`)
		if idx := bytes.Index(body, []byte("<head>")); idx >= 0 {
			body = append(body[:idx+6], append(baseTag, body[idx+6:]...)...)
		} else if idx := bytes.Index(body, []byte("<HEAD>")); idx >= 0 {
			body = append(body[:idx+6], append(baseTag, body[idx+6:]...)...)
		}
	}
	// Rewrite absolute target host URLs (with and without :443/:80).
	body = rewriteAbsoluteTargetHosts(body, target, pfx)
	// Root-absolute paths (/static/, /api/v2/, …) ignore <base> — prefix them.
	return rewriteRootPaths(body, pfx, portalToken)
}

// containsBaseHref reports whether the HTML body already has a <base href="…"> tag.
// Match is case-insensitive and only matches the <base> element (not <baseLayout>).
func containsBaseHref(body []byte) bool {
	lower := bytes.ToLower(body)
	i := 0
	for i < len(lower) {
		idx := bytes.Index(lower[i:], []byte("<base"))
		if idx < 0 {
			return false
		}
		after := i + idx + len("<base")
		if after >= len(lower) {
			return false
		}
		c := lower[after]
		// Reject <baseXYZ>; accept <base ...> or <base>.
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '/' || c == '>' {
			end := bytes.IndexByte(lower[after:], '>')
			if end < 0 {
				return false
			}
			if bytes.Contains(lower[after:after+end], []byte("href=")) {
				return true
			}
		}
		i = after
	}
	return false
}

// rewriteRootPaths prefixes root-absolute URL paths inside HTML/JS/CSS so they
// route through /web/{sessionID}/ instead of the PAM gateway root.
func rewriteRootPaths(body []byte, pfx, portalToken string) []byte {
	if len(pfx) == 0 {
		return body
	}
	// Common SPA string literals in bundled JS.
	for _, pair := range [][2]string{
		{`"/api/`, `"` + pfx + `/api/`},
		{`'/api/`, `'` + pfx + `/api/`},
		{`"/static/`, `"` + pfx + `/static/`},
		{`'/static/`, `'` + pfx + `/static/`},
		{`"/static/js/`, `"` + pfx + `/static/js/`},
		{`'/static/js/`, `'` + pfx + `/static/js/`},
		{`"/static/css/`, `"` + pfx + `/static/css/`},
		{`'/static/css/`, `'` + pfx + `/static/css/`},
		{`"/assets/`, `"` + pfx + `/assets/`},
		{`'/assets/`, `'` + pfx + `/assets/`},
		{`"/favicon/`, `"` + pfx + `/favicon/`},
		{`'/favicon/`, `'` + pfx + `/favicon/`},
		{`"/ng/`, `"` + pfx + `/ng/`},
		{`'/ng/`, `'` + pfx + `/ng/`},
		{`"/ui/`, `"` + pfx + `/ui/`},
		{`'/ui/`, `'` + pfx + `/ui/`},
		{`"/logincheck`, `"` + pfx + `/logincheck`},
		{`'/logincheck`, `'` + pfx + `/logincheck`},
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
			body = rewriteRootAttr(body, attr, q, pfx, portalToken)
		}
	}
	return body
}

func rewriteRootAttr(body []byte, attr string, quote byte, pfx, portalToken string) []byte {
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
		j := absStart
		for j < len(body) && body[j] != quote && body[j] != '?' {
			j++
		}
		out.Write(body[absStart:j])
		if portalToken != "" && j > absStart && (j >= len(body) || body[j] == quote) {
			sep := "?"
			if bytes.Contains(body[absStart:j], []byte("?")) {
				sep = "&"
			}
			out.Write([]byte(sep + pamTokenSuffix(portalToken)))
		}
		if j < len(body) && body[j] == quote {
			out.Write(body[j : j+1])
			i = j + 1
		} else {
			i = j
		}
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
