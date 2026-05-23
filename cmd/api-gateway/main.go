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
	w.Write(b)
}

func mimeForWebPath(path string) string {
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

	// Apply a previously-discovered asset prefix (e.g. "/login" on FortiOS) for
	// static assets, so we don't repeat the 404+retry for every asset.
	effectiveRest := rest
	var triedPrefix string
	if isPublicWebAsset(rest) {
		state.mu.Lock()
		ap := state.assetPrefix
		state.mu.Unlock()
		if ap != "" && !strings.HasPrefix(rest, ap+"/") && rest != ap {
			effectiveRest = ap + rest
			triedPrefix = ap
		}
		primeUpstreamSession(r.Context(), httpClient, targetURL)
	}

	upstream, upstreamURL, err := buildWebUpstreamRequest(r, targetURL, effectiveRest, upQ, sessionID, creds)
	if err != nil {
		writeWebProxyError(w, rest, "proxy build error: "+err.Error(), http.StatusBadGateway)
		return
	}

	debugf("upstream req session=%s method=%s url=%s asset=%v basic=%v",
		sessionID, upstream.Method, upstreamURL, isPublicWebAsset(rest), upstream.Header.Get("Authorization") != "")

	upResp, err := httpClient.Do(upstream)
	if err != nil {
		writeWebProxyError(w, rest, "proxy error: "+err.Error(), http.StatusBadGateway)
		return
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
	defer upResp.Body.Close()

	if upResp.StatusCode == http.StatusNotFound && isPublicWebAsset(rest) {
		log.Printf("web-proxy: final 404 session=%s url=%s cookies=%d",
			sessionID, upstreamURL, len(httpClient.Jar.Cookies(upstream.URL)))
	} else {
		debugf("upstream resp session=%s url=%s status=%d", sessionID, upstreamURL, upResp.StatusCode)
	}

	portalTok := strings.TrimSpace(r.URL.Query().Get("token"))
	if portalTok == "" {
		if c, err := r.Cookie("pam_web_tok"); err == nil {
			portalTok = strings.TrimSpace(c.Value)
		}
	}

	// Copy response headers, rewriting Location redirects to go through proxy.
	for k, vs := range upResp.Header {
		if strings.EqualFold(k, "Location") {
			for _, v := range vs {
				v = rewriteLocation(v, targetURL, sessionID, portalTok)
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
	rewriteBody := shouldRewriteWebBody(ct) || shouldRewriteWebPath(rest)
	if rewriteBody {
		body, _ := io.ReadAll(upResp.Body)
		body = rewriteHTML(body, targetURL, sessionID, portalTok)
		if mimeByPath != "" {
			w.Header().Set("Content-Type", mimeByPath)
		} else if ct != "" {
			w.Header().Set("Content-Type", ct)
		}
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
func buildWebUpstreamRequest(r *http.Request, targetURL *url.URL, rest string, upQ url.Values, sessionID string, creds weblaunch.SessionCreds) (*http.Request, string, error) {
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
	upstream.Header.Del("Cookie")
	rewriteUpstreamReferer(upstream.Header, targetURL, sessionID)
	tuneUpstreamRequest(upstream, targetURL, rest)

	// Only attach Basic Auth on GETs of non-asset paths. Form-auth appliances
	// (FortiOS, modern PAN-OS) use POST /logincheck or /api with form bodies;
	// adding an Authorization header on those requests makes the device 401 the
	// login attempt and bounce the user back to the login page even when the
	// form credentials are correct.
	if creds.Username != "" && creds.Password != "" && r.Method == http.MethodGet && !isPublicWebAsset(rest) {
		upstream.SetBasicAuth(creds.Username, creds.Password)
	}
	return upstream, upstreamURL, nil
}

// retryAssetWithFallback closes prevResp and tries the request with each
// candidate URL prefix from assetFallbackPrefixes until one returns < 400.
// The discovered prefix is cached on the session so subsequent assets skip
// the probing dance. skipPrefix is the prefix already attempted by the
// caller (the session's cached prefix, if any) so we don't retry it.
func retryAssetWithFallback(r *http.Request, state *webSessionState, targetURL *url.URL, rest string, upQ url.Values, sessionID string, creds weblaunch.SessionCreds, prevResp *http.Response, skipPrefix string) (*http.Response, string, bool) {
	httpClient := state.client
	// Drain and close the original 404 so the connection can be reused.
	io.Copy(io.Discard, prevResp.Body)
	prevResp.Body.Close()

	for _, prefix := range assetFallbackPrefixes {
		if prefix == skipPrefix {
			continue
		}
		altRest := prefix + rest
		altReq, altURL, err := buildWebUpstreamRequest(r, targetURL, altRest, upQ, sessionID, creds)
		if err != nil {
			continue
		}
		debugf("upstream retry session=%s url=%s", sessionID, altURL)
		altResp, err := httpClient.Do(altReq)
		if err != nil {
			continue
		}
		if altResp.StatusCode < 400 {
			log.Printf("web-proxy: fallback success session=%s prefix=%s url=%s", sessionID, prefix, altURL)
			state.mu.Lock()
			state.assetPrefix = prefix
			state.mu.Unlock()
			return altResp, altURL, true
		}
		io.Copy(io.Discard, altResp.Body)
		altResp.Body.Close()
	}
	// All fallbacks failed — fetch the original path once more so the caller
	// gets a real Response object to render the 404 with.
	finalReq, finalURL, err := buildWebUpstreamRequest(r, targetURL, rest, upQ, sessionID, creds)
	if err != nil {
		return nil, "", false
	}
	finalResp, err := httpClient.Do(finalReq)
	if err != nil {
		return nil, finalURL, false
	}
	return finalResp, finalURL, true
}

func mimeNeedsFix(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	return ct == "" || ct == "text/plain" || ct == "application/octet-stream"
}

func shouldRewriteWebPath(path string) bool {
	switch {
	case strings.HasSuffix(path, ".html"), strings.HasSuffix(path, ".htm"):
		return true
	case strings.HasSuffix(path, ".js"), strings.HasSuffix(path, ".mjs"):
		return true
	case strings.HasSuffix(path, ".css"):
		return true
	case strings.HasSuffix(path, ".json"), strings.HasSuffix(path, ".webmanifest"):
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
	base := strings.TrimSuffix(target.Path, "/")
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
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "text/css") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "application/manifest")
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
	if strings.HasPrefix(loc, "http://"+target.Host) ||
		strings.HasPrefix(loc, "https://"+target.Host) {
		u, err := url.Parse(loc)
		if err == nil {
			ru := u.RequestURI()
			// Avoid /web/{sid}/web/{sid}/… when the device echoes a redir param
			// containing our own proxy path (FortiOS does this after login).
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

func rewriteHTML(body []byte, target *url.URL, sessionID, portalToken string) []byte {
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
	// Rewrite absolute target host URLs.
	for _, scheme := range []string{"https://", "http://"} {
		old := []byte(scheme + target.Host)
		body = bytes.ReplaceAll(body, old, []byte(pfx))
	}
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
