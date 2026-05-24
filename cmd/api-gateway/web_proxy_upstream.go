package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
)

// webProxyDebug enables verbose request/response logging when env PAM_WEB_PROXY_DEBUG=1.
var webProxyDebug = os.Getenv("PAM_WEB_PROXY_DEBUG") == "1"

// webSessionState carries the upstream HTTP client (with its cookie jar) plus
// vendor-quirk fields like the discovered static-asset URL prefix.
type webSessionState struct {
	client *http.Client
	mu     sync.Mutex
	// assetPrefix is the upstream URL path the appliance actually serves login
	// static assets under (e.g. "/login" on FortiOS, "" on PAN-OS/root). Empty
	// until probed; populated the first time a fallback retry returns < 400.
	assetPrefix string
	// assetStrip is a leading path the appliance does NOT use for its assets,
	// even though the login HTML references them under it. FortiOS firmwares
	// (7.x+) emit <link href="/static/css/..."> but actually serve the file
	// at "/css/...". Once we learn this via fallback retry we strip the
	// prefix from every subsequent asset path so we don't pay the 5-retry
	// cost per asset.
	assetStrip string
	// fortiLoginDone tracks server-side FortiGate form login for this session.
	fortiLoginDone bool
	// detectedFortinet is set when upstream Server header contains FortiOS.
	detectedFortinet bool
}

// webUpstreamClients holds one *webSessionState per web-console session so device
// Set-Cookie headers (PAN-OS, FortiGate, etc.) are replayed on /static/ assets.
// Browsers often drop Secure cookies when the portal is served over HTTP.
var webUpstreamClients sync.Map

func upstreamSessionState(sessionID string) *webSessionState {
	if v, ok := webUpstreamClients.Load(sessionID); ok {
		return v.(*webSessionState)
	}
	jar, _ := cookiejar.New(nil)
	s := &webSessionState{
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tlsConfig{InsecureSkipVerify: true},
			},
			Jar: jar,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
	actual, _ := webUpstreamClients.LoadOrStore(sessionID, s)
	return actual.(*webSessionState)
}

func upstreamClientForSession(sessionID string) *http.Client {
	return upstreamSessionState(sessionID).client
}

func dropUpstreamClient(sessionID string) {
	webUpstreamClients.Delete(sessionID)
}

// assetFallbackPrefixes lists URL prefixes appliances commonly use to serve
// pre-auth login static assets when the bare path at root returns 404. The
// order matters: FortiOS uses /login, some PHP appliances use /p, SSL VPN
// portals use /sslvpn or /remote.
var assetFallbackPrefixes = []string{
	"/login",
	"/p",
	"/sslvpn",
	"/remote",
	"/portal",
	"/static",
}

// debugf logs at debug level when PAM_WEB_PROXY_DEBUG=1.
func debugf(format string, args ...interface{}) {
	if webProxyDebug {
		log.Printf("web-proxy: "+format, args...)
	}
}

// isPublicWebAsset is true for login-page static files that appliances serve
// without credentials. Basic auth on these can cause 404 on PAN-OS, and on
// FortiOS the Authorization header routes the request to an API handler that
// returns 404 for non-API URLs (breaking styles.css / login.js etc.).
func isPublicWebAsset(path string) bool {
	p := strings.ToLower(path)
	if q := strings.IndexByte(p, '?'); q >= 0 {
		p = p[:q]
	}
	if strings.HasPrefix(p, "/static/") ||
		strings.HasPrefix(p, "/favicon/") ||
		strings.HasPrefix(p, "/fonts/") ||
		strings.HasPrefix(p, "/images/") ||
		strings.HasPrefix(p, "/img/") ||
		strings.HasPrefix(p, "/css/") ||
		strings.HasPrefix(p, "/js/") ||
		strings.HasPrefix(p, "/assets/") {
		return true
	}
	// Bare static-file extensions used by appliance login pages (FortiOS serves
	// styles.css, legacy-main.css, login.js, legacy_theme_setup.js, site.webmanifest,
	// favicon-*.png at non-/static/ paths).
	switch {
	case strings.HasSuffix(p, ".css"),
		strings.HasSuffix(p, ".js"),
		strings.HasSuffix(p, ".mjs"),
		strings.HasSuffix(p, ".map"),
		strings.HasSuffix(p, ".webmanifest"),
		strings.HasSuffix(p, ".ico"),
		strings.HasSuffix(p, ".png"),
		strings.HasSuffix(p, ".jpg"),
		strings.HasSuffix(p, ".jpeg"),
		strings.HasSuffix(p, ".gif"),
		strings.HasSuffix(p, ".svg"),
		strings.HasSuffix(p, ".woff"),
		strings.HasSuffix(p, ".woff2"),
		strings.HasSuffix(p, ".ttf"),
		strings.HasSuffix(p, ".otf"),
		strings.HasSuffix(p, ".eot"):
		return true
	}
	return false
}

// rewriteProxySetCookie adjusts device cookies for the PAM proxy path and strips
// Secure so browsers accept them when the portal is HTTP.
func rewriteProxySetCookie(cookie, sessionID string) string {
	pfx := "/web/" + sessionID + "/"
	parts := strings.Split(cookie, ";")
	if len(parts) == 0 {
		return cookie
	}
	out := []string{strings.TrimSpace(parts[0])}
	hasPath := false
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		lower := strings.ToLower(p)
		if lower == "secure" {
			continue
		}
		if strings.HasPrefix(lower, "path=") {
			hasPath = true
			out = append(out, "Path="+pfx)
			continue
		}
		if strings.HasPrefix(lower, "domain=") {
			continue
		}
		out = append(out, p)
	}
	if !hasPath {
		out = append(out, "Path="+pfx)
	}
	return strings.Join(out, "; ")
}

// upstreamHost returns the Host header value appliances expect (no :443/:80 suffix).
func upstreamHost(target *url.URL) string {
	if target == nil {
		return ""
	}
	host := target.Hostname()
	port := target.Port()
	if port == "" {
		return host
	}
	if (target.Scheme == "https" && port == "443") || (target.Scheme == "http" && port == "80") {
		return host
	}
	return net.JoinHostPort(host, port)
}

// needsPANAuthCheckOff is true for PAN-OS nginx routes that serve login UI static files.
// Without X-PAN-Authcheck: off the front-end nginx returns 404 for /static/* via reverse proxy.
func needsPANAuthCheckOff(rest string) bool {
	p := strings.ToLower(strings.Split(rest, "?")[0])
	if isPublicWebAsset(p) {
		return true
	}
	switch {
	case p == "/login", strings.HasPrefix(p, "/login/"):
		return true
	case strings.HasPrefix(p, "/php/login"):
		return true
	case p == "/", p == "/index.html":
		return true
	}
	return false
}

// tuneUpstreamRequest sets headers required by PAN-OS / FortiGate when proxied.
func tuneUpstreamRequest(upstream *http.Request, target *url.URL, rest string) {
	upstream.Host = upstreamHost(target)
	if needsPANAuthCheckOff(rest) {
		upstream.Header.Set("X-PAN-Authcheck", "off")
	}
	if upstream.Header.Get("X-Forwarded-Proto") == "" {
		upstream.Header.Set("X-Forwarded-Proto", target.Scheme)
	}
	if upstream.Header.Get("X-Forwarded-Host") == "" {
		upstream.Header.Set("X-Forwarded-Host", upstreamHost(target))
	}
}

// primeUpstreamSession fetches the device login/root page once per session so
// PAN-OS / FortiGate Set-Cookie values exist before /static/ asset requests.
func primeUpstreamSession(ctx context.Context, client *http.Client, target *url.URL) {
	if client == nil || client.Jar == nil || target == nil {
		return
	}
	probe, _ := url.Parse(buildUpstreamURL(target, "/", nil))
	if probe != nil && len(client.Jar.Cookies(probe)) > 0 {
		return
	}
	for _, path := range []string{"/login", "/php/login.php", "/"} {
		u := buildUpstreamURL(target, path, nil)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Host = target.Host
		req.Header.Set("X-PAN-Authcheck", "off")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if probe, _ := url.Parse(u); probe != nil && len(client.Jar.Cookies(probe)) > 0 {
			return
		}
		if len(client.Jar.Cookies(probe)) > 0 {
			return
		}
	}
}
