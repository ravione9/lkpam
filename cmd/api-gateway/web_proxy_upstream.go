package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
)

// webUpstreamClients holds one HTTP client per web-console session so device
// Set-Cookie headers (PAN-OS, FortiGate, etc.) are replayed on /static/ assets.
// Browsers often drop Secure cookies when the portal is served over HTTP.
var webUpstreamClients sync.Map

func upstreamClientForSession(sessionID string) *http.Client {
	if c, ok := webUpstreamClients.Load(sessionID); ok {
		return c.(*http.Client)
	}
	jar, _ := cookiejar.New(nil)
	c := &http.Client{
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
	}
	actual, _ := webUpstreamClients.LoadOrStore(sessionID, c)
	return actual.(*http.Client)
}

func dropUpstreamClient(sessionID string) {
	webUpstreamClients.Delete(sessionID)
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
