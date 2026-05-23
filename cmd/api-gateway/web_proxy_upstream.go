package main

import (
	"context"
	"io"
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
			return http.ErrUseLastResponse
		},
	}
	actual, _ := webUpstreamClients.LoadOrStore(sessionID, c)
	return actual.(*http.Client)
}

func dropUpstreamClient(sessionID string) {
	webUpstreamClients.Delete(sessionID)
}

// isPublicWebAsset is true for login-page static files that appliances serve
// without credentials (Basic auth on these paths can cause 404 on PAN-OS).
func isPublicWebAsset(path string) bool {
	p := strings.ToLower(path)
	return strings.HasPrefix(p, "/static/") ||
		strings.HasPrefix(p, "/favicon/") ||
		strings.HasPrefix(p, "/fonts/") ||
		strings.HasPrefix(p, "/images/")
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
