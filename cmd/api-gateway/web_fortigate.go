package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/example/pam-platform/internal/weblaunch"
)

func isFortinetKind(kind string) bool {
	k := strings.ToLower(strings.TrimSpace(kind))
	return strings.Contains(k, "forti")
}

// inferTargetKind fills TargetKind when older vault payloads omit it.
func inferTargetKind(creds weblaunch.SessionCreds) string {
	if k := strings.TrimSpace(creds.TargetKind); k != "" {
		return k
	}
	u, err := url.Parse(creds.TargetURL)
	if err != nil {
		return creds.TargetKind
	}
	h := strings.ToLower(u.Hostname() + u.Path)
	if strings.Contains(h, "forti") {
		return "fortinet-fortigate"
	}
	return creds.TargetKind
}

func isFortinetTarget(creds weblaunch.SessionCreds) bool {
	return isFortinetKind(inferTargetKind(creds))
}

func isFortinetSession(creds weblaunch.SessionCreds, state *webSessionState) bool {
	if isFortinetTarget(creds) {
		return true
	}
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.detectedFortinet
}

func targetHostVariants(target *url.URL) []string {
	if target == nil {
		return nil
	}
	hn := target.Hostname()
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	add(target.Host)
	add(hn)
	if port := target.Port(); port != "" {
		add(net.JoinHostPort(hn, port))
	}
	return out
}

func rewriteAbsoluteTargetHosts(body []byte, target *url.URL, pfx string) []byte {
	for _, scheme := range []string{"https://", "http://"} {
		for _, host := range targetHostVariants(target) {
			body = bytes.ReplaceAll(body, []byte(scheme+host), []byte(pfx))
		}
	}
	return body
}

// stripInternalCookies removes PAM session cookies before forwarding to the device.
func stripInternalCookies(cookieHeader string) string {
	if cookieHeader == "" {
		return ""
	}
	var kept []string
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := part
		if i := strings.IndexByte(part, '='); i >= 0 {
			name = part[:i]
		}
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "pam_web_tok" || lower == "pam_web_sid" {
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "; ")
}

// mergeUpstreamCookies forwards browser device cookies and lets the client jar add the rest.
func mergeUpstreamCookies(upstream *http.Request, browser *http.Request, jar http.CookieJar, target *url.URL) {
	device := stripInternalCookies(browser.Header.Get("Cookie"))
	if device != "" {
		upstream.Header.Set("Cookie", device)
	} else {
		upstream.Header.Del("Cookie")
	}
	if jar == nil || target == nil {
		return
	}
	u, err := url.Parse(upstream.URL.String())
	if err != nil {
		return
	}
	jarCookies := jar.Cookies(u)
	if len(jarCookies) == 0 {
		return
	}
	seen := map[string]bool{}
	var parts []string
	if c := upstream.Header.Get("Cookie"); c != "" {
		for _, p := range strings.Split(c, ";") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			name := p
			if i := strings.IndexByte(p, '='); i >= 0 {
				name = p[:i]
			}
			seen[strings.TrimSpace(name)] = true
			parts = append(parts, p)
		}
	}
	for _, c := range jarCookies {
		if seen[c.Name] {
			continue
		}
		seen[c.Name] = true
		parts = append(parts, c.Name+"="+c.Value)
	}
	if len(parts) > 0 {
		upstream.Header.Set("Cookie", strings.Join(parts, "; "))
	}
}

func fortigateLogincheckPaths(assetPrefix string) []string {
	paths := []string{"/logincheck", "/login/logincheck"}
	p := strings.TrimSuffix(strings.TrimSpace(assetPrefix), "/")
	if p != "" && p != "/login" {
		paths = append(paths, p+"/logincheck")
	}
	return paths
}

// fortigateFormLogin performs FortiOS admin GUI login via POST /logincheck.
// FortiGate does not accept HTTP Basic auth on the login page — that yields
// "Authentication failure" while still showing the form.
func fortigateFormLogin(ctx context.Context, client *http.Client, target *url.URL, username, password, assetPrefix string) bool {
	if client == nil || target == nil || username == "" || password == "" {
		return false
	}
	for _, checkPath := range fortigateLogincheckPaths(assetPrefix) {
		for _, passField := range []string{"secretkey", "passwd"} {
			form := url.Values{}
			form.Set("username", username)
			form.Set(passField, password)
			form.Set("ajax", "1")
			u := buildUpstreamURL(target, checkPath, nil)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			tuneUpstreamRequest(req, target, checkPath)
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("web-proxy: fortigate logincheck (%s %s): %v", checkPath, passField, err)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if fortigateLoginOK(resp, body) {
				log.Printf("web-proxy: fortigate form login ok user=%q url=%s", username, u)
				return true
			}
			log.Printf("web-proxy: fortigate logincheck failed user=%q status=%d path=%s field=%s body=%q",
				username, resp.StatusCode, checkPath, passField, truncate(string(body), 120))
		}
	}
	return false
}

func fortigateLoginOK(resp *http.Response, body []byte) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return true
	}
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		loc := strings.ToLower(resp.Header.Get("Location"))
		if loc != "" && !strings.Contains(loc, "login") {
			return true
		}
	}
	var m map[string]interface{}
	if json.Unmarshal(body, &m) == nil {
		if rc, ok := m["retcode"].(float64); ok && rc == 0 {
			return true
		}
		if s, ok := m["status"].(string); ok && strings.EqualFold(s, "success") {
			return true
		}
	}
	return false
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// syncUpstreamCookiesToBrowser copies device session cookies from the proxy's
// upstream jar into the browser Set-Cookie headers (path rewritten for /web/sid/).
func syncUpstreamCookiesToBrowser(w http.ResponseWriter, jar http.CookieJar, target *url.URL, sessionID string) {
	if jar == nil || target == nil {
		return
	}
	u := &url.URL{Scheme: target.Scheme, Host: upstreamHost(target), Path: "/"}
	for _, c := range jar.Cookies(u) {
		w.Header().Add("Set-Cookie", rewriteProxySetCookie(c.Name+"="+c.Value, sessionID))
	}
}

func shouldUseBasicAuth(r *http.Request, rest string, creds weblaunch.SessionCreds) bool {
	if creds.Username == "" || creds.Password == "" {
		return false
	}
	if r.Method != http.MethodGet {
		return false
	}
	if isPublicWebAsset(rest) {
		return false
	}
	if isFortinetTarget(creds) {
		return false
	}
	p := strings.ToLower(webPathOnly(rest))
	switch p {
	case "/login", "/logincheck":
		return false
	}
	if strings.HasPrefix(p, "/login/") {
		return false
	}
	// FortiGate (and similar) login pages break when Basic auth is sent before kind is known.
	if strings.TrimSpace(creds.TargetKind) == "" && isLikelyLoginProbe(p) {
		return false
	}
	return true
}

func isLikelyLoginProbe(path string) bool {
	switch path {
	case "/", "/index.html":
		return true
	default:
		return false
	}
}

func injectFortinetLoginAssist(body []byte, creds weblaunch.SessionCreds, sessionID string) []byte {
	if !isFortinetTarget(creds) {
		lower := bytes.ToLower(body)
		if !bytes.Contains(lower, []byte("logincheck")) && !bytes.Contains(lower, []byte("fortios")) {
			return body
		}
	}
	script := fortinetProxyBridgeScript(sessionID, creds.PortalUsername)
	if i := bytes.Index(body, []byte("</body>")); i >= 0 {
		return append(append(body[:i], script...), body[i:]...)
	}
	if i := bytes.Index(body, []byte("</head>")); i >= 0 {
		return append(append(body[:i], script...), body[i:]...)
	}
	return append(body, script...)
}

func loginAssetPrefixFromTarget(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	p := strings.TrimSuffix(u.Path, "/")
	if p == "" || p == "/" {
		return ""
	}
	return p
}

func fortinetProxyBridgeScript(sessionID string, portalUser string) []byte {
	pfx := "/web/" + sessionID
	pfxJSON, _ := json.Marshal(pfx)
	userJSON, _ := json.Marshal(portalUser)
	return []byte(`<script>(function(){` +
		`var pfx=` + string(pfxJSON) + `;` +
		`function fix(u){if(typeof u!=="string")return u;` +
		`if(u.indexOf(pfx)===0)return u;` +
		`if(u.indexOf("/logincheck")>=0||u.indexOf("/logout")>=0||u.indexOf("/login")===0){` +
		`if(u.charAt(0)==="/")return pfx+u;` +
		`if(u.indexOf("://")<0)return pfx+"/"+u.replace(/^\.\//,"");}` +
		`return u;}` +
		`["assign","replace"].forEach(function(fn){` +
		`var o=Location.prototype[fn];if(!o)return;` +
		`Location.prototype[fn]=function(u){return o.call(this,fix(String(u)));};});` +
		`if(window.fetch){var f=window.fetch;window.fetch=function(u,o){return f.call(this,fix(u),o);};}` +
		`var xo=XMLHttpRequest.prototype.open;` +
		`XMLHttpRequest.prototype.open=function(m,u){arguments[1]=fix(u);return xo.apply(this,arguments);};` +
		`try{var u=document.querySelector('input[name=username],#username,input[id*=user i]');` +
		`if(u&&!u.value)u.value=` + string(userJSON) + `;}catch(e){}` +
		`})();</script>`)
}
