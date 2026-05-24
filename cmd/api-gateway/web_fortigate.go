package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/example/pam-platform/internal/weblaunch"
)

func isFortinetKind(kind string) bool {
	k := strings.ToLower(strings.TrimSpace(kind))
	return strings.Contains(k, "forti")
}

// fortigateFormLogin performs FortiOS admin GUI login via POST /logincheck.
// FortiGate does not accept HTTP Basic auth on the login page — that yields
// "Authentication failure" while still showing the form.
func fortigateFormLogin(ctx context.Context, client *http.Client, target *url.URL, username, password string) bool {
	if client == nil || target == nil || username == "" || password == "" {
		return false
	}
	// FortiOS accepts secretkey (current) or passwd (legacy).
	for _, passField := range []string{"secretkey", "passwd"} {
		form := url.Values{}
		form.Set("username", username)
		form.Set(passField, password)
		form.Set("ajax", "1")
		u := buildUpstreamURL(target, "/logincheck", nil)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		tuneUpstreamRequest(req, target, "/logincheck")
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("web-proxy: fortigate logincheck (%s): %v", passField, err)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if fortigateLoginOK(resp, body) {
			log.Printf("web-proxy: fortigate form login ok user=%q url=%s", username, u)
			return true
		}
		log.Printf("web-proxy: fortigate logincheck failed user=%q status=%d field=%s body=%q",
			username, resp.StatusCode, passField, truncate(string(body), 120))
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
	// ajax=1 JSON: {"retcode":0,...} or similar success marker
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
	if isFortinetKind(creds.TargetKind) {
		return false
	}
	p := strings.ToLower(strings.Split(rest, "?")[0])
	switch p {
	case "/login", "/logincheck":
		return false
	}
	if strings.HasPrefix(p, "/login/") {
		return false
	}
	return true
}

func injectFortinetLoginAssist(body []byte, creds weblaunch.SessionCreds) []byte {
	if !isFortinetKind(creds.TargetKind) || creds.PortalUsername == "" {
		return body
	}
	userJSON, _ := json.Marshal(creds.PortalUsername)
	script := []byte(`<script>(function(){try{var u=document.querySelector('input[name=username],#username,input[id*=user i]');if(u&&!u.value)u.value=` + string(userJSON) + `;}catch(e){}})();</script>`)
	if i := bytes.Index(body, []byte("</body>")); i >= 0 {
		return append(append(body[:i], script...), body[i:]...)
	}
	if i := bytes.Index(body, []byte("</head>")); i >= 0 {
		return append(append(body[:i], script...), body[i:]...)
	}
	return append(body, script...)
}
