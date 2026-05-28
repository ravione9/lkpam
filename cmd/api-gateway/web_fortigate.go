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
	"regexp"
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

// mergeUpstreamCookies forwards device session cookies to the upstream appliance.
// When preferJar is true (after server-side FortiGate login), the upstream jar
// is authoritative — stale pre-auth cookies from the browser must not win.
func mergeUpstreamCookies(upstream *http.Request, browser *http.Request, jar http.CookieJar, target *url.URL, preferJar bool) {
	if jar == nil || target == nil {
		device := stripInternalCookies(browser.Header.Get("Cookie"))
		if device != "" {
			upstream.Header.Set("Cookie", device)
		} else {
			upstream.Header.Del("Cookie")
		}
		return
	}
	u, err := url.Parse(upstream.URL.String())
	if err != nil {
		return
	}
	reqPath := u.Path
	if reqPath == "" {
		reqPath = "/"
	}
	jarCookies := jar.Cookies(u)
	if len(jarCookies) == 0 {
		jarCookies = collectJarCookies(jar, target, reqPath)
	}
	if preferJar {
		if len(jarCookies) == 0 {
			upstream.Header.Del("Cookie")
			return
		}
		parts := make([]string, 0, len(jarCookies))
		for _, c := range jarCookies {
			parts = append(parts, c.Name+"="+c.Value)
		}
		upstream.Header.Set("Cookie", strings.Join(parts, "; "))
		return
	}
	device := stripInternalCookies(browser.Header.Get("Cookie"))
	seen := map[string]bool{}
	var parts []string
	if device != "" {
		for _, p := range strings.Split(device, ";") {
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
	} else {
		upstream.Header.Del("Cookie")
	}
}

func fortiLoginCredentials(creds weblaunch.SessionCreds) (user, pass string, ok bool) {
	// Portal identity (TACACS / AD) — primary for FortiGate web admin.
	if u := strings.TrimSpace(creds.PortalUsername); u != "" {
		if p := strings.TrimSpace(creds.PortalPassword); p != "" {
			return u, p, true
		}
	}
	// Linked privileged account (local device login).
	if u := strings.TrimSpace(creds.Username); u != "" {
		if p := strings.TrimSpace(creds.Password); p != "" {
			return u, p, true
		}
	}
	return "", "", false
}

// isFortinetPreAuthRequest is true for login-page assets that must stay unauthenticated.
func isFortinetPreAuthRequest(rest string) bool {
	if isPublicWebAsset(rest) {
		return true
	}
	p := strings.ToLower(strings.Split(rest, "?")[0])
	if p == "/login" || strings.HasPrefix(p, "/login/") {
		return true
	}
	return strings.Contains(p, "logincheck")
}

// ensureFortiGateAuthenticated performs server-side /logincheck when portal or
// privileged credentials are available. FortiOS SPA API calls (/api/v2/*) return
// 401 until this runs — the browser cannot TACACS-auth through encrypted login.js.
func ensureFortiGateAuthenticated(ctx context.Context, client *http.Client, target *url.URL, creds weblaunch.SessionCreds, state *webSessionState, assetPrefix string) bool {
	if client == nil || target == nil || state == nil {
		return false
	}
	state.mu.Lock()
	if state.fortiLoginDone {
		state.mu.Unlock()
		return true
	}
	state.mu.Unlock()

	user, pass, ok := fortiLoginCredentials(creds)
	if !ok {
		return false
	}
	if !fortigateFormLogin(ctx, client, target, user, pass, "", assetPrefix) {
		return false
	}
	nJar := len(collectJarCookies(client.Jar, target, "/"))
	state.mu.Lock()
	state.fortiLoginDone = true
	state.mu.Unlock()
	log.Printf("web-proxy: fortigate session ready user=%q jar_cookies=%d", user, nJar)
	return true
}

func fortigateLogincheckPaths(assetPrefix string) []string {
	paths := []string{"/logincheck", "/login/logincheck"}
	p := strings.TrimSuffix(strings.TrimSpace(assetPrefix), "/")
	if p != "" && p != "/login" {
		paths = append(paths, p+"/logincheck")
	}
	return paths
}

// fortigateFormLogin establishes a FortiOS admin session. FortiOS 7.x needs
// POST /api/v2/authentication (session_key cookie); legacy /logincheck only
// sets APSCOOKIE which is insufficient for /api/v2/static/* (401).
func fortigateFormLogin(ctx context.Context, client *http.Client, target *url.URL, username, password, tokenCode, assetPrefix string) bool {
	if client == nil || target == nil || username == "" || password == "" {
		return false
	}
	if fortigateLoginViaAPI(ctx, client, target, username, password, tokenCode) {
		log.Printf("web-proxy: fortigate login ok via api/v2/authentication user=%q", username)
		return true
	}
	loginPass := password
	if tokenCode != "" {
		loginPass += tokenCode
	}
	extras := fortigateFetchLoginForm(ctx, client, target, assetPrefix)
	for _, checkPath := range fortigateLogincheckPaths(assetPrefix) {
		for _, passField := range []string{"secretkey", "passwd"} {
			form := url.Values{}
			for k, vs := range extras {
				if len(vs) > 0 {
					form.Set(k, vs[0])
				}
			}
			form.Set("username", username)
			form.Set(passField, loginPass)
			form.Set("ajax", "1")
			u := buildUpstreamURL(target, checkPath, nil)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Referer", buildUpstreamURL(target, "/login/", nil))
			tuneUpstreamRequest(req, target, checkPath)
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("web-proxy: fortigate logincheck (%s %s): %v", checkPath, passField, err)
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !fortigateLoginOK(resp, body) {
				log.Printf("web-proxy: fortigate logincheck failed user=%q status=%d path=%s field=%s body=%q",
					username, resp.StatusCode, checkPath, passField, truncate(string(body), 120))
				continue
			}
			log.Printf("web-proxy: fortigate logincheck accepted user=%q url=%s body=%q jar=%d",
				username, u, truncate(string(body), 80), len(collectJarCookies(client.Jar, target, "/")))
			if fortigateCompleteSession(ctx, client, target, assetPrefix, body) {
				log.Printf("web-proxy: fortigate form login ok user=%q url=%s", username, u)
				return true
			}
			log.Printf("web-proxy: fortigate logincheck body ok but session not valid user=%q", username)
		}
		// Non-ajax logincheck: FortiOS may issue session cookies on redirect to /.
		for _, passField := range []string{"secretkey", "passwd"} {
			form := url.Values{}
			for k, vs := range extras {
				if len(vs) > 0 {
					form.Set(k, vs[0])
				}
			}
			form.Set("username", username)
			form.Set(passField, loginPass)
			u := buildUpstreamURL(target, checkPath, nil)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(form.Encode()))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Referer", buildUpstreamURL(target, "/login/", nil))
			tuneUpstreamRequest(req, target, checkPath)
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if !fortigateLoginOK(resp, body) {
				continue
			}
			if fortigateCompleteSession(ctx, client, target, assetPrefix, body) {
				log.Printf("web-proxy: fortigate form login ok (redirect) user=%q url=%s", username, u)
				return true
			}
		}
	}
	return false
}

type fortigateAuthAPIResponse struct {
	StatusCode    int    `json:"status_code"`
	StatusMessage string `json:"status_message"`
}

// fortigateLoginViaAPI uses POST /api/v2/authentication (FortiOS 6.4.2+) which
// returns session_key + ccsrftoken cookies usable by the NG admin SPA. Plain
// /logincheck often leaves only APSCOOKIE_* and /api/v2/static/* returns 401.
func fortigateLoginViaAPI(ctx context.Context, client *http.Client, target *url.URL, username, password, tokenCode string) bool {
	if client == nil || target == nil {
		return false
	}
	const path = "/api/v2/authentication"
	ackPre, ackPost := true, true

	for step := 0; step < 5; step++ {
		payload := map[string]interface{}{
			"username":            username,
			"secretkey":           password,
			"ack_pre_disclaimer":  ackPre,
			"ack_post_disclaimer": ackPost,
		}
		if tokenCode != "" {
			payload["token_code"] = tokenCode
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return false
		}
		pageURL := buildUpstreamURL(target, path, nil)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, pageURL, bytes.NewReader(raw))
		if err != nil {
			return false
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		tuneUpstreamRequest(req, target, path)
		mergeUpstreamCookies(req, &http.Request{}, client.Jar, target, true)
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("web-proxy: fortigate api auth error: %v", err)
			return false
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fortigateStoreResponseCookies(client.Jar, pageURL, resp)

		if resp.StatusCode == http.StatusNotFound {
			log.Printf("web-proxy: fortigate api auth unavailable (404) — trying logincheck")
			return false
		}

		var ar fortigateAuthAPIResponse
		if err := json.Unmarshal(respBody, &ar); err != nil {
			log.Printf("web-proxy: fortigate api auth bad json status=%d body=%q", resp.StatusCode, truncate(string(respBody), 120))
			return false
		}
		log.Printf("web-proxy: fortigate api auth status_code=%d msg=%q cookies=[%s]",
			ar.StatusCode, ar.StatusMessage, fortigateJarCookieNames(client.Jar, target))

		switch ar.StatusCode {
		case 5:
			fortigatePrimeAuthenticatedSession(ctx, client, target, "")
			return fortigateValidateSession(ctx, client, target)
		case 3:
			ackPost = true
			ackPre = true
			continue
		case -2:
			ackPre = true
			continue
		case 2:
			if tokenCode != "" {
				continue
			}
			log.Printf("web-proxy: fortigate api auth requires 2FA token_code")
			return false
		case -1:
			log.Printf("web-proxy: fortigate api auth LOGIN_FAILED")
			return false
		default:
			if ar.StatusCode < 0 {
				log.Printf("web-proxy: fortigate api auth failed code=%d msg=%q", ar.StatusCode, ar.StatusMessage)
				return false
			}
		}
	}
	return false
}

var (
	fortiHiddenInputTag      = regexp.MustCompile(`(?i)<input[^>]*type\s*=\s*["']hidden["'][^>]*>`)
	fortiInputNameAttr       = regexp.MustCompile(`(?i)name\s*=\s*["']([^"']+)["']`)
	fortiInputValueAttr      = regexp.MustCompile(`(?i)value\s*=\s*["']([^"']*)["']`)
	fortiDocumentLocationRE  = regexp.MustCompile(`(?i)document\.location\s*=\s*["']([^"']+)["']`)
)

// fortigateFetchLoginForm GETs the login page and returns hidden form fields
// (csrf, reqid, etc.) FortiOS 7.x expects on /logincheck.
func fortigateFetchLoginForm(ctx context.Context, client *http.Client, target *url.URL, assetPrefix string) url.Values {
	out := url.Values{}
	if client == nil || target == nil {
		return out
	}
	paths := []string{"/login/", "/login", "/"}
	if p := strings.TrimSuffix(strings.TrimSpace(assetPrefix), "/"); p != "" && p != "/login" {
		paths = append([]string{p + "/login/", p + "/login"}, paths...)
	}
	for _, p := range paths {
		u := buildUpstreamURL(target, p, nil)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		tuneUpstreamRequest(req, target, p)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 400 || len(body) < 64 {
			continue
		}
		for _, tag := range fortiHiddenInputTag.FindAllString(string(body), -1) {
			nm := fortiInputNameAttr.FindStringSubmatch(tag)
			if len(nm) < 2 {
				continue
			}
			val := ""
			if vm := fortiInputValueAttr.FindStringSubmatch(tag); len(vm) >= 2 {
				val = vm[1]
			}
			out.Set(nm[1], val)
		}
		if len(out) > 0 || bytes.Contains(bytes.ToLower(body), []byte("logincheck")) {
			return out
		}
	}
	return out
}

func fortigateLoginOK(resp *http.Response, body []byte) bool {
	if resp == nil {
		return false
	}
	trimmed := bytes.TrimSpace(body)
	// FortiOS /logincheck: first byte is status — 1=ok, 0=fail (e.g. "1document.location=…").
	if len(trimmed) > 0 && trimmed[0] >= '0' && trimmed[0] <= '9' {
		return trimmed[0] == '1'
	}
	var m map[string]interface{}
	if json.Unmarshal(trimmed, &m) == nil {
		if rc, ok := m["retcode"].(float64); ok {
			return rc == 0
		}
		if s, ok := m["status"].(string); ok {
			return strings.EqualFold(s, "success")
		}
	}
	lower := bytes.ToLower(trimmed)
	if bytes.Contains(lower, []byte("retcode=0")) || bytes.Contains(lower, []byte(`"retcode":0`)) {
		return true
	}
	if bytes.Contains(lower, []byte("retcode=1")) || bytes.Contains(lower, []byte(`"retcode":1`)) {
		return false
	}
	if resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusSeeOther {
		loc := strings.ToLower(resp.Header.Get("Location"))
		return loc != "" && !strings.Contains(loc, "login")
	}
	return false
}

// fortigateCompleteSession follows FortiOS post-logincheck redirects (disclaimer,
// /prompt, redir target) until session cookies and ccsrftoken are established.
func fortigateCompleteSession(ctx context.Context, client *http.Client, target *url.URL, assetPrefix string, loginBody []byte) bool {
	if client == nil || target == nil {
		return false
	}
	loc := fortigateAbsPath(fortigateParseDocumentLocation(loginBody))
	log.Printf("web-proxy: fortigate logincheck redirect=%q cookies=[%s]", loc, fortigateJarCookieNames(client.Jar, target))

	disclaimerBody := fortigatePostDisclaimer(ctx, client, target)
	if next := fortigateAbsPath(fortigateParseDocumentLocation(disclaimerBody)); next != "" {
		loc = next
	}

	if strings.Contains(strings.ToLower(loc), "prompt") {
		fortigateUpstreamGET(ctx, client, target, loc)
		fortigatePostPrompt(ctx, client, target, loc)
		if u, err := url.Parse(loc); err == nil {
			if redir := strings.TrimSpace(u.Query().Get("redir")); redir != "" {
				fortigateUpstreamGET(ctx, client, target, redir)
			}
		}
	} else if loc != "" && !strings.Contains(strings.ToLower(loc), "logindisclaimer") {
		fortigateUpstreamGET(ctx, client, target, loc)
	}

	fortigatePrimeAuthenticatedSession(ctx, client, target, assetPrefix)
	return fortigateValidateSession(ctx, client, target)
}

func fortigateParseDocumentLocation(body []byte) string {
	m := fortiDocumentLocationRE.FindSubmatch(body)
	if len(m) >= 2 {
		return string(m[1])
	}
	return ""
}

func fortigateAbsPath(loc string) string {
	loc = strings.TrimSpace(loc)
	if loc == "" {
		return ""
	}
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		if u, err := url.Parse(loc); err == nil {
			if u.RawQuery != "" {
				return u.Path + "?" + u.RawQuery
			}
			return u.Path
		}
	}
	if !strings.HasPrefix(loc, "/") {
		loc = "/" + loc
	}
	return loc
}

func fortigateStoreResponseCookies(jar http.CookieJar, pageURL string, resp *http.Response) {
	if jar == nil || resp == nil || pageURL == "" {
		return
	}
	u, err := url.Parse(pageURL)
	if err != nil {
		return
	}
	jar.SetCookies(u, resp.Cookies())
}

func fortigateJarCookieNames(jar http.CookieJar, target *url.URL) string {
	cs := collectJarCookies(jar, target, "/")
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, c.Name)
	}
	return strings.Join(names, ",")
}

func fortigateUpstreamGET(ctx context.Context, client *http.Client, target *url.URL, path string) []byte {
	if client == nil || target == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	pageURL := buildUpstreamURL(target, path, nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, pageURL, nil)
	if err != nil {
		return nil
	}
	tuneUpstreamRequest(req, target, path)
	mergeUpstreamCookies(req, &http.Request{}, client.Jar, target, true)
	fortigateAttachCSRF(req, client.Jar, target)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fortigateStoreResponseCookies(client.Jar, pageURL, resp)
	log.Printf("web-proxy: fortigate GET %s status=%d cookies=[%s]", path, resp.StatusCode, fortigateJarCookieNames(client.Jar, target))
	return body
}

func fortigateUpstreamPOST(ctx context.Context, client *http.Client, target *url.URL, path string, form url.Values) []byte {
	if client == nil || target == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	pageURL := buildUpstreamURL(target, path, nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pageURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", buildUpstreamURL(target, "/", nil))
	tuneUpstreamRequest(req, target, path)
	mergeUpstreamCookies(req, &http.Request{}, client.Jar, target, true)
	fortigateAttachCSRF(req, client.Jar, target)
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fortigateStoreResponseCookies(client.Jar, pageURL, resp)
	log.Printf("web-proxy: fortigate POST %s status=%d cookies=[%s]", path, resp.StatusCode, fortigateJarCookieNames(client.Jar, target))
	return body
}

// fortigateAcceptDisclaimer confirms the post-login banner when enabled.
func fortigatePostDisclaimer(ctx context.Context, client *http.Client, target *url.URL) []byte {
	return fortigateUpstreamPOST(ctx, client, target, "/logindisclaimer", url.Values{"confirm": {"1"}})
}

func fortigatePostPrompt(ctx context.Context, client *http.Client, target *url.URL, promptPath string) {
	path := strings.TrimSpace(promptPath)
	if path == "" {
		path = "/prompt"
	}
	fortigateUpstreamPOST(ctx, client, target, path, url.Values{"confirm": {"1"}})
}

func fortigateCSRFCookie(jar http.CookieJar, target *url.URL, reqPath string) string {
	for _, c := range collectJarCookies(jar, target, reqPath) {
		lower := strings.ToLower(c.Name)
		if lower == "ccsrftoken" || lower == "csrftoken" || strings.HasPrefix(lower, "ccsrftoken") {
			return strings.Trim(c.Value, `"`)
		}
	}
	return ""
}

// fortigateAttachCSRF adds X-CSRFTOKEN required by FortiOS /api/v2/* requests.
func fortigateAttachCSRF(upstream *http.Request, jar http.CookieJar, target *url.URL) {
	if upstream == nil || jar == nil || target == nil {
		return
	}
	path := "/"
	if upstream.URL != nil && upstream.URL.Path != "" {
		path = upstream.URL.Path
	}
	if tok := fortigateCSRFCookie(jar, target, path); tok != "" {
		upstream.Header.Set("X-CSRFTOKEN", tok)
	}
	if upstream.Header.Get("Referer") == "" {
		upstream.Header.Set("Referer", buildUpstreamURL(target, "/", nil))
	}
}

func fortigateValidateSession(ctx context.Context, client *http.Client, target *url.URL) bool {
	const probe = "/api/v2/static/fweb_build.json"
	u := buildUpstreamURL(target, probe, nil)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	tuneUpstreamRequest(req, target, probe)
	mergeUpstreamCookies(req, &http.Request{}, client.Jar, target, true)
	fortigateAttachCSRF(req, client.Jar, target)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("web-proxy: fortigate session validate error: %v", err)
		return false
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	nJar := len(collectJarCookies(client.Jar, target, "/"))
	if resp.StatusCode == http.StatusOK {
		log.Printf("web-proxy: fortigate session valid jar_cookies=%d", nJar)
		return true
	}
	log.Printf("web-proxy: fortigate session invalid status=%d jar_cookies=%d cookies=[%s] csrf=%v",
		resp.StatusCode, nJar, fortigateJarCookieNames(client.Jar, target), fortigateCSRFCookie(client.Jar, target, probe) != "")
	return false
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// handleFortiPortalLogin performs FortiGate GUI login server-side via POST
// /logincheck with the portal username and password (+ optional MFA suffix).
// FortiOS browser login.js encrypts credentials client-side, which breaks TACACS
// through the proxy; plain logincheck matches "diagnose test authserver tacacs+".
func handleFortiPortalLogin(w http.ResponseWriter, r *http.Request, sessionID string, creds weblaunch.SessionCreds, target *url.URL, state *webSessionState) {
	writeFortiLoginJSON := func(status int, payload map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(payload)
	}
	if !isFortinetTarget(creds) {
		writeFortiLoginJSON(http.StatusBadRequest, map[string]string{"error": "not a FortiGate web session"})
		return
	}
	var in struct {
		MFA      string `json:"mfa"`
		Password string `json:"password"`
		Username string `json:"username"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	user := strings.TrimSpace(creds.PortalUsername)
	if u := strings.TrimSpace(in.Username); u != "" {
		user = u
	}
	pass := strings.TrimSpace(creds.PortalPassword)
	if p := strings.TrimSpace(in.Password); p != "" {
		pass = p
	}
	if user == "" || pass == "" {
		writeFortiLoginJSON(http.StatusBadRequest, map[string]string{
			"error": "username and password required — enter portal password in the Login via PAM bar",
		})
		return
	}
	mfa := digitsOnly(in.MFA)
	if mfa != "" && len(mfa) != 6 {
		writeFortiLoginJSON(http.StatusBadRequest, map[string]string{"error": "MFA must be 6 digits or left empty"})
		return
	}

	state.mu.Lock()
	assetPrefix := state.assetPrefix
	state.mu.Unlock()
	if assetPrefix == "" {
		assetPrefix = loginAssetPrefixFromTarget(creds.TargetURL)
	}

	log.Printf("web-proxy: pam-forti-login session=%s user=%q target=%s mfa=%v",
		sessionID, user, target.String(), len(mfa) == 6)
	ok := fortigateFormLogin(r.Context(), state.client, target, user, pass, mfa, assetPrefix)
	if !ok {
		writeFortiLoginJSON(http.StatusUnauthorized, map[string]string{
			"error": "FortiGate session not established — logincheck or post-login disclaimer failed. Check: docker compose logs gateway --tail 30",
		})
		return
	}
	state.mu.Lock()
	state.fortiLoginDone = true
	state.mu.Unlock()
	syncUpstreamCookiesToBrowser(w, state.client.Jar, target, sessionID)

	tok := strings.TrimSpace(r.URL.Query().Get("token"))
	if tok == "" {
		if c, err := r.Cookie("pam_web_tok"); err == nil {
			tok = strings.TrimSpace(c.Value)
		}
	}
	redirect := "/web/" + sessionID + "/"
	if tok != "" {
		redirect += "?token=" + url.QueryEscape(tok)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":       true,
		"redirect": redirect,
	})
}

func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// fortigatePrimeAuthenticatedSession GETs common post-login paths so FortiOS
// session cookies (Path=/, APSCookie, csrftoken) land in the upstream jar.
func fortigatePrimeAuthenticatedSession(ctx context.Context, client *http.Client, target *url.URL, assetPrefix string) {
	if client == nil || target == nil {
		return
	}
	paths := []string{"/", "/ng/", "/ui/", "/api/v2/static/fweb_build.json"}
	if p := strings.TrimSuffix(strings.TrimSpace(assetPrefix), "/"); p != "" && p != "/login" {
		paths = append([]string{p + "/", p + "/ng/"}, paths...)
	}
	for _, p := range paths {
		u := buildUpstreamURL(target, p, nil)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		tuneUpstreamRequest(req, target, p)
		mergeUpstreamCookies(req, &http.Request{}, client.Jar, target, true)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if strings.Contains(p, "fweb_build.json") && resp.StatusCode == http.StatusUnauthorized {
			log.Printf("web-proxy: fortigate prime %s still 401 after logincheck", p)
		} else {
			debugf("fortigate prime %s status=%d", p, resp.StatusCode)
		}
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
	body = neutralizeFortinetFrameBusters(body)
	targetURL, _ := url.Parse(creds.TargetURL)
	script := fortinetProxyBridgeScript(sessionID, creds.PortalUsername, targetURL)
	// Inject as EARLY as possible (right after <head>) so subsequent inline
	// scripts cannot navigate away before our location-setter override loads.
	if i := bytes.Index(bytes.ToLower(body), []byte("<head>")); i >= 0 {
		insert := i + len("<head>")
		out := make([]byte, 0, len(body)+len(script))
		out = append(out, body[:insert]...)
		out = append(out, script...)
		out = append(out, body[insert:]...)
		return out
	}
	if i := bytes.Index(body, []byte("<html>")); i >= 0 {
		insert := i + len("<html>")
		out := make([]byte, 0, len(body)+len(script))
		out = append(out, body[:insert]...)
		out = append(out, script...)
		out = append(out, body[insert:]...)
		return out
	}
	return append(script, body...)
}

// neutralizeFortinetFrameBusters rewrites the common FortiOS top-window escape
// patterns so they don't navigate the browser away from the PAM proxy origin.
// The bridge script also intercepts location.href setters; this is defence
// in depth in case the script tag executes before our injection.
func neutralizeFortinetFrameBusters(body []byte) []byte {
	patterns := []struct{ from, to string }{
		{"top.location", "window.location /*pam:topnav*/"},
		{"window.top.location", "window.location /*pam:topnav*/"},
		{"parent.location", "window.location /*pam:topnav*/"},
		{"self.parent.location", "window.location /*pam:topnav*/"},
	}
	for _, p := range patterns {
		body = bytes.ReplaceAll(body, []byte(p.from), []byte(p.to))
	}
	return body
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

// fortinetProxyBridgeScript builds a tiny in-page bridge that keeps the FortiGate
// UI inside the PAM proxy origin. It rewrites any URL that points to the
// upstream firewall (absolute https://<host>/…) or root-absolute appliance
// paths (/login/, /logincheck, /logout, /api/v2/, /static/, /favicon/, /assets/)
// back to /web/{sessionID}/… and intercepts every common navigation primitive:
//
//   • location.assign(u), location.replace(u)
//   • location.href = u, location = u, document.location = u
//   • window.open(u, …)
//   • <meta http-equiv="refresh" content="0;url=…">
//   • fetch / XMLHttpRequest absolute upstream URLs (so logincheck POST hits the proxy)
//
// Critically it overrides the `href` setter via Object.defineProperty on
// Location.prototype, which is what FortiOS uses to "frame-bust" out of any
// embedded viewer. Without this hook, FortiOS does `top.location.href = "https://192.168.48.5/login"`
// and the browser navigates straight to the firewall, bypassing PAM.
func fortinetProxyBridgeScript(sessionID, portalUser string, target *url.URL) []byte {
	pfx := "/web/" + sessionID
	hosts := []string{}
	if target != nil {
		hosts = targetHostVariants(target)
	}
	hostsJSON, _ := json.Marshal(hosts)
	pfxJSON, _ := json.Marshal(pfx)
	userJSON, _ := json.Marshal(portalUser)
	return []byte(`<script>(function(){
try{
  var pfx=` + string(pfxJSON) + `;
  var hosts=` + string(hostsJSON) + `;
  function startsAny(u,arr){for(var i=0;i<arr.length;i++){if(u.indexOf(arr[i])===0)return arr[i];}return "";}
  function stripHost(u){
    var schemes=["https://","http://"];
    for(var i=0;i<schemes.length;i++){
      for(var j=0;j<hosts.length;j++){
        var p=schemes[i]+hosts[j];
        if(u.indexOf(p)===0){return u.substr(p.length)||"/";}
      }
    }
    return "";
  }
  var rootPfx=["/logincheck","/logout","/login","/api/v2/","/static/","/favicon/","/assets/","/ng/","/p/","/sslvpn/"];
  function fix(u){
    if(typeof u!=="string"||!u)return u;
    if(u.indexOf(pfx)===0)return u;
    if(u.charAt(0)==="#"||u.indexOf("javascript:")===0||u.indexOf("data:")===0||u.indexOf("blob:")===0)return u;
    var rel=stripHost(u);
    if(rel){return pfx+rel;}
    if(u.charAt(0)==="/"){
      if(startsAny(u,rootPfx))return pfx+u;
      return u;
    }
    return u;
  }
  // Override location.href setter on Location.prototype so href=/=assign work
  try{
    var Lp=Location.prototype;
    var d=Object.getOwnPropertyDescriptor(Lp,"href");
    if(d&&d.set){
      Object.defineProperty(Lp,"href",{configurable:true,enumerable:true,get:d.get,set:function(v){return d.set.call(this,fix(String(v)));}});
    }
  }catch(e){}
  ["assign","replace"].forEach(function(fn){
    try{
      var o=Location.prototype[fn];if(!o)return;
      Location.prototype[fn]=function(u){return o.call(this,fix(String(u)));};
    }catch(e){}
  });
  // window.open
  try{
    var wo=window.open;
    window.open=function(u,n,f){return wo.call(this,fix(String(u||"")),n,f);};
  }catch(e){}
  // fetch
  try{
    if(window.fetch){var f=window.fetch;window.fetch=function(u,o){
      if(typeof u==="string"){u=fix(u);}
      else if(u&&u.url){u=new Request(fix(u.url),u);}
      return f.call(this,u,o);};}
  }catch(e){}
  // XHR
  try{
    var xo=XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open=function(m,u){arguments[1]=fix(String(u));return xo.apply(this,arguments);};
  }catch(e){}
  // <form action=…> normalize on submit
  document.addEventListener("submit",function(ev){
    try{var t=ev.target;if(t&&t.tagName==="FORM"&&t.action){var nu=fix(String(t.action));if(nu!==t.action)t.action=nu;}}catch(e){}
  },true);
  // <meta http-equiv="refresh" content="0;url=…">
  try{
    var metas=document.querySelectorAll('meta[http-equiv="refresh" i]');
    for(var i=0;i<metas.length;i++){
      var c=metas[i].getAttribute("content")||"";
      var m=c.match(/url\s*=\s*(.+)$/i);
      if(m){var nu=fix(m[1].trim());metas[i].setAttribute("content",c.replace(m[1],nu));}
    }
  }catch(e){}
  // Pre-fill portal username only. Do NOT set the password field — FortiOS
  // login.js encrypts the password on submit and breaks when .value is set
  // programmatically (shows "invalid password" without contacting TACACS).
  function prefillLogin(){
    var pu=` + string(userJSON) + `;
    if(!pu)return false;
    var usel=["input[name=username]","input[name=ajax_username]","#username","input[id*=user i]","input[type=text]"];
    for(var i=0;i<usel.length;i++){
      var el=document.querySelector(usel[i]);
      if(el&&!el.value){el.value=pu;return true;}
    }
    return false;
  }
  if(!prefillLogin()){
    document.addEventListener("DOMContentLoaded",prefillLogin);
    try{
      var obs=new MutationObserver(function(){if(prefillLogin())obs.disconnect();});
      obs.observe(document.documentElement,{childList:true,subtree:true});
      setTimeout(function(){obs.disconnect();},15000);
    }catch(e){}
  }
}catch(err){try{console.warn("pam-bridge init failed",err);}catch(e){}}
})();</script>`)
}
