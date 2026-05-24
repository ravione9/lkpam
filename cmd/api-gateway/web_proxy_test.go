package main

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/example/pam-platform/internal/weblaunch"
)

func TestBuildUpstreamURL(t *testing.T) {
	base, _ := url.Parse("https://192.168.48.5:443")
	cases := []struct {
		rest  string
		query url.Values
		want  string
	}{
		{"/static/styles.css", nil, "https://192.168.48.5/static/styles.css"},
		{"/static/js/login.js", url.Values{"v": []string{"1"}}, "https://192.168.48.5/static/js/login.js?v=1"},
	}
	for _, tc := range cases {
		got := buildUpstreamURL(base, tc.rest, tc.query)
		if got != tc.want {
			t.Errorf("rest=%q: got %q want %q", tc.rest, got, tc.want)
		}
	}
}

func TestBuildUpstreamURLWithBasePath(t *testing.T) {
	base, _ := url.Parse("https://fw.example.com/ui/")
	got := buildUpstreamURL(base, "/static/app.css", nil)
	want := "https://fw.example.com/ui/static/app.css"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestShouldRewriteWebPath(t *testing.T) {
	if !shouldRewriteWebPath("/static/js/login.js") {
		t.Fatal("expected js rewrite")
	}
	if !shouldRewriteWebPath("/static/css/legacy-main.css") {
		t.Fatal("expected css rewrite")
	}
	if shouldRewriteWebPath("/favicon.ico") {
		t.Fatal("ico should not rewrite body")
	}
	if shouldRewriteWebPath("/favicon/site.webmanifest") {
		t.Fatal("webmanifest must not be rewritten as HTML")
	}
	if shouldRewriteWebPath("/api/v2/cmdb/system.json") {
		t.Fatal("json API responses must not be rewritten as HTML")
	}
}

func TestShouldRewriteWebBody(t *testing.T) {
	if !shouldRewriteWebBody("text/html; charset=utf-8") {
		t.Fatal("expected html rewrite")
	}
	if shouldRewriteWebBody("application/manifest+json") {
		t.Fatal("manifest+json must pass through unchanged")
	}
	if shouldRewriteWebBody("application/json") {
		t.Fatal("json must pass through unchanged")
	}
}

func TestMimeForWebPath(t *testing.T) {
	if mimeForWebPath("/static/styles.css") != "text/css; charset=utf-8" {
		t.Fatal("css mime")
	}
	if mimeForWebPath("/static/js/login.js") != "application/javascript; charset=utf-8" {
		t.Fatal("js mime")
	}
}

func TestIsPublicWebAsset(t *testing.T) {
	if !isPublicWebAsset("/static/css/legacy-main.css") {
		t.Fatal("static css is public")
	}
	if isPublicWebAsset("/login") {
		t.Fatal("login is not public")
	}
}

func TestIsPublicWebAssetBareLoginAssets(t *testing.T) {
	// FortiOS-style login pages reference these at the device root — they must
	// be classified as public so the proxy does not attach Basic Auth (which
	// causes FortiGate to 404 the request).
	cases := map[string]bool{
		"/styles.css":              true,
		"/legacy-main.css":         true,
		"/login.js":                true,
		"/legacy_theme_setup.js":   true,
		"/site.webmanifest":        true,
		"/favicon.ico":             true,
		"/some/deep/app.css?v=2":   true,
		"/login":                   false,
		"/api/v2/cmdb/system":      false,
		"/php/utils/router.php":    false,
	}
	for p, want := range cases {
		if got := isPublicWebAsset(p); got != want {
			t.Errorf("isPublicWebAsset(%q)=%v want %v", p, got, want)
		}
	}
}

func TestRewriteHTMLPreservesUpstreamBase(t *testing.T) {
	target, _ := url.Parse("https://192.168.24.253/")
	upstream := []byte(`<!doctype html><html><head><base href="/login/"><link rel="stylesheet" href="styles.css"><script src="login.js"></script></head><body></body></html>`)
	out := rewriteHTML(upstream, target, "web-123", "", weblaunch.SessionCreds{})
	if !bytes.Contains(out, []byte(`<base href="/web/web-123/login/">`)) {
		t.Fatalf("upstream <base href=\"/login/\"> should be prefixed with /web/web-123/; got: %s", out)
	}
	if c := bytes.Count(out, []byte("<base")); c != 1 {
		t.Fatalf("expected exactly one <base> tag, got %d: %s", c, out)
	}
}

func TestRewriteHTMLInjectsBaseWhenAbsent(t *testing.T) {
	target, _ := url.Parse("https://example.com/")
	upstream := []byte(`<!doctype html><html><head><link href="/static/a.css"></head><body></body></html>`)
	out := rewriteHTML(upstream, target, "web-123", "", weblaunch.SessionCreds{})
	if !bytes.Contains(out, []byte(`<base href="/web/web-123/">`)) {
		t.Fatalf("expected injected base, got: %s", out)
	}
}

func TestContainsBaseHref(t *testing.T) {
	cases := map[string]bool{
		`<html><head><base href="/login/"></head>`:  true,
		`<HTML><HEAD><BASE HREF="/login/"></HEAD>`:  true,
		`<head><base    href='/x'></head>`:          true,
		`<head><baseLayout href="/x"></head>`:       false,
		`<head><link href="/x"></head>`:             false,
		`<head><base></head>`:                       false, // <base> without href is meaningless
		`<head><base target="_blank"></head>`:       false,
	}
	for in, want := range cases {
		if got := containsBaseHref([]byte(in)); got != want {
			t.Errorf("containsBaseHref(%q)=%v want %v", in, got, want)
		}
	}
}

func TestRewriteProxySetCookie(t *testing.T) {
	got := rewriteProxySetCookie("PHPSESSID=abc; Path=/; Secure; HttpOnly", "web-1-7")
	if strings.Contains(got, "Secure") {
		t.Fatalf("Secure should be stripped: %q", got)
	}
	if !strings.Contains(got, "Path=/web/web-1-7/") {
		t.Fatalf("Path not rewritten: %q", got)
	}
}

func TestNeedsPANAuthCheckOff(t *testing.T) {
	if !needsPANAuthCheckOff("/static/css/legacy-main.css") {
		t.Fatal("static needs authcheck off")
	}
	if !needsPANAuthCheckOff("/login") {
		t.Fatal("login needs authcheck off")
	}
	if needsPANAuthCheckOff("/php/utils/router.php") {
		t.Fatal("router should not auto-off")
	}
}

func TestUpstreamHost(t *testing.T) {
	u, _ := url.Parse("https://192.168.48.5:443")
	if upstreamHost(u) != "192.168.48.5" {
		t.Fatalf("got %q", upstreamHost(u))
	}
	u2, _ := url.Parse("https://192.168.48.5:4443")
	if upstreamHost(u2) != "192.168.48.5:4443" {
		t.Fatalf("got %q", upstreamHost(u2))
	}
}

func TestRewriteLocationNoDoublePrefix(t *testing.T) {
	target, _ := url.Parse("https://192.168.24.253/")
	cases := []struct {
		loc  string
		want string
	}{
		// Plain relative redirect — gets prefixed.
		{"/login", "/web/web-1-7/login"},
		// Absolute device URL — also prefixed.
		{"https://192.168.24.253/login?redir=/", "/web/web-1-7/login?redir=/"},
		// Already-prefixed (FortiOS echoes our redir param back as Location after
		// successful login) — must not become /web/web-1-7/web/web-1-7/…
		{"/web/web-1-7/?token=X", "/web/web-1-7/?token=X"},
		{"/web/web-1-7", "/web/web-1-7"},
		{"https://192.168.24.253/web/web-1-7/?token=X", "/web/web-1-7/?token=X"},
	}
	for _, tc := range cases {
		got := rewriteLocation(tc.loc, target, "web-1-7", "")
		if got != tc.want {
			t.Errorf("rewriteLocation(%q)=%q want %q", tc.loc, got, tc.want)
		}
	}
}

func TestRewriteUpstreamReferer(t *testing.T) {
	target, _ := url.Parse("https://192.168.48.5/")
	h := make(http.Header)
	h.Set("Referer", "http://192.168.24.253:8080/web/web-123/login?token=abc")
	rewriteUpstreamReferer(h, target, "web-123")
	got := h.Get("Referer")
	if got != "https://192.168.48.5/login" {
		t.Fatalf("Referer=%q", got)
	}
}
