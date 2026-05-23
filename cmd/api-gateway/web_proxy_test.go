package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
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
