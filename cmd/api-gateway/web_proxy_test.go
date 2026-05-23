package main

import (
	"net/http"
	"net/url"
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

func TestRewriteUpstreamReferer(t *testing.T) {
	target, _ := url.Parse("https://192.168.48.5/")
	h := make(http.Header)
	h.Set("Referer", "http://192.168.24.253:8080/web/web-123/login?token=abc")
	rewriteUpstreamReferer(h, target, "web-123")
	got := h.Get("Referer")
	if got != "https://192.168.48.5/login?token=abc" {
		t.Fatalf("Referer=%q", got)
	}
}
