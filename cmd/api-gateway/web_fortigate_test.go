package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/example/pam-platform/internal/weblaunch"
)

func TestShouldUseBasicAuthFortiGate(t *testing.T) {
	creds := weblaunch.SessionCreds{
		Username: "admin", Password: "secret", TargetKind: "fortinet-fortigate",
	}
	r, _ := http.NewRequest(http.MethodGet, "http://x/web/sid/login", nil)
	if shouldUseBasicAuth(r, "/login", creds) {
		t.Fatal("FortiGate login must not use Basic auth")
	}
	if shouldUseBasicAuth(r, "/", creds) {
		t.Fatal("FortiGate must use form login not Basic auth")
	}
}

func TestShouldUseBasicAuthLinuxWeb(t *testing.T) {
	creds := weblaunch.SessionCreds{Username: "root", Password: "secret", TargetKind: "linux"}
	r, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	if !shouldUseBasicAuth(r, "/", creds) {
		t.Fatal("generic web target should use Basic auth on GET /")
	}
}

func TestShouldUseBasicAuthFortiGateInferredKind(t *testing.T) {
	creds := weblaunch.SessionCreds{
		Username: "admin", Password: "secret", TargetURL: "https://fortigate01.corp.local/",
	}
	r, _ := http.NewRequest(http.MethodGet, "http://x/", nil)
	if shouldUseBasicAuth(r, "/", creds) {
		t.Fatal("FortiGate inferred from URL must not use Basic auth")
	}
}

func TestFortigateLoginOKJSON(t *testing.T) {
	body := []byte(`{"retcode":0,"message":"ok"}`)
	if !fortigateLoginOK(&http.Response{StatusCode: 200}, body) {
		t.Fatal("retcode 0 should succeed")
	}
}

func TestFortigateLoginOKLegacyPrefix(t *testing.T) {
	if !fortigateLoginOK(&http.Response{StatusCode: 200}, []byte(`1document.location="/ng/"`)) {
		t.Fatal("leading 1 should succeed")
	}
	if fortigateLoginOK(&http.Response{StatusCode: 200}, []byte(`0`)) {
		t.Fatal("leading 0 should fail")
	}
}

func TestFortigateAuthAPIResponseSuccess(t *testing.T) {
	body := []byte(`{"status_code":5,"status_message":"LOGIN_SUCCESS"}`)
	var ar fortigateAuthAPIResponse
	if err := json.Unmarshal(body, &ar); err != nil {
		t.Fatal(err)
	}
	if ar.StatusCode != 5 || ar.StatusMessage != "LOGIN_SUCCESS" {
		t.Fatalf("unexpected %+v", ar)
	}
}

func TestIsFortiBuildManifestPath(t *testing.T) {
	for _, p := range []string{
		"/api/v2/static/fweb_build.json",
		"/api/v2/static/fweb_build.json?vdom=root",
		"/login/api/v2/static/fweb_build.json",
	} {
		if !isFortiBuildManifestPath(p) {
			t.Fatalf("expected match: %s", p)
		}
	}
	if isFortiBuildManifestPath("/api/v2/static/other.json") {
		t.Fatal("should not match other static files")
	}
}

func TestFortigateParseDocumentLocation(t *testing.T) {
	body := []byte(`1document.location="/prompt?viewOnly&redir=%2F";`)
	got := fortigateParseDocumentLocation(body)
	if got != "/prompt?viewOnly&redir=%2F" {
		t.Fatalf("got %q", got)
	}
	if p := fortigateAbsPath(got); p != got {
		t.Fatalf("abs path %q", p)
	}
}

func TestFortigateResponseIsLoginHTML(t *testing.T) {
	login := []byte(`<!doctype html><html><head><script src="login.js"></script></head><body><input name="username"></body></html>`)
	if !fortigateResponseIsLoginHTML(login) {
		t.Fatal("expected login HTML detection")
	}
	ng := []byte(`<!doctype html><html><head><base href="/ng/"></head><body><app-root></app-root></body></html>`)
	if fortigateResponseIsLoginHTML(ng) {
		t.Fatal("ng shell should not match login HTML")
	}
}

func TestIsFortinetSPAEntryPath(t *testing.T) {
	for _, p := range []string{"/ng/", "/ng/dashboard", "/ui/", "/"} {
		if !isFortinetSPAEntryPath(p) {
			t.Fatalf("expected SPA entry: %s", p)
		}
	}
	if isFortinetSPAEntryPath("/static/js/app.js") {
		t.Fatal("static asset is not SPA entry")
	}
}

func TestFortigateBuildStubFromStatus(t *testing.T) {
	meta := map[string]interface{}{
		"version": "v7.2.8",
		"build":   float64(1639),
		"results": map[string]interface{}{
			"version":    "v7.2.8",
			"build":      float64(1639),
			"branch":     "GA",
			"model_name": "FortiGate",
			"hostname":   "HQ_600E",
		},
	}
	raw, err := fortigateBuildStubFromStatus(meta)
	if err != nil {
		t.Fatal(err)
	}
	var stub map[string]interface{}
	if err := json.Unmarshal(raw, &stub); err != nil {
		t.Fatal(err)
	}
	if stub["version"] != "v7.2.8" {
		t.Fatalf("version=%v", stub["version"])
	}
	if stub["build"].(float64) != 1639 {
		t.Fatalf("build=%v", stub["build"])
	}
	results, ok := stub["results"].(map[string]interface{})
	if !ok {
		t.Fatalf("stub missing results: %v", stub)
	}
	if results["CONFIG_GUI_PUBLIC_PATH"] != "/ng/" {
		t.Fatalf("CONFIG_GUI_PUBLIC_PATH=%v", results["CONFIG_GUI_PUBLIC_PATH"])
	}
	if results["version"] != "v7.2.8" {
		t.Fatalf("results.version=%v", results["version"])
	}
}
