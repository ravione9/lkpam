// api-gateway is the only externally-exposed HTTP service. It:
//   - serves the embedded admin web UI at /
//   - proxies REST calls to the internal services after JWT verification
//
// In production this would be replaced with Kong/Envoy with custom plugins;
// the Go implementation here keeps the reference stack small.
package main

import (
	"embed"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/httpx"
)

//go:embed web/*
var webFS embed.FS

func main() {
	authURL := mustURL(config.Get("PAM_AUTH_URL", "http://localhost:8081"))
	vaultURL := mustURL(config.Get("PAM_VAULT_URL", "http://localhost:8082"))
	policyURL := mustURL(config.Get("PAM_POLICY_URL", "http://localhost:8083"))
	approvalURL := mustURL(config.Get("PAM_APPROVAL_URL", "http://localhost:8084"))
	auditURL := mustURL(config.Get("PAM_AUDIT_URL", "http://localhost:8085"))

	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/auth/login", proxyPath(authURL, "/login"))
	mux.HandleFunc("POST /api/auth/verify", proxyPath(authURL, "/verify"))
	mux.Handle("/api/auth/", protected(http.StripPrefix("/api/auth", reverse(authURL)), authURL))
	mux.Handle("/api/vault/", http.StripPrefix("/api/vault", protected(reverse(vaultURL), authURL)))
	mux.Handle("/api/policy/", http.StripPrefix("/api/policy", protected(reverse(policyURL), authURL)))
	mux.Handle("/api/approval/", http.StripPrefix("/api/approval", protected(reverse(approvalURL), authURL)))
	mux.Handle("/api/audit/", http.StripPrefix("/api/audit", protected(reverse(auditURL), authURL)))

	// Static UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		b, err := webFS.ReadFile("web/" + path)
		if err != nil {
			b, err = webFS.ReadFile("web/index.html")
			if err != nil {
				http.NotFound(w, r)
				return
			}
		}
		if strings.HasSuffix(path, ".html") || path == "index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		}
		w.Write(b)
	})

	addr := config.Get("PAM_GATEWAY_ADDR", ":8080")
	log.Printf("api-gateway listening on %s — open http://localhost%s/", addr, addr)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

// reverse builds a single-host reverse proxy.
func reverse(target *url.URL) http.Handler {
	return httputil.NewSingleHostReverseProxy(target)
}

// protected gates the downstream handler with JWT verification by calling
// auth-service /verify. Fast-path: if the token is missing/invalid, return
// 401 immediately. Real deployments would cache verifications.
func protected(next http.Handler, authBase *url.URL) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok, err := httpx.BearerToken(r)
		if err != nil {
			httpx.Error(w, http.StatusUnauthorized, err)
			return
		}
		// Verify with auth-service
		body := strings.NewReader(`{"Token":"` + tok + `"}`)
		req, _ := http.NewRequestWithContext(r.Context(), "POST", authBase.String()+"/verify", body)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			httpx.Error(w, http.StatusBadGateway, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			io.Copy(w, resp.Body)
			w.WriteHeader(resp.StatusCode)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		log.Fatalf("bad url %q: %v", s, err)
	}
	return u
}

// proxyPath forwards a request to target+path without stripping the gateway prefix.
func proxyPath(target *url.URL, path string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := *target
		u.Path = path
		r2 := r.Clone(r.Context())
		r2.URL = &u
		r2.Host = u.Host
		reverse(&u).ServeHTTP(w, r2)
	})
}
