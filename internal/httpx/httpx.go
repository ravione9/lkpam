// Package httpx contains small HTTP helpers shared by every service:
// JSON encode/decode, request logging, bearer-token middleware.
package httpx

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// JSON writes v as JSON with status code.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ReadJSON decodes the request body into v.
func ReadJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

// Error writes a standard error envelope.
func Error(w http.ResponseWriter, status int, err error) {
	JSON(w, status, map[string]string{"error": err.Error()})
}

// LoggingMiddleware logs every request with status and duration.
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// WebSocket upgrades must not wrap ResponseWriter — ReverseProxy needs Hijacker.
		if isWebSocketUpgrade(r) {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		log.Printf("%s %s -> %d (%s)", r.Method, r.URL.Path, rec.status, time.Since(start))
	})
}

func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Connection"), "upgrade") &&
		strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "websocket")
}

type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(c int) { r.status = c; r.ResponseWriter.WriteHeader(c) }

func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer does not support hijack")
	}
	return h.Hijack()
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// RegisterHealth adds GET /health for container orchestration probes.
func RegisterHealth(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
}

// BearerToken extracts the JWT from the Authorization header.
func BearerToken(r *http.Request) (string, error) {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return "", errors.New("missing bearer token")
	}
	return strings.TrimPrefix(h, "Bearer "), nil
}

// BearerTokenFromRequest returns a JWT from Authorization header, ?token= query,
// or the pam_web_tok cookie set when a web console iframe first authenticates.
func BearerTokenFromRequest(r *http.Request) (string, error) {
	if tok, err := BearerToken(r); err == nil {
		return tok, nil
	}
	if tok := strings.TrimSpace(r.URL.Query().Get("token")); tok != "" {
		return tok, nil
	}
	if c, err := r.Cookie("pam_web_tok"); err == nil && strings.TrimSpace(c.Value) != "" {
		return c.Value, nil
	}
	return "", errors.New("missing bearer token")
}
