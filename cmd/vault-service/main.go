// vault-service exposes credential storage and SSH cert issuance over HTTP.
// All endpoints require a valid JWT from auth-service and a role of
// "admin" or "proxy" (i.e. callers are services, not end users).
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/httpx"
	"github.com/example/pam-platform/internal/vault"
)

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("vault: db: %v", err)
	}
	defer d.Close()

	v, err := vault.New(d, config.Get("PAM_MASTER_KEY", ""))
	if err != nil {
		log.Fatalf("vault: init: %v", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /ca/pub", func(w http.ResponseWriter, r *http.Request) {
		k, err := v.PublicCAKey(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(k)
	})

	mux.HandleFunc("POST /secrets", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Name      string `json:"name"`
			Plaintext string `json:"plaintext"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if err := v.PutSecret(r.Context(), req.Name, []byte(req.Plaintext), nil); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "stored"})
	})

	mux.HandleFunc("GET /secrets", func(w http.ResponseWriter, r *http.Request) {
		out, err := v.ListSecrets(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("DELETE /secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if err := v.DeleteSecret(r.Context(), name); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})

	mux.HandleFunc("POST /ssh-cert", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Principals []string `json:"principals"`
			TTLSeconds int      `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		ttl := time.Duration(req.TTLSeconds) * time.Second
		if ttl <= 0 || ttl > 4*time.Hour {
			ttl = 30 * time.Minute
		}
		priv, cert, err := v.IssueSSHCert(req.Principals, ttl)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{
			"private_key": string(priv),
			"certificate": string(cert),
		})
	})

	addr := config.Get("PAM_VAULT_ADDR", ":8082")
	log.Printf("vault-service listening on %s", addr)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
