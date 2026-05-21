// vault-service exposes credential storage, SSH cert issuance, the CCP
// (Central Credential Provider) endpoint that lets applications fetch
// privileged passwords via API key, and runs the CPM (Central Policy
// Manager) background worker that rotates passwords on schedule.
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/example/pam-platform/internal/accounts"
	"github.com/example/pam-platform/internal/ccp"
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

	accountSvc := &accounts.Service{DB: d, Vault: v}
	ccpSvc := &ccp.Service{DB: d}

	// CPM rotation worker — runs every 5 minutes, rotates due accounts.
	go runCPM(accountSvc)

	mux := http.NewServeMux()
	httpx.RegisterHealth(mux)

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

	// --- RDP launcher ---
	//
	// Returns a Microsoft .rdp file pre-filled with the host, username, and
	// (optionally) tunneled credentials. The Windows client opens it directly.
	// We do NOT embed the password — instead we run `cmdkey` injection from
	// the bundled helper or fall back to the user typing it. This avoids
	// keeping plaintext on disk in the .rdp file.
	mux.HandleFunc("GET /rdp-file", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		port := r.URL.Query().Get("port")
		user := r.URL.Query().Get("username")
		name := r.URL.Query().Get("name")
		if host == "" {
			httpx.Error(w, http.StatusBadRequest, newErr("host required"))
			return
		}
		if port == "" {
			port = "3389"
		}
		if name == "" {
			name = host
		}
		// Build the .rdp file. These are line-oriented Microsoft "i:" "s:" "b:" entries.
		var b []byte
		b = append(b, []byte("screen mode id:i:2\r\n")...)
		b = append(b, []byte("use multimon:i:0\r\n")...)
		b = append(b, []byte("session bpp:i:32\r\n")...)
		b = append(b, []byte("compression:i:1\r\n")...)
		b = append(b, []byte("keyboardhook:i:2\r\n")...)
		b = append(b, []byte("audiocapturemode:i:0\r\n")...)
		b = append(b, []byte("videoplaybackmode:i:1\r\n")...)
		b = append(b, []byte("connection type:i:7\r\n")...)
		b = append(b, []byte("networkautodetect:i:1\r\n")...)
		b = append(b, []byte("bandwidthautodetect:i:1\r\n")...)
		b = append(b, []byte("displayconnectionbar:i:1\r\n")...)
		b = append(b, []byte("enableworkspacereconnect:i:0\r\n")...)
		b = append(b, []byte("disable wallpaper:i:0\r\n")...)
		b = append(b, []byte("allow font smoothing:i:1\r\n")...)
		b = append(b, []byte("allow desktop composition:i:1\r\n")...)
		b = append(b, []byte("disable full window drag:i:1\r\n")...)
		b = append(b, []byte("disable menu anims:i:1\r\n")...)
		b = append(b, []byte("disable themes:i:0\r\n")...)
		b = append(b, []byte("disable cursor setting:i:0\r\n")...)
		b = append(b, []byte("bitmapcachepersistenable:i:1\r\n")...)
		b = append(b, []byte("full address:s:"+host+":"+port+"\r\n")...)
		b = append(b, []byte("audiomode:i:0\r\n")...)
		b = append(b, []byte("redirectprinters:i:0\r\n")...)
		b = append(b, []byte("redirectcomports:i:0\r\n")...)
		b = append(b, []byte("redirectsmartcards:i:1\r\n")...)
		b = append(b, []byte("redirectclipboard:i:1\r\n")...)
		b = append(b, []byte("redirectposdevices:i:0\r\n")...)
		b = append(b, []byte("autoreconnection enabled:i:1\r\n")...)
		b = append(b, []byte("authentication level:i:2\r\n")...)
		b = append(b, []byte("prompt for credentials:i:1\r\n")...)
		b = append(b, []byte("negotiate security layer:i:1\r\n")...)
		b = append(b, []byte("remoteapplicationmode:i:0\r\n")...)
		b = append(b, []byte("alternate shell:s:\r\n")...)
		b = append(b, []byte("shell working directory:s:\r\n")...)
		b = append(b, []byte("gatewayhostname:s:\r\n")...)
		b = append(b, []byte("gatewayusagemethod:i:4\r\n")...)
		b = append(b, []byte("gatewaycredentialssource:i:4\r\n")...)
		b = append(b, []byte("gatewayprofileusagemethod:i:0\r\n")...)
		b = append(b, []byte("promptcredentialonce:i:0\r\n")...)
		b = append(b, []byte("use redirection server name:i:0\r\n")...)
		if user != "" {
			b = append(b, []byte("username:s:"+user+"\r\n")...)
		}
		w.Header().Set("Content-Type", "application/x-rdp")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.rdp"`)
		w.Write(b)
	})

	// --- Central Credential Provider (app-to-app) ---
	//
	// Apps call:
	//   GET /ccp/accounts?account=<name-or-id>
	//   X-API-Key: pam_<plaintext>
	// Returns: { "username": "...", "password": "...", "account": {...} }
	mux.HandleFunc("GET /ccp/accounts", func(w http.ResponseWriter, r *http.Request) {
		apiKey := r.Header.Get("X-API-Key")
		app, err := ccpSvc.Authenticate(r.Context(), apiKey, r.RemoteAddr)
		if err != nil {
			httpx.Error(w, http.StatusUnauthorized, err)
			return
		}
		acctQ := r.URL.Query().Get("account")
		if acctQ == "" {
			httpx.Error(w, http.StatusBadRequest,
				newErr("account query parameter required"))
			return
		}
		acct, err := lookupAccount(r.Context(), d, accountSvc, acctQ, app.SafeID)
		if err != nil {
			httpx.Error(w, http.StatusNotFound, err)
			return
		}
		if !app.AccountAllowed(acct.ID, acct.Name) {
			httpx.Error(w, http.StatusForbidden,
				newErr("account not in app allowlist"))
			return
		}
		pw, err := v.GetSecret(r.Context(), acct.SecretRef)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{
			"account_id":   acct.ID,
			"account_name": acct.Name,
			"username":     acct.Username,
			"safe":         acct.SafeName,
			"password":     string(pw),
			"app":          app.Name,
		})
	})

	addr := config.Get("PAM_VAULT_ADDR", ":8082")
	log.Printf("vault-service listening on %s", addr)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

// lookupAccount finds a privileged account by id or name, optionally scoped
// to a safe.
func lookupAccount(ctx context.Context, d *db.DB, svc *accounts.Service,
	q string, safeID *int64) (*accounts.PrivilegedAccount, error) {
	if id, err := strconv.ParseInt(q, 10, 64); err == nil {
		return svc.Get(ctx, id)
	}
	row := d.QueryRowContext(ctx,
		`SELECT id FROM privileged_accounts WHERE name = ?`+
			func() string {
				if safeID != nil {
					return ` AND safe_id = ?`
				}
				return ``
			}(),
		argList(q, safeID)...)
	var id int64
	if err := row.Scan(&id); err != nil {
		return nil, newErr("account not found")
	}
	return svc.Get(ctx, id)
}

func argList(q string, safeID *int64) []any {
	args := []any{q}
	if safeID != nil {
		args = append(args, *safeID)
	}
	return args
}

// runCPM is the Central Policy Manager loop. Every interval it asks the
// accounts service for due-for-rotation accounts and rotates them. In
// production this would also push the new password to the target via a
// platform-specific rotator plugin; for now the vault stores the new value
// and the target operator must apply it (this scaffold doesn't push to live
// devices yet).
func runCPM(svc *accounts.Service) {
	interval := config.GetDuration("PAM_CPM_INTERVAL", 5*time.Minute)
	t := time.NewTicker(interval)
	defer t.Stop()
	log.Printf("cpm: rotation worker started (interval=%s)", interval)
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		due, err := svc.Due(ctx)
		cancel()
		if err != nil {
			log.Printf("cpm: due query failed: %v", err)
			continue
		}
		if len(due) == 0 {
			continue
		}
		log.Printf("cpm: %d accounts due for rotation", len(due))
		for _, a := range due {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := svc.Rotate(ctx, a.ID, "cpm-worker"); err != nil {
				log.Printf("cpm: rotate %d (%s): %v", a.ID, a.Name, err)
			} else {
				log.Printf("cpm: rotated account %d (%s)", a.ID, a.Name)
			}
			cancel()
		}
	}
}

type strErr struct{ s string }

func (e *strErr) Error() string { return e.s }

func newErr(s string) error { return &strErr{s: s} }
