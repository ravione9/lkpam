// auth-service exposes /login and /verify. It signs short-lived JWTs that
// every other service trusts. In a real deployment this proxies to your IdP.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/example/pam-platform/internal/auth"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/events"
	"github.com/example/pam-platform/internal/httpx"
)

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("auth: open db: %v", err)
	}
	defer d.Close()

	svc := &auth.Service{
		DB:          d,
		JWTSecret:   []byte(config.Get("PAM_JWT_SECRET", "dev-only-change-me")),
		JWTTTL:      config.GetDuration("PAM_JWT_TTL", 30*time.Minute),
		JWTIssuer:   "pam-platform",
		JWTAudience: "pam-services",
	}

	bus := events.New()

	// Bootstrap: if the DB has no users, create an admin/admin user.
	bootstrap(svc)

	mux := http.NewServeMux()
	httpx.RegisterHealth(mux)

	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Username, Password, OTP string }
		if err := httpx.ReadJSON(r, &req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		u, err := svc.Authenticate(r.Context(), req.Username, req.Password)
		if err != nil {
			bus.Publish(events.Event{Source: "auth", Kind: "login.failed", Severity: "warn", Actor: req.Username})
			httpx.Error(w, http.StatusUnauthorized, err)
			return
		}
		// MFA step (stub): require OTP=="123456" if the env demands it.
		if config.Get("PAM_REQUIRE_MFA", "0") == "1" && req.OTP != config.Get("PAM_DEV_OTP", "123456") {
			httpx.Error(w, http.StatusUnauthorized, errMFAFailed)
			return
		}
		tok, err := svc.IssueToken(u)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		bus.Publish(events.Event{Source: "auth", Kind: "login.ok", Severity: "info", Actor: u.Username})
		httpx.JSON(w, http.StatusOK, map[string]any{
			"token": tok,
			"user":  u,
		})
	})

	mux.HandleFunc("POST /verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Token string }
		if err := httpx.ReadJSON(r, &req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		c, err := svc.VerifyToken(req.Token)
		if err != nil {
			httpx.Error(w, http.StatusUnauthorized, err)
			return
		}
		httpx.JSON(w, http.StatusOK, c)
	})

	mux.HandleFunc("GET /users", func(w http.ResponseWriter, r *http.Request) {
		out, err := svc.ListUsers(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("POST /users", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Email    string `json:"email"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := httpx.ReadJSON(r, &req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		id, err := svc.CreateUser(r.Context(), req.Username, req.Email, req.Password, req.Role)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusCreated, map[string]int64{"id": id})
	})

	mux.HandleFunc("PUT /users/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var in auth.UpdateUserInput
		if err := httpx.ReadJSON(r, &in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if err := svc.UpdateUser(r.Context(), id, in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	addr := config.Get("PAM_AUTH_ADDR", ":8081")
	log.Printf("auth-service listening on %s", addr)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

func bootstrap(svc *auth.Service) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var n int
	_ = svc.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	if n > 0 {
		return
	}
	adminUser := config.Get("PAM_ADMIN_USER", "admin")
	adminPass := config.Get("PAM_ADMIN_PASS", "admin")
	if _, err := svc.CreateUser(ctx, adminUser, "admin@example.com", adminPass, "admin"); err != nil {
		log.Printf("bootstrap admin failed: %v", err)
		os.Exit(1)
	}
	log.Printf("bootstrap: created initial admin user %q (please change password)", adminUser)
}

// sentinel errors
type errStr string

func (e errStr) Error() string { return string(e) }

const errMFAFailed = errStr("mfa verification failed")
