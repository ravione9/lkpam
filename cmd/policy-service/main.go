// policy-service evaluates access decisions on behalf of the SSH proxy and
// the API gateway. It is intentionally stateless; the source of truth is the
// policies table in the DB.
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/example/pam-platform/internal/approval"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/httpx"
	"github.com/example/pam-platform/internal/inventory"
	"github.com/example/pam-platform/internal/policy"
)

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("policy: db: %v", err)
	}
	defer d.Close()

	seedPolicies(d)
	ensureUserPolicies(d)

	eng := &policy.Engine{DB: d}
	inv := &inventory.Service{DB: d}
	groupSvc := &groups.Service{DB: d}
	matrix := &approval.MatrixService{DB: d}
	profile := &policy.ProfileBuilder{
		Engine: eng, Inv: inv, Groups: groupSvc, Matrix: matrix,
	}

	mux := http.NewServeMux()
	httpx.RegisterHealth(mux)

	mux.HandleFunc("GET /access-profile", func(w http.ResponseWriter, r *http.Request) {
		uidStr := r.Header.Get("X-PAM-UID")
		role := r.Header.Get("X-PAM-Role")
		uid, err := strconv.ParseInt(uidStr, 10, 64)
		if err != nil || uid <= 0 {
			httpx.Error(w, http.StatusUnauthorized, errors.New("missing caller identity"))
			return
		}
		if role == "" {
			_ = d.QueryRowContext(r.Context(), `SELECT role FROM users WHERE id=?`, uid).Scan(&role)
		}
		out, err := profile.Build(r.Context(), uid, role)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("POST /decide", func(w http.ResponseWriter, r *http.Request) {
		var in policy.Input
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		// Expand to effective roles via group memberships when only Role is set.
		if len(in.Roles) == 0 && in.UserID > 0 {
			if roles, err := groupSvc.EffectiveRoles(r.Context(), in.UserID, in.Role); err == nil {
				in.Roles = roles
			}
		}
		dec, err := eng.Decide(r.Context(), in)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, dec)
	})

	mux.HandleFunc("POST /cmd-check", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Command string   `json:"command"`
			Allow   []string `json:"allow"`
			Deny    []string `json:"deny"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]bool{
			"allowed": policy.CommandAllowed(req.Command, req.Allow, req.Deny),
		})
	})

	mux.HandleFunc("GET /policies", func(w http.ResponseWriter, r *http.Request) {
		out, err := eng.ListRules(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("POST /policies", func(w http.ResponseWriter, r *http.Request) {
		var rule policy.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		id, err := eng.CreateRule(r.Context(), rule)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusCreated, map[string]int64{"id": id})
	})

	mux.HandleFunc("PUT /policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var rule policy.Rule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		rule.ID = id
		if err := eng.UpdateRule(r.Context(), rule); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("DELETE /policies/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := eng.DeleteRule(r.Context(), id); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})

	mux.HandleFunc("GET /targets", func(w http.ResponseWriter, r *http.Request) {
		out, err := inv.List(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("POST /targets", func(w http.ResponseWriter, r *http.Request) {
		var t inventory.Target
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		id, err := inv.Create(r.Context(), t)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusCreated, map[string]int64{"id": id})
	})

	mux.HandleFunc("PUT /targets/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var t inventory.Target
		if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		t.ID = id
		if err := inv.Update(r.Context(), t); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("DELETE /targets/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := inv.Delete(r.Context(), id); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})

	addr := config.Get("PAM_POLICY_ADDR", ":8083")
	log.Printf("policy-service listening on %s", addr)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

func seedPolicies(d *db.DB) {
	var n int
	_ = d.QueryRow(`SELECT COUNT(*) FROM policies`).Scan(&n)
	if n > 0 {
		return
	}
	rows := []struct {
		role, kind   string
		tier, appr   int
		allow, deny  string
	}{
		{"admin", "*", 0, 0, "", "rm -rf /,format,erase startup-config,write erase"},
		{"netops", "cisco", 1, 1, "show,configure terminal,interface,ip,ping", "reload,erase,write erase,format,delete"},
		{"netops", "arista", 1, 1, "show,configure,interface,ip,ping", "reload,erase,write erase,format,delete"},
		{"netops", "juniper", 1, 1, "show,set,configure,ping", "request system reboot,request system zeroize"},
		{"secops", "palo", 1, 1, "show,configure,test,ping", "reboot,debug system disk-image"},
		{"secops", "forti", 1, 1, "show,get,config,ping", "execute reboot,execute factoryreset"},
		{"sysadmin", "linux", 2, 0, "sudo,systemctl,journalctl,ls,cat,grep,less,tail", "rm -rf /,mkfs,dd if=/dev"},
		{"viewer", "*", 3, 0, "show,get,cat,ls,grep,ping", "*"},
		{"user", "*", 3, 1, "show,get,cat,ls,grep,ping", "reload,erase,reboot,format,delete,rm -rf,shutdown"},
		{"user", "cisco", 2, 1, "show,ping", "configure,reload,erase,write"},
		{"user", "linux", 2, 1, "ls,cat,grep,less,tail,ping", "rm -rf,mkfs,reboot"},
		{"user", "windows", 2, 1, "", "format,shutdown"},
	}
	for _, r := range rows {
		_, err := d.Exec(`INSERT INTO policies(role,target_kind,tier_max,require_approval,allowed_commands,denied_commands)
		                  VALUES(?,?,?,?,?,?)`,
			r.role, r.kind, r.tier, r.appr, r.allow, r.deny)
		if err != nil {
			log.Printf("seed policy %s/%s: %v", r.role, r.kind, err)
		}
	}
	log.Printf("seeded %d default policies", len(rows))
}

// ensureUserPolicies backfills JIT policies for the default "user" role on existing DBs.
func ensureUserPolicies(d *db.DB) {
	var n int
	_ = d.QueryRow(`SELECT COUNT(*) FROM policies WHERE role = 'user'`).Scan(&n)
	if n > 0 {
		return
	}
	rows := []struct {
		role, kind  string
		tier, appr  int
		allow, deny string
	}{
		{"user", "*", 3, 1, "show,get,cat,ls,grep,ping", "reload,erase,reboot,format,delete,rm -rf,shutdown"},
		{"user", "cisco", 2, 1, "show,ping", "configure,reload,erase,write"},
		{"user", "linux", 2, 1, "ls,cat,grep,less,tail,ping", "rm -rf,mkfs,reboot"},
		{"user", "windows", 2, 1, "", "format,shutdown"},
	}
	for _, r := range rows {
		_, err := d.Exec(`INSERT INTO policies(role,target_kind,tier_max,require_approval,allowed_commands,denied_commands)
		                  VALUES(?,?,?,?,?,?)`,
			r.role, r.kind, r.tier, r.appr, r.allow, r.deny)
		if err != nil {
			log.Printf("ensure user policy %s/%s: %v", r.role, r.kind, err)
		}
	}
	log.Printf("backfilled default policies for role 'user'")
}
