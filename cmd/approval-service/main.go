// approval-service handles JIT access request creation, the approval matrix,
// and multi-approver decision recording.
package main

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/example/pam-platform/internal/approval"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/groups"
	"github.com/example/pam-platform/internal/httpx"
)

func callerIdentity(r *http.Request) (uid int64, role string, ok bool) {
	uidStr := r.Header.Get("X-PAM-UID")
	role = r.Header.Get("X-PAM-Role")
	if uidStr == "" {
		return 0, "", false
	}
	uid, err := strconv.ParseInt(uidStr, 10, 64)
	if err != nil || uid <= 0 {
		return 0, "", false
	}
	return uid, role, true
}

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("approval: db: %v", err)
	}
	defer d.Close()

	matrix := &approval.MatrixService{DB: d}
	groupSvc := &groups.Service{DB: d}
	svc := &approval.Service{
		DB:           d,
		Matrix:       matrix,
		GroupMembers: groupSvc,
	}

	// One-time migration: backfill sudo_granted for requests that were approved
	// before the auto-grant logic existed. Without this, users who were approved
	// with sudo_requested=1 under old code would never get sudo provisioned.
	if res, err := d.Exec(`
		UPDATE access_requests
		SET sudo_granted = 1
		WHERE status = 'approved'
		  AND COALESCE(sudo_requested, 0) = 1
		  AND COALESCE(sudo_granted, 0) = 0`); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("approval: backfilled sudo_granted=1 on %d existing approved requests", n)
		}
	}

	mux := http.NewServeMux()
	httpx.RegisterHealth(mux)

	mux.HandleFunc("POST /requests", func(w http.ResponseWriter, r *http.Request) {
		uid, _, ok := callerIdentity(r)
		if !ok {
			httpx.Error(w, http.StatusUnauthorized, errors.New("missing caller identity"))
			return
		}
		var req struct {
			TargetID      int64  `json:"target_id"`
			Reason        string `json:"reason"`
			TTLSeconds    int    `json:"ttl_seconds"`
			SudoRequested bool   `json:"sudo_requested"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		id, err := svc.Create(r.Context(), uid, req.TargetID, req.Reason,
			time.Duration(req.TTLSeconds)*time.Second, req.SudoRequested)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusCreated, map[string]int64{"id": id})
	})

	mux.HandleFunc("POST /requests/{id}/decide", func(w http.ResponseWriter, r *http.Request) {
		approverID, approverRole, ok := callerIdentity(r)
		if !ok {
			httpx.Error(w, http.StatusUnauthorized, errors.New("missing caller identity"))
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var req struct {
			Approve bool   `json:"approve"`
			Comment string `json:"comment"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		res, err := svc.Decide(r.Context(), id, approverID, approverRole, req.Approve, req.Comment)
		if err != nil {
			switch {
			case errors.Is(err, approval.ErrSelfApproval),
				errors.Is(err, approval.ErrNotApprover):
				httpx.Error(w, http.StatusForbidden, err)
			case errors.Is(err, approval.ErrAlreadyDecided),
				errors.Is(err, approval.ErrRequestClosed):
				httpx.Error(w, http.StatusConflict, err)
			default:
				httpx.Error(w, http.StatusBadRequest, err)
			}
			return
		}
		httpx.JSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("POST /requests/{id}/grant-sudo", func(w http.ResponseWriter, r *http.Request) {
		_, approverRole, ok := callerIdentity(r)
		if !ok || approverRole != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin only"))
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var req struct{ Grant bool `json:"grant"` }
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if err := svc.GrantSudo(r.Context(), id, req.Grant); err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "sudo_granted": req.Grant})
	})

	mux.HandleFunc("POST /requests/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		callerID, callerRole, ok := callerIdentity(r)
		if !ok || callerRole != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin only"))
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := svc.Revoke(r.Context(), id, callerID); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("GET /requests/approved", func(w http.ResponseWriter, r *http.Request) {
		_, role, ok := callerIdentity(r)
		if !ok {
			httpx.Error(w, http.StatusUnauthorized, errors.New("missing caller identity"))
			return
		}
		if role != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin role required"))
			return
		}
		out, err := svc.ListApprovedEnriched(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("GET /requests/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		req, err := svc.Get(r.Context(), id)
		if err != nil {
			httpx.Error(w, http.StatusNotFound, err)
			return
		}
		decisions, _ := svc.ListDecisions(r.Context(), id)
		need, _ := svc.RequiredApprovals(r.Context(), id)
		httpx.JSON(w, http.StatusOK, map[string]any{
			"request":   req,
			"decisions": decisions,
			"approvals_need": need,
		})
	})

	mux.HandleFunc("GET /requests/pending", func(w http.ResponseWriter, r *http.Request) {
		_, role, ok := callerIdentity(r)
		if !ok {
			httpx.Error(w, http.StatusUnauthorized, errors.New("missing caller identity"))
			return
		}
		if role != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin role required"))
			return
		}
		out, err := svc.ListPendingEnriched(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("GET /requests/mine", func(w http.ResponseWriter, r *http.Request) {
		uid, _, ok := callerIdentity(r)
		if !ok {
			httpx.Error(w, http.StatusUnauthorized, errors.New("missing caller identity"))
			return
		}
		out, err := svc.ListMineEnriched(r.Context(), uid)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("GET /access/{userId}/{targetId}", func(w http.ResponseWriter, r *http.Request) {
		uid, _ := strconv.ParseInt(r.PathValue("userId"), 10, 64)
		tid, _ := strconv.ParseInt(r.PathValue("targetId"), 10, 64)
		ok, err := svc.IsApproved(r.Context(), uid, tid)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]bool{"approved": ok})
	})

	// --- Approval Matrix ---
	mux.HandleFunc("GET /matrix", func(w http.ResponseWriter, r *http.Request) {
		rules, err := matrix.List(r.Context())
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusOK, rules)
	})

	mux.HandleFunc("POST /matrix", func(w http.ResponseWriter, r *http.Request) {
		_, role, ok := callerIdentity(r)
		if !ok || role != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin role required"))
			return
		}
		var rule approval.MatrixRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		id, err := matrix.Create(r.Context(), rule)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusCreated, map[string]int64{"id": id})
	})

	mux.HandleFunc("PUT /matrix/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, role, ok := callerIdentity(r)
		if !ok || role != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin role required"))
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var rule approval.MatrixRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		rule.ID = id
		if err := matrix.Update(r.Context(), rule); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("DELETE /matrix/{id}", func(w http.ResponseWriter, r *http.Request) {
		_, role, ok := callerIdentity(r)
		if !ok || role != "admin" {
			httpx.Error(w, http.StatusForbidden, errors.New("admin role required"))
			return
		}
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := matrix.Delete(r.Context(), id); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})

	addr := config.Get("PAM_APPROVAL_ADDR", ":8084")
	log.Printf("approval-service listening on %s", addr)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
