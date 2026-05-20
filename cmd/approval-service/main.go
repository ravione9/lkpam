// approval-service handles JIT access request creation and approval.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/example/pam-platform/internal/approval"
	"github.com/example/pam-platform/internal/config"
	"github.com/example/pam-platform/internal/db"
	"github.com/example/pam-platform/internal/httpx"
)

func main() {
	dsn := config.Get("PAM_DB", "file:./data/pam.db?cache=shared&_pragma=foreign_keys(1)")
	d, err := db.Open(dsn)
	if err != nil {
		log.Fatalf("approval: db: %v", err)
	}
	defer d.Close()

	svc := &approval.Service{DB: d}

	mux := http.NewServeMux()

	mux.HandleFunc("POST /requests", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID     int64  `json:"user_id"`
			TargetID   int64  `json:"target_id"`
			Reason     string `json:"reason"`
			TTLSeconds int    `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		id, err := svc.Create(r.Context(), req.UserID, req.TargetID, req.Reason, time.Duration(req.TTLSeconds)*time.Second)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err)
			return
		}
		httpx.JSON(w, http.StatusCreated, map[string]int64{"id": id})
	})

	mux.HandleFunc("POST /requests/{id}/decide", func(w http.ResponseWriter, r *http.Request) {
		idStr := r.PathValue("id")
		id, _ := strconv.ParseInt(idStr, 10, 64)
		var req struct {
			ApproverID int64 `json:"approver_id"`
			Approve    bool  `json:"approve"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		if err := svc.Decide(r.Context(), id, req.ApproverID, req.Approve); err != nil {
			httpx.Error(w, http.StatusBadRequest, err)
			return
		}
		httpx.JSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	mux.HandleFunc("GET /requests/pending", func(w http.ResponseWriter, r *http.Request) {
		out, err := svc.ListPendingEnriched(r.Context())
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

	addr := config.Get("PAM_APPROVAL_ADDR", ":8084")
	log.Printf("approval-service listening on %s", addr)
	if err := http.ListenAndServe(addr, httpx.LoggingMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}
