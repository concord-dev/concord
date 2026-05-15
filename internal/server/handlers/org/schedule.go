package org

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/cronx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

func (h *Handlers) GetSchedule(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	sch, err := h.store.GetSchedule(r.Context(), p.Org.ID)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "no schedule configured for this org")
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, sch)
}

// PutSchedule installs or replaces an org's schedule. Body shape:
//
//	{"cron_expr": "0 */6 * * *", "enabled": true}
//
// The cron expression is validated up-front; an unparseable expression is 400,
// not 500.
func (h *Handlers) PutSchedule(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	var body struct {
		CronExpr string `json:"cron_expr"`
		Enabled  *bool  `json:"enabled,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.CronExpr == "" {
		httpx.Error(w, http.StatusBadRequest, "cron_expr is required")
		return
	}
	next, err := cronx.Next(body.CronExpr, time.Now())
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	sch, err := h.store.UpsertSchedule(r.Context(), p.Org.ID, body.CronExpr, enabled, next)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, sch)
}

func (h *Handlers) DeleteSchedule(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	if err := h.store.DeleteSchedule(r.Context(), p.Org.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			httpx.Error(w, http.StatusNotFound, "no schedule configured for this org")
			return
		}
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
