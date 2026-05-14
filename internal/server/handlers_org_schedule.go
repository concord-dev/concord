package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/concord-dev/concord/internal/store"
)

func (c *Concord) handleGetSchedule(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	sch, err := c.Store.GetSchedule(r.Context(), p.Org.ID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no schedule configured for this org")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sch)
}

// handlePutSchedule installs or replaces an org's schedule. Body shape:
//
//	{"cron_expr": "0 */6 * * *", "enabled": true}
//
// The cron expression is validated up-front; an unparseable expression is
// 400, not 500. next_fire_at is computed and persisted by the store.
func (c *Concord) handlePutSchedule(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	var body struct {
		CronExpr string `json:"cron_expr"`
		Enabled  *bool  `json:"enabled,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if body.CronExpr == "" {
		writeError(w, http.StatusBadRequest, "cron_expr is required")
		return
	}
	next, err := ValidateCronExpr(body.CronExpr, time.Now())
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	sch, err := c.Store.UpsertSchedule(r.Context(), p.Org.ID, body.CronExpr, enabled, next)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sch)
}

func (c *Concord) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	p, _ := principalFromContext(r.Context())
	if err := c.Store.DeleteSchedule(r.Context(), p.Org.ID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "no schedule configured for this org")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
