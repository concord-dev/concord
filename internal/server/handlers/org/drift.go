package org

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

func (h *Handlers) ListDriftEvents(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	q := r.URL.Query()

	if v := q.Get("run_id"); v != "" {
		runID, err := uuid.Parse(v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "`run_id` must be a UUID")
			return
		}
		events, err := h.store.ListDriftEventsForRun(r.Context(), p.Org.ID, runID)
		if err != nil {
			httpx.Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		if events == nil {
			events = []store.DriftEvent{}
		}
		httpx.JSON(w, http.StatusOK, events)
		return
	}

	opts := store.ListDriftOptions{
		ControlID: q.Get("control_id"),
		From:      q.Get("from"),
		To:        q.Get("to"),
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			httpx.Error(w, http.StatusBadRequest, "`limit` must be a positive integer")
			return
		}
		opts.Limit = n
	}
	if v := q.Get("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "`since` must be RFC3339")
			return
		}
		opts.Since = t
	}
	if v := q.Get("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "`until` must be RFC3339")
			return
		}
		opts.Until = t
	}

	events, err := h.store.ListDriftEvents(r.Context(), p.Org.ID, opts)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []store.DriftEvent{}
	}
	httpx.JSON(w, http.StatusOK, events)
}

