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

// ListDriftEvents serves GET /v1/orgs/{slug}/drift. Gated by `runs:read`
// (drift is meta on runs; we don't introduce a separate permission for it).
// Query params:
//
//	limit       1..500 (default 50)
//	since       RFC3339 inclusive
//	until       RFC3339 exclusive
//	control_id  filter to one control's history
//	from        filter on from_status (e.g. "pass")
//	to          filter on to_status   (e.g. "fail")
//	run_id      return only drift events recorded against that run
//
// Order: newest first. Use this to power the "regressions inbox" — pair
// `?from=pass&to=fail` with a since= timestamp to get exactly the
// pages-someone events for an investigator's time window.
func (h *Handlers) ListDriftEvents(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	q := r.URL.Query()

	// Per-run subview: if run_id is supplied, ignore everything else and
	// return that run's drift in chronological order. The fact-of-the-run
	// is the single most common UI query (the run detail page).
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

