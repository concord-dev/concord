package org

import (
	"net/http"
	"strconv"
	"time"

	"github.com/concord-dev/concord/internal/server/authctx"
	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// ListAuditEvents serves GET /v1/orgs/{slug}/audit. Gated by the audit:read
// permission (owner + admin roles). Query params:
//
//	limit   integer 1..500   (default 50)
//	since   RFC3339 timestamp (inclusive)
//	until   RFC3339 timestamp (exclusive)
//	action  exact-match filter on the action name
//
// The endpoint reads from the org-scoped index so a single-org query is
// fast even at millions of rows total.
func (h *Handlers) ListAuditEvents(w http.ResponseWriter, r *http.Request) {
	p, _ := authctx.PrincipalFrom(r.Context())
	q := r.URL.Query()

	opts := store.ListAuditOptions{Action: q.Get("action")}
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

	events, err := h.store.ListAuditEvents(r.Context(), p.Org.ID, opts)
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []store.AuditEvent{}
	}
	httpx.JSON(w, http.StatusOK, events)
}
