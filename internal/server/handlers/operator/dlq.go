package operator

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)

// DLQ surface — Phase 4.
//
// Two dead-letter populations live behind these endpoints:
//
//   1. event_outbox rows where attempt_count >= dispatcher.MaxAttempts
//      and published_at IS NULL. These mean the Kafka producer
//      couldn't ship the event despite repeated retries.
//
//   2. webhook_delivery rows where status='dead'. These mean a specific
//      receiver was broken long enough that the retrier gave up.
//
// All routes are operator-token gated by the router and audit every
// mutating call via the Handlers.audit helper. Replay is reversible
// (it just resets the row); abandon is reversible too (replay clears
// abandoned_at). Forensic data (attempts_log, payload, last_error)
// is preserved across both transitions.

// outboxMaxAttempts is the dispatcher's MaxAttempts threshold the
// ListDeadOutbox query needs. Kept here as a small constant so the
// handler doesn't need a dependency injection just for one int; if the
// dispatcher's default ever changes we update both sites together. The
// constant is also documented in cmd/server's --outbox-max-attempts
// help text so an operator setting a non-default value can compute the
// matching DLQ threshold.
const outboxMaxAttempts = 20

// ListDLQEvents returns dead event_outbox rows, paginated. Query
// parameters: ?limit (1..500, default 50), ?offset (default 0),
// ?org_id (uuid filter), ?kind (event-kind filter).
func (h *Handlers) ListDLQEvents(w http.ResponseWriter, r *http.Request) {
	filters, ok := h.parseDLQFilters(w, r)
	if !ok {
		return
	}
	rows, err := h.store.ListDeadOutbox(r.Context(), outboxMaxAttempts, store.ListDeadOutboxFilters{
		OrgID:  filters.OrgID,
		Kind:   filters.Kind,
		Limit:  filters.Limit,
		Offset: filters.Offset,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []store.EventOutboxRow{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"events": rows,
		"limit":  filters.Limit,
		"offset": filters.Offset,
	})
}

// GetDLQEvent returns one event_outbox row, including its full payload
// and per-attempt diagnostics. 404 when the id doesn't exist.
func (h *Handlers) GetDLQEvent(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	row, err := h.store.GetOutboxRow(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "no event with id "+id.String())
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, row)
}

// ReplayDLQEvent resets a dead event_outbox row so the dispatcher
// picks it up on its next tick. 404 when the row doesn't exist or has
// already been published. The reset is audited.
func (h *Handlers) ReplayDLQEvent(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	err := h.store.ReplayOutbox(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "no replayable event with id "+id.String())
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "dlq.event.replay",
		TargetType: "event_outbox",
		TargetID:   &id,
	})
	httpx.JSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"replayed": true,
	})
}

// AbandonDLQEvent marks a dead event_outbox row so the dispatcher
// skips it on every future tick. 404 when the row doesn't exist or has
// already been published. The mutation is audited.
func (h *Handlers) AbandonDLQEvent(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	err := h.store.AbandonOutbox(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "no abandonable event with id "+id.String())
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "dlq.event.abandon",
		TargetType: "event_outbox",
		TargetID:   &id,
	})
	w.WriteHeader(http.StatusNoContent)
}

// ListDLQDeliveries returns dead webhook_delivery rows, paginated.
// Same query params as ListDLQEvents (?limit, ?offset, ?org_id, ?kind).
func (h *Handlers) ListDLQDeliveries(w http.ResponseWriter, r *http.Request) {
	filters, ok := h.parseDLQFilters(w, r)
	if !ok {
		return
	}
	rows, err := h.store.ListDeadDeliveries(r.Context(), store.ListDeadDeliveriesFilters{
		OrgID:  filters.OrgID,
		Kind:   filters.Kind,
		Limit:  filters.Limit,
		Offset: filters.Offset,
	})
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if rows == nil {
		rows = []store.WebhookDelivery{}
	}
	httpx.JSON(w, http.StatusOK, map[string]any{
		"deliveries": rows,
		"limit":      filters.Limit,
		"offset":     filters.Offset,
	})
}

// GetDLQDelivery returns one webhook_delivery row, including
// attempts_log and the most-recent error. 404 when the id doesn't
// exist.
func (h *Handlers) GetDLQDelivery(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	d, err := h.store.GetWebhookDelivery(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "no delivery with id "+id.String())
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	httpx.JSON(w, http.StatusOK, d)
}

// ReplayDLQDelivery transitions a dead webhook_delivery row back to
// 'failed' so the retrier picks it up on its next tick. The reset is
// audited.
func (h *Handlers) ReplayDLQDelivery(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	err := h.store.ReplayDelivery(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "no replayable delivery with id "+id.String())
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "dlq.delivery.replay",
		TargetType: "webhook_delivery",
		TargetID:   &id,
	})
	httpx.JSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"replayed": true,
	})
}

// AbandonDLQDelivery marks a dead webhook_delivery row so the retrier
// skips it.
func (h *Handlers) AbandonDLQDelivery(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	err := h.store.AbandonDelivery(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		httpx.Error(w, http.StatusNotFound, "no abandonable delivery with id "+id.String())
		return
	}
	if err != nil {
		httpx.Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	h.audit(r, store.RecordAuditParams{
		Action:     "dlq.delivery.abandon",
		TargetType: "webhook_delivery",
		TargetID:   &id,
	})
	w.WriteHeader(http.StatusNoContent)
}

// ─── helpers ─────────────────────────────────────────────────────────

type dlqFilters struct {
	OrgID  *uuid.UUID
	Kind   string
	Limit  int
	Offset int
}

// parseDLQFilters walks the query string + writes 400 on bad input.
// Returns (filters, true) on success or (_, false) when a response was
// already written.
func (h *Handlers) parseDLQFilters(w http.ResponseWriter, r *http.Request) (dlqFilters, bool) {
	var f dlqFilters
	q := r.URL.Query()
	if v := q.Get("org_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid org_id: "+err.Error())
			return dlqFilters{}, false
		}
		f.OrgID = &id
	}
	f.Kind = q.Get("kind")
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			httpx.Error(w, http.StatusBadRequest, "limit must be an integer in [1,500]")
			return dlqFilters{}, false
		}
		f.Limit = n
	} else {
		f.Limit = 50
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			httpx.Error(w, http.StatusBadRequest, "offset must be a non-negative integer")
			return dlqFilters{}, false
		}
		f.Offset = n
	}
	return f, true
}

// parsePathID extracts the {id} path parameter and writes 400 on
// malformed input. The router enforces the path shape so this
// function is the second line of defence (operator endpoints don't
// get to assume the parser; tools can probe the route directly).
func parsePathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	idStr := r.PathValue("id")
	if idStr == "" {
		httpx.Error(w, http.StatusBadRequest, "missing id in path")
		return uuid.Nil, false
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid id: "+err.Error())
		return uuid.Nil, false
	}
	return id, true
}
