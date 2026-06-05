package operator

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/concord-dev/concord/internal/server/httpx"
	"github.com/concord-dev/concord/internal/store"
)


const outboxMaxAttempts = 20

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


type dlqFilters struct {
	OrgID  *uuid.UUID
	Kind   string
	Limit  int
	Offset int
}

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
