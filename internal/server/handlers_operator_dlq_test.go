package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// ─── shared fixtures ─────────────────────────────────────────────────

// seedDeadOutboxRow enqueues an event_outbox row then forces it past the
// dispatcher's max-attempts ceiling so it qualifies as dead. Returns the
// row id.
func seedDeadOutboxRow(t *testing.T, h *harness, kind string) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	eventID := uuid.New()
	occurred := time.Now().UTC().Truncate(time.Microsecond)
	var id uuid.UUID
	err := h.c.Store.Pool().QueryRow(ctx,
		`INSERT INTO event_outbox (event_id, org_id, kind, payload, occurred_at, attempt_count, last_error, next_attempt_at)
		 VALUES ($1, $2, $3, $4::jsonb, $5, 20, 'simulated dead', now() + interval '1 hour')
		 RETURNING id`,
		eventID, h.org.ID, kind, fmt.Sprintf(`{"event_id":"%s","kind":%q}`, eventID, kind), occurred,
	).Scan(&id)
	require.NoError(t, err)
	return id
}

// seedDeadDelivery inserts a webhook + a webhook_delivery row already at
// status='dead'. Returns (deliveryID, webhookID).
func seedDeadDelivery(t *testing.T, h *harness, kind string) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	wh, _, err := h.c.Store.CreateWebhook(ctx, store.CreateWebhookParams{
		OrgID:   h.org.ID,
		URL:     "http://127.0.0.1:1", // unreachable on purpose
		Enabled: true,
	})
	require.NoError(t, err)

	var id uuid.UUID
	err = h.c.Store.Pool().QueryRow(ctx,
		`INSERT INTO webhook_delivery
		    (webhook_id, event_id, org_id, event_kind, status, attempt_count, last_http_status, last_error)
		 VALUES ($1, $2, $3, $4, 'dead', 5, 500, 'simulated dead')
		 RETURNING id`,
		wh.ID, uuid.New(), h.org.ID, kind,
	).Scan(&id)
	require.NoError(t, err)
	return id, wh.ID
}

// ─── /operator/v1/dlq/events ─────────────────────────────────────────

func TestDLQEvents_RequiresOperatorToken(t *testing.T) {
	h := newHarness(t)
	for _, path := range []string{
		"/operator/v1/dlq/events",
		"/operator/v1/dlq/events/00000000-0000-0000-0000-000000000000",
	} {
		resp, _ := h.do(t, "GET", path, "", h.apiToken)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "GET %s under api token must be 401", path)
	}
	for _, path := range []string{
		"/operator/v1/dlq/events/00000000-0000-0000-0000-000000000000/replay",
	} {
		resp, _ := h.do(t, "POST", path, "", h.apiToken)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode, "POST %s under api token must be 401", path)
	}
}

func TestDLQEvents_ListAndPaginate(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 3; i++ {
		seedDeadOutboxRow(t, h, "run.completed")
	}

	resp, raw := h.do(t, "GET", "/operator/v1/dlq/events", "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var got struct {
		Events []store.EventOutboxRow `json:"events"`
		Limit  int                    `json:"limit"`
		Offset int                    `json:"offset"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.GreaterOrEqual(t, len(got.Events), 3, "list must include all three seeded rows")
	assert.Equal(t, 50, got.Limit)
	assert.Equal(t, 0, got.Offset)

	// Pagination — limit=1 returns 1 row.
	resp, raw = h.do(t, "GET", "/operator/v1/dlq/events?limit=1", "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Len(t, got.Events, 1)
	assert.Equal(t, 1, got.Limit)
}

func TestDLQEvents_ListFiltersByKind(t *testing.T) {
	h := newHarness(t)
	seedDeadOutboxRow(t, h, "run.completed")
	seedDeadOutboxRow(t, h, "drift.detected")

	resp, raw := h.do(t, "GET", "/operator/v1/dlq/events?kind=drift.detected", "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got struct {
		Events []store.EventOutboxRow `json:"events"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	require.NotEmpty(t, got.Events)
	for _, e := range got.Events {
		assert.Equal(t, "drift.detected", e.Kind, "kind filter must exclude non-matching rows")
	}
}

func TestDLQEvents_ListRejectsBadFilters(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		q    string
		want int
	}{
		{"?limit=0", http.StatusBadRequest},
		{"?limit=999", http.StatusBadRequest},
		{"?limit=abc", http.StatusBadRequest},
		{"?offset=-1", http.StatusBadRequest},
		{"?org_id=not-a-uuid", http.StatusBadRequest},
	}
	for _, c := range cases {
		resp, _ := h.do(t, "GET", "/operator/v1/dlq/events"+c.q, "", testOperatorToken)
		assert.Equal(t, c.want, resp.StatusCode, "query %s should be %d", c.q, c.want)
	}
}

func TestDLQEvents_GetOneReturnsFullRow(t *testing.T) {
	h := newHarness(t)
	id := seedDeadOutboxRow(t, h, "run.completed")

	resp, raw := h.do(t, "GET", "/operator/v1/dlq/events/"+id.String(), "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var got store.EventOutboxRow
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, id, got.ID)
	assert.Equal(t, h.org.ID, got.OrgID)
	assert.Equal(t, "run.completed", got.Kind)
	assert.GreaterOrEqual(t, got.AttemptCount, 20)
	assert.NotNil(t, got.LastError)
	assert.Contains(t, *got.LastError, "simulated dead")
}

func TestDLQEvents_GetUnknownIs404(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do(t, "GET", "/operator/v1/dlq/events/"+uuid.NewString(), "", testOperatorToken)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestDLQEvents_ReplayResetsRowAndAudits(t *testing.T) {
	h := newHarness(t)
	id := seedDeadOutboxRow(t, h, "run.completed")

	resp, raw := h.do(t, "POST", "/operator/v1/dlq/events/"+id.String()+"/replay", "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))

	// Row should be eligible for the dispatcher again: attempt_count=0,
	// last_error NULL, next_attempt_at <= now().
	row, err := h.c.Store.GetOutboxRow(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, 0, row.AttemptCount)
	assert.Nil(t, row.LastError)
	assert.True(t, row.NextAttemptAt.Before(time.Now().Add(time.Second)),
		"next_attempt_at must be reset to now")

	// Audit row should exist.
	audited := findAuditAction(t, h, "dlq.event.replay")
	assert.NotZero(t, audited, "replay must write an audit_event row")
}

func TestDLQEvents_AbandonHidesFromDispatcher(t *testing.T) {
	h := newHarness(t)
	id := seedDeadOutboxRow(t, h, "run.completed")

	resp, _ := h.do(t, "DELETE", "/operator/v1/dlq/events/"+id.String(), "", testOperatorToken)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	row, err := h.c.Store.GetOutboxRow(context.Background(), id)
	require.NoError(t, err)
	require.NotNil(t, row.AbandonedAt, "abandoned_at must be stamped")

	// List query honours the abandoned filter.
	resp, raw := h.do(t, "GET", "/operator/v1/dlq/events", "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var got struct {
		Events []store.EventOutboxRow `json:"events"`
	}
	require.NoError(t, json.Unmarshal(raw, &got))
	for _, e := range got.Events {
		assert.NotEqual(t, id, e.ID, "abandoned row must not appear in DLQ list")
	}

	audited := findAuditAction(t, h, "dlq.event.abandon")
	assert.NotZero(t, audited)
}

func TestDLQEvents_ReplayClearsAbandonment(t *testing.T) {
	// Operators may abandon then change their mind. Replay must lift
	// the abandon flag.
	h := newHarness(t)
	id := seedDeadOutboxRow(t, h, "run.completed")

	_, _ = h.do(t, "DELETE", "/operator/v1/dlq/events/"+id.String(), "", testOperatorToken)
	row, _ := h.c.Store.GetOutboxRow(context.Background(), id)
	require.NotNil(t, row.AbandonedAt)

	resp, _ := h.do(t, "POST", "/operator/v1/dlq/events/"+id.String()+"/replay", "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	row, _ = h.c.Store.GetOutboxRow(context.Background(), id)
	assert.Nil(t, row.AbandonedAt, "replay must clear abandoned_at — letting operators undo abandon")
}

// ─── /operator/v1/dlq/deliveries ─────────────────────────────────────

func TestDLQDeliveries_ListAndReplayAndAbandon(t *testing.T) {
	h := newHarness(t)
	id, _ := seedDeadDelivery(t, h, "run.completed")

	// List
	resp, raw := h.do(t, "GET", "/operator/v1/dlq/deliveries", "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var listed struct {
		Deliveries []store.WebhookDelivery `json:"deliveries"`
	}
	require.NoError(t, json.Unmarshal(raw, &listed))
	require.NotEmpty(t, listed.Deliveries)
	found := false
	for _, d := range listed.Deliveries {
		if d.ID == id {
			found = true
			assert.Equal(t, store.DeliveryDead, d.Status)
		}
	}
	assert.True(t, found, "seeded dead delivery must be in the list")

	// Get
	resp, raw = h.do(t, "GET", "/operator/v1/dlq/deliveries/"+id.String(), "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	var got store.WebhookDelivery
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, id, got.ID)
	assert.Equal(t, store.DeliveryDead, got.Status)

	// Replay
	resp, _ = h.do(t, "POST", "/operator/v1/dlq/deliveries/"+id.String()+"/replay", "", testOperatorToken)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	d, err := h.c.Store.GetWebhookDelivery(context.Background(), id)
	require.NoError(t, err)
	assert.Equal(t, store.DeliveryFailed, d.Status, "replay must transition dead → failed")
	assert.Equal(t, 0, d.AttemptCount)
	require.NotNil(t, d.NextAttemptAt)
	assert.True(t, d.NextAttemptAt.Before(time.Now().Add(time.Second)))

	// Abandon
	resp, _ = h.do(t, "DELETE", "/operator/v1/dlq/deliveries/"+id.String(), "", testOperatorToken)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	d, _ = h.c.Store.GetWebhookDelivery(context.Background(), id)
	require.NotNil(t, d.AbandonedAt)

	// Audit
	assert.NotZero(t, findAuditAction(t, h, "dlq.delivery.replay"))
	assert.NotZero(t, findAuditAction(t, h, "dlq.delivery.abandon"))
}

// findAuditAction returns the count of audit_event rows for the given
// action — used to assert that an audited operation actually fired.
func findAuditAction(t *testing.T, h *harness, action string) int {
	t.Helper()
	var n int
	require.NoError(t, h.c.Store.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_event WHERE action = $1`, action).Scan(&n))
	return n
}
