package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Schedules ────────────────────────────────────────────────────────

func TestSchedule_PutGetDelete(t *testing.T) {
	h := newHarness(t)
	base := "/v1/orgs/" + h.org.Slug + "/schedule"

	// No schedule yet.
	respMiss, _ := h.do(t, "GET", base, "", h.apiToken)
	assert.Equal(t, http.StatusNotFound, respMiss.StatusCode)

	respPut, raw := h.do(t, "PUT", base, `{"cron_expr":"@hourly"}`, h.apiToken)
	require.Equal(t, http.StatusOK, respPut.StatusCode, string(raw))
	var sch struct {
		CronExpr   string    `json:"cron_expr"`
		Enabled    bool      `json:"enabled"`
		NextFireAt time.Time `json:"next_fire_at"`
	}
	require.NoError(t, json.Unmarshal(raw, &sch))
	assert.Equal(t, "@hourly", sch.CronExpr)
	assert.True(t, sch.Enabled, "PUT defaults to enabled=true")
	assert.True(t, sch.NextFireAt.After(time.Now()),
		"next_fire_at should be in the future")

	respGet, rawGet := h.do(t, "GET", base, "", h.apiToken)
	require.Equal(t, http.StatusOK, respGet.StatusCode)
	require.NoError(t, json.Unmarshal(rawGet, &sch))
	assert.Equal(t, "@hourly", sch.CronExpr)

	respDel, _ := h.do(t, "DELETE", base, "", h.apiToken)
	assert.Equal(t, http.StatusNoContent, respDel.StatusCode)
	respGet2, _ := h.do(t, "GET", base, "", h.apiToken)
	assert.Equal(t, http.StatusNotFound, respGet2.StatusCode)
}

func TestSchedule_InvalidCronReturns400(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "PUT", "/v1/orgs/"+h.org.Slug+"/schedule",
		`{"cron_expr":"not a cron"}`, h.apiToken)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "invalid cron expression")
}

func TestSchedule_DisabledFlag(t *testing.T) {
	h := newHarness(t)
	_, raw := h.do(t, "PUT", "/v1/orgs/"+h.org.Slug+"/schedule",
		`{"cron_expr":"@daily","enabled":false}`, h.apiToken)
	var sch struct {
		Enabled bool `json:"enabled"`
	}
	require.NoError(t, json.Unmarshal(raw, &sch))
	assert.False(t, sch.Enabled, "explicit enabled=false should round-trip")
}

// TestScheduler_FiresDueRunEndToEnd is the integration test: install a
// schedule whose next_fire_at is already in the past, force one scheduler
// tick, then confirm the run shows up in /v1/orgs/{slug}/runs.
func TestScheduler_FiresDueRunEndToEnd(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Backdate next_fire_at by manipulating via the store directly so the
	// scheduler picks it up on the first manual tick.
	past := time.Now().Add(-1 * time.Minute)
	_, err := h.st.UpsertSchedule(ctx, h.org.ID, "@hourly", true, past)
	require.NoError(t, err)

	// Fire one tick synchronously.
	h.c.SchedulerForTest().FireImmediately(t)

	// The org's run history should now contain one scheduler-driven run.
	require.Eventually(t, func() bool {
		resp, body := h.do(t, "GET", "/v1/orgs/"+h.org.Slug+"/runs", "", h.apiToken)
		if resp.StatusCode != http.StatusOK {
			return false
		}
		var runs []map[string]any
		_ = json.Unmarshal(body, &runs)
		return len(runs) >= 1
	}, 5*time.Second, 50*time.Millisecond, "scheduler tick should have created a run")
}
