package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// ─── Runs ──────────────────────────────────────────────────────────────

func TestSubmitRun_LandsTerminalWithAgentSource(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Run", uniqueSlug("run"))
	tok, _, _ := s.CreateAPIToken(ctx, org.ID, "ci", nil)

	now := time.Now().UTC()
	r, err := s.SubmitRun(ctx, store.SubmitRunParams{
		OrgID:        org.ID,
		TokenID:      &tok.ID,
		AgentVersion: "0.5.2",
		Source:       store.RunSourceAgent,
		StartedAt:    now.Add(-30 * time.Second),
		CompletedAt:  now,
		Summary:      []byte(`{"pass":3}`),
		Findings:     []byte(`[{"control_id":"X","status":"pass"}]`),
	})
	require.NoError(t, err)
	assert.Equal(t, store.RunSucceeded, r.Status)
	assert.Equal(t, store.RunSourceAgent, r.Source)

	full, err := s.GetRun(ctx, org.ID, r.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RunSucceeded, full.Status)
	assert.Equal(t, "0.5.2", full.AgentVersion)
	require.NotNil(t, full.TriggeredByToken)
}

func TestGetRun_CannotCrossOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateOrganization(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "B", uniqueSlug("b"))

	now := time.Now().UTC()
	r, err := s.SubmitRun(ctx, store.SubmitRunParams{
		OrgID: a.ID, Source: store.RunSourceAgent,
		StartedAt: now, CompletedAt: now,
		Summary: []byte(`{}`), Findings: []byte(`[]`),
	})
	require.NoError(t, err)

	_, err = s.GetRun(ctx, b.ID, r.ID)
	assert.ErrorIs(t, err, store.ErrNotFound)
}
