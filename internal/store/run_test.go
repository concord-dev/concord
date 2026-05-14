package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// ─── Runs ──────────────────────────────────────────────────────────────

func TestRunLifecycle_PendingRunningSucceeded(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Run", uniqueSlug("run"))
	tok, _, _ := s.CreateAPIToken(ctx, org.ID, "ci", nil)

	r, err := s.CreateRun(ctx, store.CreateRunParams{OrgID: org.ID, TokenID: &tok.ID})
	require.NoError(t, err)
	assert.Equal(t, store.RunPending, r.Status)
	require.NoError(t, s.MarkRunRunning(ctx, r.ID))
	require.NoError(t, s.CompleteRun(ctx, r.ID,
		[]byte(`{"pass":3}`), []byte(`[{"id":"X"}]`)))
	final, err := s.GetRun(ctx, org.ID, r.ID)
	require.NoError(t, err)
	assert.Equal(t, store.RunSucceeded, final.Status)
	require.NotNil(t, final.TriggeredByToken)
}

func TestGetRun_CannotCrossOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateOrganization(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "B", uniqueSlug("b"))
	r, _ := s.CreateRun(ctx, store.CreateRunParams{OrgID: a.ID})
	_, err := s.GetRun(ctx, b.ID, r.ID)
	assert.ErrorIs(t, err, store.ErrNotFound)
}
