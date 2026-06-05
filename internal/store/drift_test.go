package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

func submitTwoRuns(t *testing.T, s *store.Store, orgID uuid.UUID) (uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC()

	first, err := s.SubmitRun(ctx, store.SubmitRunParams{
		OrgID: orgID, Source: store.RunSourceAgent,
		StartedAt: now.Add(-1 * time.Minute), CompletedAt: now.Add(-1 * time.Minute),
		Summary:  []byte(`{}`),
		Findings: []byte(`[{"control_id":"a","status":"pass"}]`),
	})
	require.NoError(t, err)
	second, err := s.SubmitRun(ctx, store.SubmitRunParams{
		OrgID: orgID, Source: store.RunSourceAgent,
		StartedAt: now, CompletedAt: now,
		Summary:  []byte(`{}`),
		Findings: []byte(`[{"control_id":"a","status":"fail"}]`),
	})
	require.NoError(t, err)
	return first.ID, second.ID
}

func TestGetPreviousRunFindings_HappyPath(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Drift", uniqueSlug("drift"))

	firstID, secondID := submitTwoRuns(t, s, org.ID)

	findings, priorID, err := s.GetPreviousRunFindings(ctx, org.ID, secondID)
	require.NoError(t, err)
	assert.Equal(t, firstID, priorID,
		"prior run id must be the immediately-preceding run for this org")
	var parsed []map[string]any
	require.NoError(t, json.Unmarshal(findings, &parsed),
		"prior findings must be valid JSON the detector can decode")
	require.Len(t, parsed, 1)
	assert.Equal(t, "pass", parsed[0]["status"])
	assert.Equal(t, "a", parsed[0]["control_id"])
}

func TestGetPreviousRunFindings_FirstRunReturnsNotFound(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "First", uniqueSlug("first"))
	now := time.Now().UTC()
	only, err := s.SubmitRun(ctx, store.SubmitRunParams{
		OrgID: org.ID, Source: store.RunSourceAgent,
		StartedAt: now, CompletedAt: now,
		Summary: []byte(`{}`), Findings: []byte(`[]`),
	})
	require.NoError(t, err)

	_, _, err = s.GetPreviousRunFindings(ctx, org.ID, only.ID)
	assert.ErrorIs(t, err, store.ErrNotFound,
		"a single-run org must surface ErrNotFound so the SubmitRun handler can short-circuit cleanly")
}

func TestRecordDriftEvents_AndListByOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "List", uniqueSlug("list"))
	firstID, secondID := submitTwoRuns(t, s, org.ID)

	require.NoError(t, s.RecordDriftEvents(ctx, []store.RecordDriftEventParams{
		{OrgID: org.ID, RunID: secondID, PriorRunID: &firstID,
			ControlID: "a", From: "pass", To: "fail", Rationale: "key found"},
		{OrgID: org.ID, RunID: secondID, PriorRunID: &firstID,
			ControlID: "b", From: "fail", To: "pass"},
	}))

	events, err := s.ListDriftEvents(ctx, org.ID, store.ListDriftOptions{})
	require.NoError(t, err)
	assert.Len(t, events, 2, "list must surface every recorded transition")

	regs, err := s.ListDriftEvents(ctx, org.ID, store.ListDriftOptions{From: "pass", To: "fail"})
	require.NoError(t, err)
	if assert.Len(t, regs, 1) {
		assert.Equal(t, "a", regs[0].ControlID)
		assert.Equal(t, "key found", regs[0].Rationale)
		require.NotNil(t, regs[0].PriorRunID)
		assert.Equal(t, firstID, *regs[0].PriorRunID)
	}
}

func TestRecordDriftEvents_EmptySliceIsNoOp(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Empty", uniqueSlug("empty"))

	require.NoError(t, s.RecordDriftEvents(ctx, nil))
	require.NoError(t, s.RecordDriftEvents(ctx, []store.RecordDriftEventParams{}))

	events, _ := s.ListDriftEvents(ctx, org.ID, store.ListDriftOptions{})
	assert.Empty(t, events)
}

func TestListDriftEvents_ScopesByOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateOrganization(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "B", uniqueSlug("b"))
	_, aSecond := submitTwoRuns(t, s, a.ID)

	require.NoError(t, s.RecordDriftEvents(ctx, []store.RecordDriftEventParams{
		{OrgID: a.ID, RunID: aSecond, ControlID: "a", From: "pass", To: "fail"},
	}))

	bEvents, _ := s.ListDriftEvents(ctx, b.ID, store.ListDriftOptions{})
	assert.Empty(t, bEvents, "org B must not see org A's drift")
	aEvents, _ := s.ListDriftEvents(ctx, a.ID, store.ListDriftOptions{})
	assert.Len(t, aEvents, 1)
}

func TestListDriftEventsForRun_ReturnsOnlyThatRun(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Per", uniqueSlug("per"))
	firstID, secondID := submitTwoRuns(t, s, org.ID)

	require.NoError(t, s.RecordDriftEvents(ctx, []store.RecordDriftEventParams{
		{OrgID: org.ID, RunID: secondID, PriorRunID: &firstID,
			ControlID: "a", From: "pass", To: "fail"},
	}))

	got, err := s.ListDriftEventsForRun(ctx, org.ID, secondID)
	require.NoError(t, err)
	assert.Len(t, got, 1)

	none, err := s.ListDriftEventsForRun(ctx, org.ID, firstID)
	require.NoError(t, err)
	assert.Empty(t, none, "the first run had no prior, so it must have no drift events of its own")
}
