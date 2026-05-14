package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

// ─── Schedules ────────────────────────────────────────────────────────

func TestUpsertSchedule_InsertsThenReplaces(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Sched", uniqueSlug("sched"))

	next := time.Now().Add(time.Hour).Truncate(time.Second)
	first, err := s.UpsertSchedule(ctx, org.ID, "@hourly", true, next)
	require.NoError(t, err)
	assert.Equal(t, "@hourly", first.CronExpr)
	assert.True(t, first.Enabled)

	// Replace with a different expression. Same row id.
	newNext := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	second, err := s.UpsertSchedule(ctx, org.ID, "0 9 * * *", false, newNext)
	require.NoError(t, err)
	assert.Equal(t, first.ID, second.ID, "upsert must reuse the row (UNIQUE org_id)")
	assert.Equal(t, "0 9 * * *", second.CronExpr)
	assert.False(t, second.Enabled)
}

func TestGetSchedule_NotFoundIsSentinel(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Miss", uniqueSlug("miss"))
	_, err := s.GetSchedule(ctx, org.ID)
	assert.ErrorIs(t, err, store.ErrNotFound)
}

func TestClaimDueSchedules_ReturnsOnlyDueRows(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	due, _ := s.CreateOrganization(ctx, "Due", uniqueSlug("due"))
	notDue, _ := s.CreateOrganization(ctx, "Soon", uniqueSlug("soon"))
	disabled, _ := s.CreateOrganization(ctx, "Off", uniqueSlug("off"))

	past := time.Now().Add(-1 * time.Minute)
	future := time.Now().Add(1 * time.Hour)

	_, err := s.UpsertSchedule(ctx, due.ID, "@hourly", true, past)
	require.NoError(t, err)
	_, err = s.UpsertSchedule(ctx, notDue.ID, "@hourly", true, future)
	require.NoError(t, err)
	_, err = s.UpsertSchedule(ctx, disabled.ID, "@hourly", false, past)
	require.NoError(t, err)

	now := time.Now()
	claimed, err := s.ClaimDueSchedules(ctx, now, func(expr string) (time.Time, error) {
		return now.Add(time.Hour), nil
	})
	require.NoError(t, err)

	gotIDs := map[uuid.UUID]bool{}
	for _, c := range claimed {
		gotIDs[c.OrgID] = true
	}
	assert.True(t, gotIDs[due.ID], "due, enabled schedule should be claimed")
	assert.False(t, gotIDs[notDue.ID], "future schedule must NOT be claimed")
	assert.False(t, gotIDs[disabled.ID], "disabled schedule must NOT be claimed")
}

func TestClaimDueSchedules_AdvancesNextFireAt(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Adv", uniqueSlug("adv"))
	past := time.Now().Add(-1 * time.Minute)
	_, _ = s.UpsertSchedule(ctx, org.ID, "@hourly", true, past)

	now := time.Now()
	advanced := now.Add(time.Hour)
	_, err := s.ClaimDueSchedules(ctx, now, func(expr string) (time.Time, error) {
		return advanced, nil
	})
	require.NoError(t, err)

	// After the claim, next_fire_at moved forward and last_fired_at is set.
	sch, err := s.GetSchedule(ctx, org.ID)
	require.NoError(t, err)
	require.NotNil(t, sch.LastFiredAt)
	assert.WithinDuration(t, advanced, sch.NextFireAt, time.Second,
		"next_fire_at should be set to the nextFn return value")
	assert.WithinDuration(t, now, *sch.LastFiredAt, time.Second)
}

func TestClaimDueSchedules_BadCronExpressionBumpsByHour(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Bad", uniqueSlug("bad"))
	past := time.Now().Add(-1 * time.Minute)
	_, _ = s.UpsertSchedule(ctx, org.ID, "broken expression", true, past)

	now := time.Now()
	_, err := s.ClaimDueSchedules(ctx, now, func(expr string) (time.Time, error) {
		return time.Time{}, errors.New("cannot parse")
	})
	require.NoError(t, err)
	sch, _ := s.GetSchedule(ctx, org.ID)
	assert.True(t, sch.NextFireAt.After(now.Add(50*time.Minute)),
		"broken schedules should be re-tried roughly an hour later, not on every tick")
}

func TestDeleteSchedule_RemovesRow(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Del", uniqueSlug("del"))
	_, _ = s.UpsertSchedule(ctx, org.ID, "@hourly", true, time.Now().Add(time.Hour))
	require.NoError(t, s.DeleteSchedule(ctx, org.ID))
	assert.ErrorIs(t, s.DeleteSchedule(ctx, org.ID), store.ErrNotFound)
}
