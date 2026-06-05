package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)

func TestRecordAudit_PersistsRowVisibleToList(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Audit", uniqueSlug("audit"))
	u, _ := s.CreateUser(ctx, store.CreateUserParams{
		FirstName: "A", LastName: "U", Email: uniqueEmail("audit"),
	})

	s.RecordAudit(ctx, store.RecordAuditParams{
		ActorKind:   store.AuditActorUser,
		ActorUserID: &u.ID,
		OrgID:       &org.ID,
		Action:      "auth.login.success",
		TargetType:  "session",
		IP:          "127.0.0.1",
		UserAgent:   "test-agent",
		RequestID:   "req-abc",
		Details:     map[string]any{"foo": "bar"},
	})

	events, err := s.ListAuditEvents(ctx, org.ID, store.ListAuditOptions{Limit: 10})
	require.NoError(t, err)
	require.Len(t, events, 1)
	got := events[0]
	assert.Equal(t, store.AuditActorUser, got.ActorKind)
	require.NotNil(t, got.ActorUserID)
	assert.Equal(t, u.ID, *got.ActorUserID)
	assert.Equal(t, "auth.login.success", got.Action)
	assert.Equal(t, "session", got.TargetType)
	assert.Equal(t, "127.0.0.1", got.IP)
	assert.Equal(t, "test-agent", got.UserAgent)
	assert.Equal(t, "req-abc", got.RequestID)

	var details map[string]any
	require.NoError(t, json.Unmarshal(got.Details, &details))
	assert.Equal(t, "bar", details["foo"])
}

func TestListAuditEvents_ScopesByOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateOrganization(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "B", uniqueSlug("b"))

	for i := 0; i < 3; i++ {
		s.RecordAudit(ctx, store.RecordAuditParams{
			ActorKind: store.AuditActorSystem,
			OrgID:     &a.ID,
			Action:    "a-event",
		})
	}
	s.RecordAudit(ctx, store.RecordAuditParams{
		ActorKind: store.AuditActorSystem,
		OrgID:     &b.ID,
		Action:    "b-event",
	})

	eventsA, err := s.ListAuditEvents(ctx, a.ID, store.ListAuditOptions{})
	require.NoError(t, err)
	assert.Len(t, eventsA, 3, "org A must see only its own events — no cross-tenant leakage")
	for _, e := range eventsA {
		assert.Equal(t, "a-event", e.Action)
	}
}

func TestListAuditEvents_FiltersComposeAndOrderNewestFirst(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Filter", uniqueSlug("filter"))

	for _, action := range []string{"x", "y", "x"} {
		s.RecordAudit(ctx, store.RecordAuditParams{
			ActorKind: store.AuditActorSystem,
			OrgID:     &org.ID,
			Action:    action,
		})
		time.Sleep(5 * time.Millisecond) // separate occurred_at timestamps
	}

	xs, err := s.ListAuditEvents(ctx, org.ID, store.ListAuditOptions{Action: "x"})
	require.NoError(t, err)
	require.Len(t, xs, 2)
	for _, e := range xs {
		assert.Equal(t, "x", e.Action)
	}
	assert.True(t, xs[0].OccurredAt.After(xs[1].OccurredAt) ||
		xs[0].OccurredAt.Equal(xs[1].OccurredAt),
		"results must be ordered newest first")

	one, err := s.ListAuditEvents(ctx, org.ID, store.ListAuditOptions{Limit: 1})
	require.NoError(t, err)
	assert.Len(t, one, 1)
}

func TestRecordAudit_OrgDeleteCascadesEvents(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Cascade", uniqueSlug("cascade"))

	s.RecordAudit(ctx, store.RecordAuditParams{
		ActorKind: store.AuditActorSystem,
		OrgID:     &org.ID,
		Action:    "to-be-gone",
	})

	events, _ := s.ListAuditEvents(ctx, org.ID, store.ListAuditOptions{})
	require.Len(t, events, 1)

	_, err := s.Pool().Exec(ctx, `DELETE FROM organization WHERE id = $1`, org.ID)
	require.NoError(t, err)

	events, err = s.ListAuditEvents(ctx, org.ID, store.ListAuditOptions{})
	require.NoError(t, err)
	assert.Empty(t, events, "org deletion must cascade the audit trail")
}

func TestRecordAudit_MissingActionDoesNotPanic(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "Bad", uniqueSlug("bad"))

	s.RecordAudit(ctx, store.RecordAuditParams{
		ActorKind: store.AuditActorSystem,
		OrgID:     &org.ID,
	})

	events, _ := s.ListAuditEvents(ctx, org.ID, store.ListAuditOptions{})
	assert.Empty(t, events, "invalid params must not insert a row")
}
