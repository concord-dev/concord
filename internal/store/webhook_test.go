package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/store"
)


func TestCreateWebhook_GeneratesSecretWhenAbsent(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "WH", uniqueSlug("wh"))

	wh, secret, err := s.CreateWebhook(ctx, store.CreateWebhookParams{
		OrgID: org.ID, URL: "https://example.com/hook", Enabled: true,
	})
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(secret, "whsec_"))
	assert.NotEmpty(t, wh.Secret, "store row must persist the secret")
	assert.NotNil(t, wh.EventKinds)
	assert.Empty(t, wh.EventKinds, "default event_kinds is empty (= all)")
}

func TestCreateWebhook_AcceptsExplicitSecretAndKinds(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "WH", uniqueSlug("wh"))

	wh, plain, err := s.CreateWebhook(ctx, store.CreateWebhookParams{
		OrgID:      org.ID,
		URL:        "https://example.com/hook",
		Secret:     "whsec_known",
		EventKinds: []string{"run.completed", "run.failed"},
		Enabled:    true,
	})
	require.NoError(t, err)
	assert.Equal(t, "whsec_known", plain)
	assert.Equal(t, []string{"run.completed", "run.failed"}, wh.EventKinds)
}

func TestCreateWebhook_RequiresURL(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "WH", uniqueSlug("wh"))
	_, _, err := s.CreateWebhook(ctx, store.CreateWebhookParams{OrgID: org.ID})
	assert.Error(t, err)
}

func TestListEnabledWebhooks_SkipsDisabled(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "WH", uniqueSlug("wh"))
	on, _, _ := s.CreateWebhook(ctx, store.CreateWebhookParams{
		OrgID: org.ID, URL: "https://example.com/on", Enabled: true,
	})
	_, _, _ = s.CreateWebhook(ctx, store.CreateWebhookParams{
		OrgID: org.ID, URL: "https://example.com/off", Enabled: false,
	})
	got, err := s.ListEnabledWebhooks(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, on.ID, got[0].ID)
}

func TestUpdateWebhook_PatchesIndividualFields(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "WH", uniqueSlug("wh"))
	wh, _, _ := s.CreateWebhook(ctx, store.CreateWebhookParams{
		OrgID: org.ID, URL: "https://a", EventKinds: []string{"run.started"}, Enabled: true,
	})
	newURL := "https://b"
	disabled := false
	updated, err := s.UpdateWebhook(ctx, org.ID, wh.ID, store.UpdateWebhookParams{
		URL: &newURL, Enabled: &disabled,
	})
	require.NoError(t, err)
	assert.Equal(t, "https://b", updated.URL)
	assert.False(t, updated.Enabled)
	assert.Equal(t, []string{"run.started"}, updated.EventKinds,
		"un-patched fields must be preserved")
}

func TestRecordWebhookResult_PersistsStatusAndError(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	org, _ := s.CreateOrganization(ctx, "WH", uniqueSlug("wh"))
	wh, _, _ := s.CreateWebhook(ctx, store.CreateWebhookParams{
		OrgID: org.ID, URL: "https://x", Enabled: true,
	})

	require.NoError(t, s.RecordWebhookResult(ctx, wh.ID, 502, "bad gateway"))
	got, _ := s.GetWebhook(ctx, org.ID, wh.ID)
	require.NotNil(t, got.LastStatus)
	assert.Equal(t, 502, *got.LastStatus)
	assert.Equal(t, "bad gateway", got.LastError)
	require.NotNil(t, got.LastFiredAt)
}

func TestDeleteWebhook_CannotCrossOrg(t *testing.T) {
	s := openTestStore(t)
	ctx := context.Background()
	a, _ := s.CreateOrganization(ctx, "A", uniqueSlug("a"))
	b, _ := s.CreateOrganization(ctx, "B", uniqueSlug("b"))
	wh, _, _ := s.CreateWebhook(ctx, store.CreateWebhookParams{
		OrgID: a.ID, URL: "https://x", Enabled: true,
	})
	assert.ErrorIs(t, s.DeleteWebhook(ctx, b.ID, wh.ID), store.ErrNotFound)
}

