package server_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server"
)


func TestWebhooks_CreateGetListUpdateDelete(t *testing.T) {
	h := newHarness(t)
	base := "/v1/orgs/" + h.org.Slug + "/webhooks"

	respC, raw := h.do(t, "POST", base,
		`{"url":"https://hooks.example/x","event_kinds":["run.completed"]}`, h.apiToken)
	require.Equal(t, http.StatusCreated, respC.StatusCode, string(raw))
	var created struct {
		Webhook webhookViewT `json:"webhook"`
		Secret  string       `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(raw, &created))
	assert.True(t, strings.HasPrefix(created.Secret, "whsec_"),
		"secret must be returned with the whsec_ prefix at creation time")
	assert.NotEqual(t, uuid.Nil, created.Webhook.ID)

	respG, rawG := h.do(t, "GET", base+"/"+created.Webhook.ID.String(), "", h.apiToken)
	require.Equal(t, http.StatusOK, respG.StatusCode)
	assert.NotContains(t, string(rawG), "whsec_",
		"webhook GET response must never include the secret")

	respL, rawL := h.do(t, "GET", base, "", h.apiToken)
	require.Equal(t, http.StatusOK, respL.StatusCode)
	var list []webhookViewT
	require.NoError(t, json.Unmarshal(rawL, &list))
	require.Len(t, list, 1)

	respU, _ := h.do(t, "PUT", base+"/"+created.Webhook.ID.String(),
		`{"enabled":false}`, h.apiToken)
	require.Equal(t, http.StatusOK, respU.StatusCode)
	respG2, rawG2 := h.do(t, "GET", base+"/"+created.Webhook.ID.String(), "", h.apiToken)
	require.Equal(t, http.StatusOK, respG2.StatusCode)
	var view webhookViewT
	require.NoError(t, json.Unmarshal(rawG2, &view))
	assert.False(t, view.Enabled)

	respD, _ := h.do(t, "DELETE", base+"/"+created.Webhook.ID.String(), "", h.apiToken)
	assert.Equal(t, http.StatusNoContent, respD.StatusCode)
	respG3, _ := h.do(t, "GET", base+"/"+created.Webhook.ID.String(), "", h.apiToken)
	assert.Equal(t, http.StatusNotFound, respG3.StatusCode)
}

func TestWebhooks_RejectsNonHTTPURL(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/webhooks",
		`{"url":"ftp://nope"}`, h.apiToken)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "http://")
}

func TestWebhooks_SignatureRoundTrip(t *testing.T) {
	body := []byte(`{"version":1,"kind":"run.completed"}`)
	secret := "whsec_test_round_trip"

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	assert.True(t, server.VerifyWebhookSignature(secret, body, sig),
		"server-side Verify must accept a worker-side signature")
	assert.False(t, server.VerifyWebhookSignature(secret+"x", body, sig),
		"wrong secret must fail validation")
	assert.False(t, server.VerifyWebhookSignature(secret, append(body, 'x'), sig),
		"tampered body must fail validation")
}

func TestSubmitRun_EnqueuesOutboxEvent(t *testing.T) {
	h := newHarness(t)
	h.submitTestRun(t, h.apiToken, "[]")

	require.Eventually(t, func() bool {
		var count int
		_ = h.c.Store.Pool().QueryRow(t.Context(),
			`SELECT count(*) FROM event_outbox WHERE org_id = $1 AND kind = 'run.completed'`,
			h.org.ID).Scan(&count)
		return count == 1
	}, 5*time.Second, 50*time.Millisecond,
		"SubmitRun must enqueue exactly one run.completed event in the outbox")
}

type webhookViewT struct {
	ID         uuid.UUID `json:"id"`
	URL        string    `json:"url"`
	EventKinds []string  `json:"event_kinds"`
	Enabled    bool      `json:"enabled"`
	LastStatus *int      `json:"last_status,omitempty"`
}
