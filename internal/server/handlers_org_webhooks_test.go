package server_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/server"
)

// ─── Webhooks ─────────────────────────────────────────────────────────

func TestWebhooks_CreateGetListUpdateDelete(t *testing.T) {
	h := newHarness(t)
	base := "/v1/orgs/" + h.org.Slug + "/webhooks"

	// Create.
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

	// Get — secret must NOT appear.
	respG, rawG := h.do(t, "GET", base+"/"+created.Webhook.ID.String(), "", h.apiToken)
	require.Equal(t, http.StatusOK, respG.StatusCode)
	assert.NotContains(t, string(rawG), "whsec_",
		"webhook GET response must never include the secret")

	// List.
	respL, rawL := h.do(t, "GET", base, "", h.apiToken)
	require.Equal(t, http.StatusOK, respL.StatusCode)
	var list []webhookViewT
	require.NoError(t, json.Unmarshal(rawL, &list))
	require.Len(t, list, 1)

	// Update — toggle enabled to false.
	respU, _ := h.do(t, "PUT", base+"/"+created.Webhook.ID.String(),
		`{"enabled":false}`, h.apiToken)
	require.Equal(t, http.StatusOK, respU.StatusCode)
	respG2, rawG2 := h.do(t, "GET", base+"/"+created.Webhook.ID.String(), "", h.apiToken)
	require.Equal(t, http.StatusOK, respG2.StatusCode)
	var view webhookViewT
	require.NoError(t, json.Unmarshal(rawG2, &view))
	assert.False(t, view.Enabled)

	// Delete.
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

// TestWebhooks_FireOnRunDeliversSignedPayload is the integration test:
// register a webhook, run a check, prove the receiver got an HMAC-signed
// `run.completed` event whose signature verifies against the secret.
func TestWebhooks_FireOnRunDeliversSignedPayload(t *testing.T) {
	h := newHarness(t)

	type captured struct {
		Event string
		Sig   string
		Body  []byte
	}
	got := make(chan captured, 8)
	mockSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got <- captured{
			Event: r.Header.Get("X-Concord-Event"),
			Sig:   r.Header.Get("X-Concord-Signature"),
			Body:  body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(mockSink.Close)

	// Register the webhook.
	respC, rawC := h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/webhooks",
		fmt.Sprintf(`{"url":%q,"event_kinds":["run.completed"]}`, mockSink.URL),
		h.apiToken)
	require.Equal(t, http.StatusCreated, respC.StatusCode, string(rawC))
	var created struct {
		Webhook webhookViewT `json:"webhook"`
		Secret  string       `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(rawC, &created))

	// Push a run — the server broadcasts run.completed which fires the webhook.
	h.submitTestRun(t, h.apiToken, "[]")

	// Wait for the delivery — only run.completed should arrive (run.started
	// is filtered out by event_kinds).
	var c captured
	select {
	case c = <-got:
	case <-time.After(15 * time.Second):
		t.Fatal("webhook receiver never got an event")
	}
	assert.Equal(t, "run.completed", c.Event)
	assert.True(t, strings.HasPrefix(c.Sig, "sha256="),
		"X-Concord-Signature must use the sha256= prefix")

	// Verify the signature against the receiver-side helper.
	ok := server.VerifyWebhookSignature(created.Secret, c.Body, c.Sig)
	assert.True(t, ok, "signature must validate with the disclosed secret")

	// Confirm the row's last_status got recorded as 200 by the server.
	require.Eventually(t, func() bool {
		respG, raw := h.do(t, "GET",
			"/v1/orgs/"+h.org.Slug+"/webhooks/"+created.Webhook.ID.String(),
			"", h.apiToken)
		if respG.StatusCode != http.StatusOK {
			return false
		}
		var v webhookViewT
		_ = json.Unmarshal(raw, &v)
		return v.LastStatus != nil && *v.LastStatus == http.StatusOK
	}, 5*time.Second, 50*time.Millisecond,
		"webhook row should reflect a 200 last_status after successful delivery")
}

func TestWebhooks_EventKindFilterSkipsUnsubscribedKinds(t *testing.T) {
	h := newHarness(t)

	got := make(chan string, 8)
	mockSink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Header.Get("X-Concord-Event")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(mockSink.Close)

	// Subscribe ONLY to run.failed — run.completed must NOT reach the receiver.
	_, _ = h.do(t, "POST", "/v1/orgs/"+h.org.Slug+"/webhooks",
		fmt.Sprintf(`{"url":%q,"event_kinds":["run.failed"]}`, mockSink.URL),
		h.apiToken)
	h.submitTestRun(t, h.apiToken, "[]")

	select {
	case kind := <-got:
		t.Fatalf("receiver subscribed only to run.failed should not see %q", kind)
	case <-time.After(2 * time.Second):
		// expected — no delivery
	}
}

// webhookViewT is the test-side shadow of server.webhookView (unexported).
type webhookViewT struct {
	ID         uuid.UUID `json:"id"`
	URL        string    `json:"url"`
	EventKinds []string  `json:"event_kinds"`
	Enabled    bool      `json:"enabled"`
	LastStatus *int      `json:"last_status,omitempty"`
}
