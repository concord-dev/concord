package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/concord-dev/concord/internal/store"
)

// webhookHTTPClient is the single client every outbound delivery uses. A
// short total timeout protects the server: one slow receiver must never
// stall the request that triggered the broadcast.
var webhookHTTPClient = &http.Client{Timeout: 10 * time.Second}

// signPayload returns the value for the X-Concord-Signature header. The
// "sha256=" prefix matches the GitHub / Stripe convention so receivers can
// pick the algorithm from the header.
func signPayload(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature is exported for receivers (and tests) that want to
// check signatures. Uses constant-time comparison.
func VerifyWebhookSignature(secret string, body []byte, headerValue string) bool {
	want := signPayload(secret, body)
	return hmac.Equal([]byte(want), []byte(headerValue))
}

// Broadcast is the post-SubmitRun side-effect: publish run.completed on the
// in-process bus (SSE subscribers see it instantly) and fire per-org
// webhooks. Webhook delivery is detached so a slow receiver cannot stall
// the request that triggered this. Exported as a method so the org handler
// subpackage can take it as a `Broadcaster` func value.
func (c *Concord) Broadcast(run store.Run, summary []byte) {
	at := time.Now().UTC()
	if run.CompletedAt != nil {
		at = *run.CompletedAt
	}
	evt := bus.Event{
		Kind:    bus.RunCompleted,
		OrgID:   run.OrgID,
		RunID:   run.ID,
		At:      at,
		Status:  string(run.Status),
		Summary: summary,
	}
	c.bus.Publish(evt)
	c.bg.Go(func() { c.fireWebhooks(evt) })
}

// BroadcastDrift publishes a control.drifted event when SubmitRun detected
// at least one control transition. Mirrors Broadcast's shape but carries
// the per-control transition payload. No-op when transitions is empty so
// callers don't need to guard.
func (c *Concord) BroadcastDrift(run store.Run, transitions []bus.Transition) {
	if len(transitions) == 0 {
		return
	}
	at := time.Now().UTC()
	if run.CompletedAt != nil {
		at = *run.CompletedAt
	}
	evt := bus.Event{
		Kind:        bus.ControlDrifted,
		OrgID:       run.OrgID,
		RunID:       run.ID,
		At:          at,
		Transitions: transitions,
	}
	c.bus.Publish(evt)
	c.bg.Go(func() { c.fireWebhooks(evt) })
}

func (c *Concord) fireWebhooks(e bus.Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hooks, err := c.Store.ListEnabledWebhooks(ctx, e.OrgID)
	if err != nil {
		slog.Error("webhook list failed",
			slog.String("org_id", e.OrgID.String()),
			slog.String("err", err.Error()))
		return
	}
	if len(hooks) == 0 {
		return
	}
	body, err := json.Marshal(e)
	if err != nil {
		slog.Error("webhook marshal failed",
			slog.String("org_id", e.OrgID.String()),
			slog.String("err", err.Error()))
		return
	}
	for _, wh := range hooks {
		if !eventKindAllowed(wh.EventKinds, e.Kind) {
			continue
		}
		// Capture wh by value so the loop variable's reuse doesn't race
		// with the goroutine reading it. (Go 1.22+ per-iteration scoping
		// makes this defensive; keeping it explicit for readers.)
		wh := wh
		c.bg.Go(func() { c.deliverOne(wh, e.Kind, body) })
	}
}

// eventKindAllowed implements the EventKinds filter: empty list = all kinds,
// non-empty = match exact kind names.
func eventKindAllowed(allowed []string, kind bus.Kind) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, k := range allowed {
		if k == string(kind) {
			return true
		}
	}
	return false
}

// deliverOne POSTs body to wh.URL with HMAC signing + standard headers.
// Result is persisted to the webhook row so operators can see last delivery
// status.
func (c *Concord) deliverOne(wh store.Webhook, kind bus.Kind, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		_ = c.Store.RecordWebhookResult(context.Background(), wh.ID, 0, err.Error())
		c.metrics.RecordWebhookDelivery("network_error")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "concord-server/"+c.Version)
	req.Header.Set("X-Concord-Event", string(kind))
	req.Header.Set("X-Concord-Webhook-Id", wh.ID.String())
	req.Header.Set("X-Concord-Signature", signPayload(wh.Secret, body))

	resp, err := webhookHTTPClient.Do(req)
	if err != nil {
		_ = c.Store.RecordWebhookResult(context.Background(), wh.ID, 0, err.Error())
		slog.Error("webhook delivery failed",
			slog.String("webhook_id", wh.ID.String()),
			slog.String("url", wh.URL),
			slog.String("err", err.Error()))
		c.metrics.RecordWebhookDelivery("network_error")
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = c.Store.RecordWebhookResult(context.Background(), wh.ID,
			resp.StatusCode, fmt.Sprintf("non-2xx response: %d", resp.StatusCode))
		c.metrics.RecordWebhookDelivery("non_2xx")
		return
	}
	_ = c.Store.RecordWebhookResult(context.Background(), wh.ID, resp.StatusCode, "")
	c.metrics.RecordWebhookDelivery("success")
}
