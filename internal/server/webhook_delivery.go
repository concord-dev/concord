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
	"net/http"
	"os"
	"time"

	"github.com/concord-dev/concord/internal/server/bus"
	"github.com/concord-dev/concord/internal/store"
)

// webhookHTTPClient is the single client every outbound delivery uses. A
// short total timeout protects the server: one slow receiver must never
// stall the worker pipeline.
var webhookHTTPClient = &http.Client{Timeout: 10 * time.Second}

// signPayload returns the value for the X-Concord-Signature header. The
// "sha256=" prefix matches the GitHub / Stripe webhook convention so receivers
// can pick the algorithm from the header.
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

// broadcast publishes an event to in-process subscribers AND fires per-org
// webhooks. Webhook delivery runs in a detached goroutine so a slow receiver
// cannot stall the worker that's calling this.
func (c *Concord) broadcast(e bus.Event) {
	c.bus.Publish(e)
	go c.fireWebhooks(e)
}

func (c *Concord) fireWebhooks(e bus.Event) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	hooks, err := c.Store.ListEnabledWebhooks(ctx, e.OrgID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "webhooks: list for org %s: %v\n", e.OrgID, err)
		return
	}
	if len(hooks) == 0 {
		return
	}
	body, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(os.Stderr, "webhooks: marshal event: %v\n", err)
		return
	}
	for _, wh := range hooks {
		if !eventKindAllowed(wh.EventKinds, e.Kind) {
			continue
		}
		go c.deliverOne(wh, e.Kind, body)
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

// deliverOne POSTs body to wh.URL with HMAC signing + standard headers. Result
// is persisted to the webhook row so operators can see last delivery status.
func (c *Concord) deliverOne(wh store.Webhook, kind bus.Kind, body []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		_ = c.Store.RecordWebhookResult(context.Background(), wh.ID, 0, err.Error())
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
		fmt.Fprintf(os.Stderr, "webhook %s POST %s: %v\n", wh.ID, wh.URL, err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = c.Store.RecordWebhookResult(context.Background(), wh.ID,
			resp.StatusCode, fmt.Sprintf("non-2xx response: %d", resp.StatusCode))
		return
	}
	_ = c.Store.RecordWebhookResult(context.Background(), wh.ID, resp.StatusCode, "")
}
