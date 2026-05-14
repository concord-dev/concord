// Package notify provides event sinks that turn watcher state-change events
// into outgoing notifications (stderr, Slack incoming-webhook, generic JSON
// webhook). Every sink is a func(Event) so they compose via Multi.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/concord-dev/concord/internal/watcher"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Sink is the contract every notifier satisfies. It must be safe to call from
// inside the watch loop and should not block longer than the configured client
// timeout — the loop runs sequentially per iteration.
type Sink = func(watcher.Event)

// Stderr writes a one-line text representation to w. Used as the default sink
// when neither Slack nor a generic webhook is configured.
func Stderr(w io.Writer) Sink {
	return func(e watcher.Event) {
		fmt.Fprintf(w, "[%s] %s: %s → %s (%s)\n",
			e.At.Format(time.RFC3339), e.ControlID, e.From, e.To, e.Reason)
	}
}

// Multi fans out a single event to every supplied sink in order. nil sinks
// are skipped so callers can wire them conditionally.
func Multi(sinks ...Sink) Sink {
	return func(e watcher.Event) {
		for _, s := range sinks {
			if s != nil {
				s(e)
			}
		}
	}
}

// Slack posts each event as a Slack incoming-webhook message. The payload uses
// block-kit so the channel rendering shows the control id, transition, and
// reason as separate fields. Errors are written to errOut; they never block
// the watch loop.
func Slack(webhookURL string, client *http.Client, errOut io.Writer) Sink {
	if client == nil {
		client = defaultClient()
	}
	return func(e watcher.Event) {
		payload := slackPayload(e)
		raw, err := json.Marshal(payload)
		if err != nil {
			fmt.Fprintf(errOut, "slack notify: marshal: %v\n", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(raw))
		if err != nil {
			fmt.Fprintf(errOut, "slack notify: new request: %v\n", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(errOut, "slack notify: POST: %v\n", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			body, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(errOut, "slack notify: returned %d: %s\n", resp.StatusCode, string(body))
		}
	}
}

// Webhook POSTs the raw Event as JSON to url. Suitable for hooking into any
// generic alerting/SIEM/automation pipeline (PagerDuty events API, n8n,
// Tines, etc.). Each event becomes one request.
func Webhook(url string, client *http.Client, errOut io.Writer) Sink {
	if client == nil {
		client = defaultClient()
	}
	return func(e watcher.Event) {
		raw, err := json.Marshal(e)
		if err != nil {
			fmt.Fprintf(errOut, "webhook notify: marshal: %v\n", err)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
		if err != nil {
			fmt.Fprintf(errOut, "webhook notify: new request: %v\n", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "concord-watch/0.1")
		resp, err := client.Do(req)
		if err != nil {
			fmt.Fprintf(errOut, "webhook notify: POST: %v\n", err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode > 299 {
			body, _ := io.ReadAll(resp.Body)
			fmt.Fprintf(errOut, "webhook notify: returned %d: %s\n", resp.StatusCode, string(body))
		}
	}
}

// slackPayload renders an event into a minimal block-kit message. The colour
// hint is encoded in the first emoji rather than Slack's "attachments" legacy
// path, which keeps the payload aligned with the modern incoming-webhook spec.
func slackPayload(e watcher.Event) map[string]any {
	emoji := severityEmoji(e)
	header := fmt.Sprintf("%s %s — %s", emoji, e.ControlID, e.Reason)
	if e.Title != "" {
		header = fmt.Sprintf("%s %s — %s (%s)", emoji, e.ControlID, e.Reason, e.Title)
	}
	transition := fmt.Sprintf("`%s` → `%s`", nonEmpty(string(e.From), "—"), e.To)
	return map[string]any{
		"text": header,
		"blocks": []map[string]any{
			{
				"type": "section",
				"text": map[string]any{
					"type": "mrkdwn",
					"text": "*" + header + "*\n" + transition + " · " + e.At.UTC().Format(time.RFC3339),
				},
			},
		},
	}
}

func severityEmoji(e watcher.Event) string {
	switch e.Reason {
	case "regression":
		return ":rotating_light:"
	case "remediated":
		return ":white_check_mark:"
	case "evaluation error":
		return ":warning:"
	case "evaluation recovered":
		return ":arrow_up:"
	}
	switch e.To {
	case apiv1.StatusPass:
		return ":white_check_mark:"
	case apiv1.StatusFail:
		return ":rotating_light:"
	case apiv1.StatusError:
		return ":warning:"
	}
	return ":information_source:"
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func defaultClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
