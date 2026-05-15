package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/report"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// pushOpts is the agent-push surface shared by `concord push` and the
// --push-to flag on `check` / `watch`. Kept in one place so a future change
// (signing scheme, retry policy, etc.) only edits one struct.
type pushOpts struct {
	serverURL  string
	orgSlug    string
	token      string
	keyID      string // optional — UUID of the registered agent_key
	keyPath    string // optional — path to the Ed25519 private key on disk
	agentLabel string // free-form, lands in agent_version
}

func newPushCmd() *cobra.Command {
	var (
		findingsPath string
		opts         pushOpts
	)
	cmd := &cobra.Command{
		Use:   "push",
		Short: "Submit a completed findings file to a Concord server",
		Long: `push uploads a findings.json produced by "concord check --output" to a
Concord server. Use it from CI / cron / wherever your scans run, when you'd
rather keep credentials on your side and let Concord only see results.

Sign the submission by passing --key-id + --key (the agent_key UUID and the
private-key file from "concord keygen"). Without those, the upload still
succeeds — the server records it as source=unsigned.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if findingsPath == "" {
				return errors.New("--findings is required")
			}
			raw, err := os.ReadFile(findingsPath)
			if err != nil {
				return fmt.Errorf("reading %s: %w", findingsPath, err)
			}
			var findings []apiv1.Finding
			if err := json.Unmarshal(raw, &findings); err != nil {
				return fmt.Errorf("parsing findings JSON: %w", err)
			}
			return pushFindings(cmd.Context(), opts, findings, time.Now().UTC(), time.Now().UTC())
		},
	}
	cmd.Flags().StringVar(&findingsPath, "findings", "", "Path to a findings JSON (produced by `concord check --output ... --format json`)")
	addPushFlags(cmd, &opts)
	return cmd
}

// addPushFlags wires the --to / --org-slug / --token / --key-id / --key
// flags onto cmd. Reused by `push`, `check --push-to`, and `watch --push-to`.
func addPushFlags(cmd *cobra.Command, opts *pushOpts) {
	cmd.Flags().StringVar(&opts.serverURL, "to", os.Getenv("CONCORD_SERVER_URL"), "Concord server base URL (or CONCORD_SERVER_URL)")
	cmd.Flags().StringVar(&opts.orgSlug, "org-slug", os.Getenv("CONCORD_ORG_SLUG"), "Organization slug (or CONCORD_ORG_SLUG)")
	cmd.Flags().StringVar(&opts.token, "token", os.Getenv("CONCORD_API_TOKEN"), "API token (or CONCORD_API_TOKEN)")
	cmd.Flags().StringVar(&opts.keyID, "key-id", os.Getenv("CONCORD_AGENT_KEY_ID"), "UUID of a registered agent_key (enables signing)")
	cmd.Flags().StringVar(&opts.keyPath, "key", os.Getenv("CONCORD_AGENT_KEY_PATH"), "Path to the Ed25519 private key from `concord keygen`")
	cmd.Flags().StringVar(&opts.agentLabel, "agent-label", "", "Optional agent identifier recorded on the run (e.g. CI job name)")
}

// pushFindings POSTs a complete agent submission. summary is recomputed
// server-side from findings; we send it for fidelity in case the policy
// engine ever introduces non-summable fields.
func pushFindings(ctx context.Context, opts pushOpts, findings []apiv1.Finding, startedAt, completedAt time.Time) error {
	if err := opts.validate(); err != nil {
		return err
	}
	if findings == nil {
		findings = []apiv1.Finding{}
	}
	summary := report.Summarize(findings)

	body, err := json.Marshal(map[string]any{
		"agent": map[string]string{
			"version": agentVersion(opts.agentLabel),
		},
		"started_at":   startedAt.UTC(),
		"completed_at": completedAt.UTC(),
		"summary":      summary,
		"findings":     findings,
	})
	if err != nil {
		return fmt.Errorf("encoding submission: %w", err)
	}

	url := strings.TrimRight(opts.serverURL, "/") + "/v1/orgs/" + opts.orgSlug + "/runs"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+opts.token)
	req.Header.Set("User-Agent", "concord-agent/"+versionString())

	if opts.keyID != "" || opts.keyPath != "" {
		sig, err := signBody(opts, body)
		if err != nil {
			return err
		}
		req.Header.Set("X-Concord-Agent-Key-Id", opts.keyID)
		req.Header.Set("X-Concord-Agent-Signature", sig)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	// Print the run id / source so CI logs are useful.
	var ack struct {
		RunID             string `json:"run_id"`
		Source            string `json:"source"`
		SignatureVerified bool   `json:"signature_verified"`
		URL               string `json:"url"`
	}
	if err := json.Unmarshal(respBody, &ack); err == nil && ack.RunID != "" {
		fmt.Fprintf(os.Stderr, "✓ run %s submitted (source=%s, signed=%t)\n   %s%s\n",
			ack.RunID, ack.Source, ack.SignatureVerified,
			strings.TrimRight(opts.serverURL, "/"), ack.URL)
	}
	return nil
}

// signBody reads the private key and returns base64 Ed25519(body).
func signBody(opts pushOpts, body []byte) (string, error) {
	if opts.keyID == "" || opts.keyPath == "" {
		return "", errors.New("--key-id and --key must both be set to sign (or both unset to push unsigned)")
	}
	raw, err := os.ReadFile(opts.keyPath)
	if err != nil {
		return "", fmt.Errorf("reading private key %s: %w", opts.keyPath, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("private key file %s is %d bytes, expected %d (Ed25519)", opts.keyPath, len(raw), ed25519.PrivateKeySize)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(raw), body)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func (o pushOpts) validate() error {
	if o.serverURL == "" {
		return errors.New("--to is required (or set CONCORD_SERVER_URL)")
	}
	if o.orgSlug == "" {
		return errors.New("--org-slug is required (or set CONCORD_ORG_SLUG)")
	}
	if o.token == "" {
		return errors.New("--token is required (or set CONCORD_API_TOKEN)")
	}
	if (o.keyID == "") != (o.keyPath == "") {
		return errors.New("--key-id and --key must both be set or both unset")
	}
	return nil
}

// agentVersion encodes the CLI version + an optional user-supplied label.
// "1.2.3" or "1.2.3/ci-prod" — the / separator is a stable parse boundary.
func agentVersion(label string) string {
	v := versionString()
	if label != "" {
		return v + "/" + label
	}
	return v
}

// versionString is the agent version reported on every push. Wired to the
// same `version` global the version.go subcommand prints.
func versionString() string {
	if version != "" {
		return version
	}
	return "dev"
}
