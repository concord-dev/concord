package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/cli/credentials"
	"github.com/concord-dev/concord/pkg/report"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type pushOpts struct {
	serverURL   string
	orgSlug     string
	projectSlug string
	token       string
	agentLabel  string // free-form, lands in agent_version
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

Authentication is the same API token used everywhere else. No separate
signing key: the token is the agent's identity. Revoke the token, the
agent stops working.`,
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

func addPushFlags(cmd *cobra.Command, opts *pushOpts) {
	cmd.Flags().StringVar(&opts.serverURL, "to", os.Getenv("CONCORD_SERVER_URL"), "Concord server base URL (or CONCORD_SERVER_URL)")
	cmd.Flags().StringVar(&opts.orgSlug, "org-slug", os.Getenv("CONCORD_ORG_SLUG"), "Organization slug (or CONCORD_ORG_SLUG)")
	cmd.Flags().StringVar(&opts.projectSlug, "project", os.Getenv("CONCORD_PROJECT_SLUG"), "Project slug (or CONCORD_PROJECT_SLUG; defaults to the profile's default_project or 'default')")
	cmd.Flags().StringVar(&opts.token, "token", os.Getenv("CONCORD_API_TOKEN"), "API token (or CONCORD_API_TOKEN)")
	cmd.Flags().StringVar(&opts.agentLabel, "agent-label", "", "Optional agent identifier recorded on the run (e.g. CI job name)")
}

func pushFindings(ctx context.Context, opts pushOpts, findings []apiv1.Finding, startedAt, completedAt time.Time) error {
	opts.resolveFromCredentials()
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

	url := strings.TrimRight(opts.serverURL, "/") + "/v1/orgs/" + opts.orgSlug +
		"/projects/" + opts.projectSlug + "/runs"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+opts.token)
	req.Header.Set("User-Agent", "concord-agent/"+versionString())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBody))
	}

	var ack struct {
		RunID  string `json:"run_id"`
		Source string `json:"source"`
		URL    string `json:"url"`
	}
	if err := json.Unmarshal(respBody, &ack); err == nil && ack.RunID != "" {
		fmt.Fprintf(os.Stderr, "✓ run %s submitted (source=%s)\n   %s%s\n",
			ack.RunID, ack.Source, strings.TrimRight(opts.serverURL, "/"), ack.URL)
	}
	return nil
}

func (o *pushOpts) resolveFromCredentials() {
	file, err := credentials.Load()
	if err == nil {
		if p, perr := file.CurrentProfile(); perr == nil {
			if o.serverURL == "" {
				o.serverURL = p.Server
			}
			if o.orgSlug == "" {
				o.orgSlug = p.DefaultOrg
			}
			if o.projectSlug == "" {
				o.projectSlug = p.DefaultProject
			}
			if o.token == "" {
				o.token = p.Token
			}
		}
	}
	if o.projectSlug == "" {
		o.projectSlug = "default"
	}
}

func (o pushOpts) validate() error {
	if o.serverURL == "" {
		return errors.New("--to is required (or set CONCORD_SERVER_URL, or run `concord login`)")
	}
	if o.orgSlug == "" {
		return errors.New("--org-slug is required (or set CONCORD_ORG_SLUG, or run `concord orgs use <slug>`)")
	}
	if o.token == "" {
		return errors.New("--token is required (or set CONCORD_API_TOKEN, or run `concord login`)")
	}
	return nil
}

func agentVersion(label string) string {
	v := versionString()
	if label != "" {
		return v + "/" + label
	}
	return v
}

func versionString() string {
	if version != "" {
		return version
	}
	return "dev"
}
