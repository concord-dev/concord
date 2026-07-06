package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	sdkplugin "github.com/concord-dev/concord-plugin-sdk/plugin"
	"github.com/concord-dev/concord/internal/plugins"
)

type remediationAttemptDTO struct {
	ID            string     `json:"id"`
	OrgID         string     `json:"org_id"`
	ProjectID     string     `json:"project_id"`
	FindingID     string     `json:"finding_id"`
	PluginSource  string     `json:"plugin_source"`
	PluginVersion string     `json:"plugin_version"`
	Action        string     `json:"action"`
	Mode          string     `json:"mode"`
	Status        string     `json:"status"`
	Reason        string     `json:"reason"`
	ReceiptID     string     `json:"receipt_id,omitempty"`
	StartedAt     time.Time  `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
}

func newRemediateCmd() *cobra.Command {
	var (
		flagServer       string
		flagOrgSlug      string
		flagProject      string
		flagToken        string
		flagPluginSource string
		flagAction       string
		flagReason       string
		flagDryRun       bool
		flagExecute      bool
		flagParamsJSON   string
	)
	cmd := &cobra.Command{
		Use:   "remediate <finding-id>",
		Short: "Run a Remediator plugin against a finding (dry-run or execute)",
		Long: `Run a Remediator plugin to fix a failing finding.

The CLI spawns the named plugin locally (with the user's credentials),
calls DryRun or Execute, and POSTs the result + steps to the Concord
platform which signs the receipt and writes it to the audit chain.

Examples:
  concord remediate FIND-abc --plugin aws --action s3.enable_public_access_block --dry-run
  concord remediate FIND-abc --plugin aws --action s3.enable_public_access_block --execute --reason "Q3 audit close-out"`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			findingID := strings.TrimSpace(args[0])
			if findingID == "" {
				return errors.New("finding id is required")
			}
			if flagDryRun == flagExecute {
				return errors.New("specify exactly one of --dry-run or --execute")
			}
			mode := "dry_run"
			if flagExecute {
				mode = "execute"
				if strings.TrimSpace(flagReason) == "" {
					return errors.New("--reason is required when --execute (audit log evidence)")
				}
			}
			if flagPluginSource == "" {
				return errors.New("--plugin is required (e.g., --plugin aws)")
			}
			if flagAction == "" {
				return errors.New("--action is required (e.g., --action s3.enable_public_access_block)")
			}

			var params map[string]any
			if strings.TrimSpace(flagParamsJSON) != "" {
				params = map[string]any{}
				if err := json.Unmarshal([]byte(flagParamsJSON), &params); err != nil {
					return fmt.Errorf("--params is not valid JSON: %w", err)
				}
			}

			fs, err := resolveServer(flagServer, flagOrgSlug, flagProject, flagToken)
			if err != nil {
				return err
			}

			mgr := plugins.New(plugins.Options{})
			if derr := mgr.Discover(); derr != nil {
				return fmt.Errorf("discovering plugins: %w", derr)
			}
			entry := mgr.FindRemediator(flagPluginSource)
			if entry == nil {
				return fmt.Errorf("no remediator plugin discovered for source %q — install with `concord plugin install %s-remediator`", flagPluginSource, flagPluginSource)
			}
			rem, err := plugins.SpawnRemediator(*entry, 120*time.Second)
			if err != nil {
				return err
			}
			defer rem.Close()

			ctx := context.Background()
			caps, err := rem.Capabilities(ctx)
			if err != nil {
				return fmt.Errorf("plugin capabilities: %w", err)
			}
			if !containsString(caps.Actions, flagAction) {
				return fmt.Errorf("plugin %s does not advertise action %q (advertised: %v)", caps.Source, flagAction, caps.Actions)
			}

			// Step 1 — open the pending attempt on the platform.
			attempt, err := openRemediationAttempt(fs, findingID, openBody{
				PluginSource:  caps.Source,
				PluginVersion: caps.Version,
				Action:        flagAction,
				Mode:          mode,
				Reason:        flagReason,
				Params:        params,
			})
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "opened attempt %s (mode=%s, plugin=%s/%s)\n",
				attempt.ID, attempt.Mode, attempt.PluginSource, attempt.PluginVersion)

			// Step 2 — invoke the plugin locally.
			pluginReq := sdkplugin.RemediateRequest{
				FindingID: findingID,
				Action:    flagAction,
				Params:    params,
			}
			var resp sdkplugin.RemediateResponse
			if mode == "execute" {
				pluginReq.ApprovalToken = attempt.ID
				resp, err = rem.Execute(ctx, pluginReq)
			} else {
				resp, err = rem.DryRun(ctx, pluginReq)
			}

			status := "succeeded"
			errorMsg := ""
			if err != nil {
				status = "failed"
				errorMsg = err.Error()
			} else if resp.Outcome == "failed" {
				status = "failed"
				errorMsg = resp.ErrorMessage
			}

			// Step 3 — complete the attempt on the platform; receipt gets signed.
			completed, cerr := completeRemediationAttempt(fs, attempt.ID, completeBody{
				Status:       status,
				Steps:        resp.Steps,
				ErrorMessage: errorMsg,
			})
			if cerr != nil {
				return fmt.Errorf("plugin returned but completion POST failed: %w (plugin err: %v)", cerr, err)
			}

			renderAttempt(cmd.OutOrStdout(), completed, resp.Steps)
			if status == "failed" {
				return fmt.Errorf("remediation failed: %s", errorMsg)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&flagServer, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&flagOrgSlug, "org-slug", "", "org slug")
	cmd.Flags().StringVar(&flagProject, "project", "", `project slug (default: profile's default project, then "default")`)
	cmd.Flags().StringVar(&flagToken, "token", "", "API token")
	cmd.Flags().StringVar(&flagPluginSource, "plugin", "", "remediator plugin source (e.g., aws)")
	cmd.Flags().StringVar(&flagAction, "action", "", "action id from plugin Capabilities.actions")
	cmd.Flags().StringVar(&flagReason, "reason", "", "operator-supplied reason; required for --execute")
	cmd.Flags().BoolVar(&flagDryRun, "dry-run", false, "show what would change without executing")
	cmd.Flags().BoolVar(&flagExecute, "execute", false, "perform the action against the target API")
	cmd.Flags().StringVar(&flagParamsJSON, "params", "", "action params as a JSON object (e.g., '{\"bucket\":\"my-bucket\"}')")
	return cmd
}

type openBody struct {
	PluginSource  string         `json:"plugin_source"`
	PluginVersion string         `json:"plugin_version"`
	Action        string         `json:"action"`
	Mode          string         `json:"mode"`
	Reason        string         `json:"reason"`
	Params        map[string]any `json:"params,omitempty"`
}

type completeBody struct {
	Status       string                    `json:"status"`
	Steps        []sdkplugin.RemediateStep `json:"steps,omitempty"`
	ErrorMessage string                    `json:"error_message,omitempty"`
}

func openRemediationAttempt(fs findingsServer, findingID string, body openBody) (*remediationAttemptDTO, error) {
	raw, _ := json.Marshal(body)
	url := fs.url + fs.projectBase() + "/findings/" + findingID + "/remediation-attempts"
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+fs.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rawResp, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("open attempt %d: %s", resp.StatusCode, rawResp)
	}
	var out remediationAttemptDTO
	if err := json.Unmarshal(rawResp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func completeRemediationAttempt(fs findingsServer, attemptID string, body completeBody) (*remediationAttemptDTO, error) {
	raw, _ := json.Marshal(body)
	url := fs.url + fs.projectBase() + "/remediation-attempts/" + attemptID + "/complete"
	req, _ := http.NewRequest(http.MethodPut, url, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+fs.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	rawResp, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("complete attempt %d: %s", resp.StatusCode, rawResp)
	}
	var out remediationAttemptDTO
	if err := json.Unmarshal(rawResp, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func renderAttempt(w io.Writer, a *remediationAttemptDTO, steps []sdkplugin.RemediateStep) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "attempt\t%s\n", a.ID)
	fmt.Fprintf(tw, "status\t%s\n", a.Status)
	fmt.Fprintf(tw, "mode\t%s\n", a.Mode)
	fmt.Fprintf(tw, "plugin\t%s/%s\n", a.PluginSource, a.PluginVersion)
	fmt.Fprintf(tw, "action\t%s\n", a.Action)
	if a.ReceiptID != "" {
		fmt.Fprintf(tw, "receipt\t%s\n", a.ReceiptID)
	}
	tw.Flush()
	if len(steps) > 0 {
		fmt.Fprintln(w, "steps:")
		for _, s := range steps {
			fmt.Fprintf(w, "  %s %s\n", s.Operation, s.Resource)
		}
	}
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
