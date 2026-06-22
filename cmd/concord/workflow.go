package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type workflowInstanceDTO struct {
	ID                string         `json:"id"`
	OrgID             string         `json:"org_id"`
	Kind              string         `json:"kind"`
	DefinitionVersion int            `json:"definition_version"`
	Status            string         `json:"status"`
	CurrentState      string         `json:"current_state"`
	Input             map[string]any `json:"input,omitempty"`
	Vars              map[string]any `json:"vars,omitempty"`
	Error             string         `json:"error,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
	CompletedAt       *time.Time     `json:"completed_at,omitempty"`
}

type workflowStepDTO struct {
	ID            string     `json:"id"`
	StepKey       string     `json:"step_key"`
	Action        string     `json:"action"`
	Status        string     `json:"status"`
	AttemptCount  int        `json:"attempt_count"`
	MaxAttempts   int        `json:"max_attempts"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	LastError     string     `json:"last_error,omitempty"`
	ProcessedAt   *time.Time `json:"processed_at,omitempty"`
}

type workflowTimerDTO struct {
	ID       string     `json:"id"`
	TimerKey string     `json:"timer_key"`
	Signal   string     `json:"signal"`
	FireAt   time.Time  `json:"fire_at"`
	FiredAt  *time.Time `json:"fired_at,omitempty"`
}

type workflowDetailDTO struct {
	Instance workflowInstanceDTO `json:"instance"`
	Steps    []workflowStepDTO   `json:"steps"`
	Timers   []workflowTimerDTO  `json:"timers"`
}

func newWorkflowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "workflow",
		Aliases: []string{"wf"},
		Short:   "Inspect and manage durable workflow instances (campaigns, SLA timelines)",
	}
	cmd.AddCommand(newWorkflowListCmd())
	cmd.AddCommand(newWorkflowShowCmd())
	cmd.AddCommand(newWorkflowCancelCmd())
	return cmd
}

func newWorkflowListCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		kind, status, format      string
		limit                     int
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List workflow instances for this org",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			rows, err := listWorkflows(cmd.Context(), fs, kind, status, limit)
			if err != nil {
				return err
			}
			return printWorkflowInstances(os.Stdout, rows, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&kind, "kind", "", "Filter by workflow kind (e.g. access_review_campaign)")
	cmd.Flags().StringVar(&status, "status", "", "Filter by status: running|waiting|completed|failed|cancelled")
	cmd.Flags().IntVar(&limit, "limit", 0, "Maximum number of instances to return (server default 100, max 1000)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newWorkflowShowCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "show <workflow-id>",
		Short: "Show one workflow instance with its steps and timers",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			detail, err := getWorkflowDetail(cmd.Context(), fs, args[0])
			if err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(detail)
			}
			printWorkflowDetail(os.Stdout, detail)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newWorkflowCancelCmd() *cobra.Command {
	var serverURL, orgSlug, token, reason string
	cmd := &cobra.Command{
		Use:   "cancel <workflow-id>",
		Short: "Cancel a running workflow instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			inst, err := cancelWorkflow(cmd.Context(), fs, args[0], reason)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s cancelled (status=%s)\n", inst.ID, inst.Status)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&reason, "reason", "", "Cancellation reason recorded on the audit trail")
	return cmd
}

func listWorkflows(ctx context.Context, fs findingsServer, kind, status string, limit int) ([]workflowInstanceDTO, error) {
	q := url.Values{}
	if kind != "" {
		q.Set("kind", kind)
	}
	if status != "" {
		q.Set("status", status)
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	path := "/v1/orgs/" + fs.orgSlug + "/workflows"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var rows []workflowInstanceDTO
	if err := apiGet(ctx, fs, path, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func getWorkflowDetail(ctx context.Context, fs findingsServer, id string) (workflowDetailDTO, error) {
	var detail workflowDetailDTO
	err := apiGet(ctx, fs, "/v1/orgs/"+fs.orgSlug+"/workflows/"+id, &detail)
	return detail, err
}

func cancelWorkflow(ctx context.Context, fs findingsServer, id, reason string) (workflowInstanceDTO, error) {
	// Keep body a nil interface (not a typed-nil map) when there's no reason, so
	// apiSend omits the request body rather than sending a JSON `null`.
	var body any
	if strings.TrimSpace(reason) != "" {
		body = map[string]any{"reason": reason}
	}
	var inst workflowInstanceDTO
	err := apiSend(ctx, fs, "POST", "/v1/orgs/"+fs.orgSlug+"/workflows/"+id+"/cancel", body, &inst)
	return inst, err
}

func printWorkflowInstances(w io.Writer, rows []workflowInstanceDTO, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "no workflows")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tKIND\tSTATUS\tSTATE\tCREATED\tUPDATED")
	for _, c := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			c.ID, c.Kind, c.Status, c.CurrentState,
			c.CreatedAt.Format("2006-01-02 15:04"),
			c.UpdatedAt.Format("2006-01-02 15:04"))
	}
	return tw.Flush()
}

func printWorkflowDetail(w io.Writer, d workflowDetailDTO) {
	inst := d.Instance
	fmt.Fprintf(w, "Workflow   : %s\n", inst.ID)
	fmt.Fprintf(w, "Kind       : %s (v%d)\n", inst.Kind, inst.DefinitionVersion)
	fmt.Fprintf(w, "Status     : %s\n", inst.Status)
	fmt.Fprintf(w, "State      : %s\n", inst.CurrentState)
	fmt.Fprintf(w, "Created    : %s\n", inst.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Updated    : %s\n", inst.UpdatedAt.Format(time.RFC3339))
	if inst.CompletedAt != nil {
		fmt.Fprintf(w, "Completed  : %s\n", inst.CompletedAt.Format(time.RFC3339))
	}
	if inst.Error != "" {
		fmt.Fprintf(w, "Error      : %s\n", inst.Error)
	}
	if len(inst.Input) > 0 {
		fmt.Fprintf(w, "Input      : %s\n", compactJSON(inst.Input))
	}
	if len(inst.Vars) > 0 {
		fmt.Fprintf(w, "Vars       : %s\n", compactJSON(inst.Vars))
	}

	fmt.Fprintln(w, "\nSteps:")
	if len(d.Steps) == 0 {
		fmt.Fprintln(w, "  (none)")
	} else {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  STEP\tACTION\tSTATUS\tATTEMPTS\tNEXT/PROCESSED\tLAST ERROR")
		for _, s := range d.Steps {
			when := "—"
			if s.ProcessedAt != nil {
				when = s.ProcessedAt.Format(time.RFC3339)
			} else if !s.NextAttemptAt.IsZero() {
				when = s.NextAttemptAt.Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%d/%d\t%s\t%s\n",
				s.StepKey, s.Action, s.Status, s.AttemptCount, s.MaxAttempts, when, truncate(s.LastError, 48))
		}
		_ = tw.Flush()
	}

	fmt.Fprintln(w, "\nTimers:")
	if len(d.Timers) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  TIMER\tSIGNAL\tFIRE AT\tFIRED")
	for _, t := range d.Timers {
		fired := "—"
		if t.FiredAt != nil {
			fired = t.FiredAt.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n",
			t.TimerKey, t.Signal, t.FireAt.Format(time.RFC3339), fired)
	}
	_ = tw.Flush()
}

func compactJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(raw)
}

func truncate(s string, n int) string {
	if s == "" {
		return "—"
	}
	// Count runes, not bytes: slicing a string on a byte boundary can split a
	// multi-byte rune and emit invalid UTF-8 (last_error is arbitrary server text).
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
