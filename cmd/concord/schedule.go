package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type scheduleDTO struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Kind          string     `json:"kind"`
	Spec          string     `json:"spec"`
	Enabled       bool       `json:"enabled"`
	NextRunAt     *time.Time `json:"next_run_at,omitempty"`
	LastRunAt     *time.Time `json:"last_run_at,omitempty"`
	LastRunStatus string     `json:"last_run_status,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
}

type scheduleRunDTO struct {
	FireTime   *time.Time `json:"fire_time,omitempty"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Status     string     `json:"status"`
	Error      string     `json:"error,omitempty"`
}

func scheduleBase(fs findingsServer) string {
	return "/v1/orgs/" + fs.orgSlug + "/schedules"
}

func tsOrDash(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.RFC3339)
}

func newScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "schedule",
		Aliases: []string{"sched"},
		Short:   "Manage server-side schedules (recurring collection, evaluation, and campaigns)",
	}
	cmd.AddCommand(newScheduleCreateCmd())
	cmd.AddCommand(newScheduleListCmd())
	cmd.AddCommand(newScheduleShowCmd())
	cmd.AddCommand(newScheduleUpdateCmd())
	cmd.AddCommand(newScheduleEnableCmd("enable", true))
	cmd.AddCommand(newScheduleEnableCmd("disable", false))
	cmd.AddCommand(newScheduleRunCmd())
	cmd.AddCommand(newScheduleRunsCmd())
	cmd.AddCommand(newScheduleDeleteCmd())
	return cmd
}

func newScheduleCreateCmd() *cobra.Command {
	var serverURL, orgSlug, token, name, kind, spec, argsJSON string
	var disabled bool
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a schedule (cron or @-descriptor spec, e.g. '@every 6h' or '0 2 * * *')",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			payload := map[string]any{"name": name, "kind": kind, "spec": spec, "enabled": !disabled}
			if argsJSON != "" {
				var a map[string]any
				if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
					return fmt.Errorf("--args must be a JSON object: %w", err)
				}
				payload["args"] = a
			}
			var sc scheduleDTO
			if err := apiSend(cmd.Context(), fs, "POST", scheduleBase(fs), payload, &sc); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: %s (%s, next %s)\n", sc.ID, sc.Name, sc.Kind, tsOrDash(sc.NextRunAt))
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&name, "name", "", "Unique schedule name (required)")
	cmd.Flags().StringVar(&kind, "kind", "", "Job kind, e.g. collection.trigger, attestation.launch (required)")
	cmd.Flags().StringVar(&spec, "spec", "", "Cron expression or @-descriptor (required)")
	cmd.Flags().StringVar(&argsJSON, "args", "", "Job arguments as a JSON object")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "Create the schedule paused")
	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("kind")
	_ = cmd.MarkFlagRequired("spec")
	return cmd
}

func newScheduleListCmd() *cobra.Command {
	var serverURL, orgSlug, token, kind, enabled, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List schedules",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			if kind != "" {
				q.Set("kind", kind)
			}
			if enabled != "" {
				q.Set("enabled", enabled)
			}
			path := scheduleBase(fs)
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			var rows []scheduleDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no schedules")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tENABLED\tKIND\tSPEC\tNEXT\tLAST")
			for _, sc := range rows {
				last := "-"
				if sc.LastRunStatus != "" {
					last = sc.LastRunStatus
				}
				fmt.Fprintf(tw, "%s\t%t\t%s\t%s\t%s\t%s\n", sc.ID, sc.Enabled, sc.Kind, sc.Spec, tsOrDash(sc.NextRunAt), last)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&kind, "kind", "", "Filter by job kind")
	cmd.Flags().StringVar(&enabled, "enabled", "", "Filter: true|false")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newScheduleShowCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one schedule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var sc scheduleDTO
			if err := apiGet(cmd.Context(), fs, scheduleBase(fs)+"/"+args[0], &sc); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(sc)
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintf(tw, "id\t%s\n", sc.ID)
			fmt.Fprintf(tw, "name\t%s\n", sc.Name)
			fmt.Fprintf(tw, "kind\t%s\n", sc.Kind)
			fmt.Fprintf(tw, "spec\t%s\n", sc.Spec)
			fmt.Fprintf(tw, "enabled\t%t\n", sc.Enabled)
			fmt.Fprintf(tw, "next\t%s\n", tsOrDash(sc.NextRunAt))
			fmt.Fprintf(tw, "last\t%s (%s)\n", tsOrDash(sc.LastRunAt), dashIfEmpty(sc.LastRunStatus))
			if sc.LastError != "" {
				fmt.Fprintf(tw, "last_error\t%s\n", sc.LastError)
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newScheduleUpdateCmd() *cobra.Command {
	var serverURL, orgSlug, token, name, spec, argsJSON string
	cmd := &cobra.Command{
		Use:   "update <id>",
		Short: "Update a schedule's name, spec, or args",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			payload := map[string]any{}
			if cmd.Flags().Changed("name") {
				payload["name"] = name
			}
			if cmd.Flags().Changed("spec") {
				payload["spec"] = spec
			}
			if cmd.Flags().Changed("args") {
				var a map[string]any
				if err := json.Unmarshal([]byte(argsJSON), &a); err != nil {
					return fmt.Errorf("--args must be a JSON object: %w", err)
				}
				payload["args"] = a
			}
			if len(payload) == 0 {
				return fmt.Errorf("nothing to update: pass --name, --spec, or --args")
			}
			var sc scheduleDTO
			if err := apiSend(cmd.Context(), fs, "PATCH", scheduleBase(fs)+"/"+args[0], payload, &sc); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: updated (next %s)\n", sc.ID, tsOrDash(sc.NextRunAt))
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&name, "name", "", "New name")
	cmd.Flags().StringVar(&spec, "spec", "", "New cron/@-descriptor spec (recomputes next run)")
	cmd.Flags().StringVar(&argsJSON, "args", "", "Replacement job arguments as a JSON object")
	return cmd
}

func newScheduleEnableCmd(verb string, enabled bool) *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   verb + " <id>",
		Short: verb + " a schedule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var sc scheduleDTO
			if err := apiSend(cmd.Context(), fs, "PATCH", scheduleBase(fs)+"/"+args[0], map[string]any{"enabled": enabled}, &sc); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s: enabled=%t\n", sc.ID, sc.Enabled)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newScheduleRunCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "run <id>",
		Short: "Fire a schedule once now without changing its cadence",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var run scheduleRunDTO
			if err := apiSend(cmd.Context(), fs, "POST", scheduleBase(fs)+"/"+args[0]+"/run", nil, &run); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "ran: %s", run.Status)
			if run.Error != "" {
				fmt.Fprintf(os.Stdout, " (%s)", run.Error)
			}
			fmt.Fprintln(os.Stdout)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newScheduleRunsCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	var limit int
	cmd := &cobra.Command{
		Use:   "runs <id>",
		Short: "Show a schedule's execution history, newest first",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			path := scheduleBase(fs) + "/" + args[0] + "/runs"
			if limit > 0 {
				path += "?limit=" + fmt.Sprint(limit)
			}
			var rows []scheduleRunDTO
			if err := apiGet(cmd.Context(), fs, path, &rows); err != nil {
				return err
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(rows)
			}
			if len(rows) == 0 {
				fmt.Fprintln(os.Stdout, "no runs")
				return nil
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "FIRE\tFINISHED\tSTATUS\tERROR")
			for _, r := range rows {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", tsOrDash(r.FireTime), tsOrDash(r.FinishedAt), r.Status, dashIfEmpty(r.Error))
			}
			return tw.Flush()
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().IntVar(&limit, "limit", 0, "Max runs to return")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newScheduleDeleteCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "Delete a schedule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if err := apiSend(cmd.Context(), fs, "DELETE", scheduleBase(fs)+"/"+args[0], nil, nil); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "deleted %s\n", args[0])
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}
