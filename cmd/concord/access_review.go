package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type accessReviewCycleDTO struct {
	ID              string                  `json:"id"`
	Quarter         string                  `json:"quarter"`
	Status          string                  `json:"status"`
	StartedAt       time.Time               `json:"started_at"`
	DueAt           time.Time               `json:"due_at"`
	CompletedAt     *time.Time              `json:"completed_at,omitempty"`
	StartedByUserID *string                 `json:"started_by_user_id,omitempty"`
	Notes           string                  `json:"notes,omitempty"`
	ItemCounts      accessReviewCountsDTO   `json:"item_counts"`
}

type accessReviewCountsDTO struct {
	Total    int `json:"total"`
	Pending  int `json:"pending"`
	Keep     int `json:"keep"`
	Revoke   int `json:"revoke"`
	Escalate int `json:"escalate"`
}

type accessReviewItemDTO struct {
	ID             string     `json:"id"`
	SubjectUserID  string     `json:"subject_user_id"`
	SubjectEmail   string     `json:"subject_email"`
	ReviewerUserID *string    `json:"reviewer_user_id,omitempty"`
	System         string     `json:"system"`
	Scope          string     `json:"scope"`
	ProjectID      *string    `json:"project_id,omitempty"`
	RoleName       string     `json:"role_name"`
	Decision       *string    `json:"decision,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	Justification  string     `json:"justification,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
}

func newAccessReviewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "access-review",
		Aliases: []string{"ar"},
		Short:   "Quarterly access reviews (SOC 2 CC6 / ISO 27001 A.5.18)",
	}
	cmd.AddCommand(newAccessReviewStartCmd())
	cmd.AddCommand(newAccessReviewListCmd())
	cmd.AddCommand(newAccessReviewShowCmd())
	cmd.AddCommand(newAccessReviewDecideCmd())
	cmd.AddCommand(newAccessReviewCompleteCmd())
	cmd.AddCommand(newAccessReviewCancelCmd())
	return cmd
}

func newAccessReviewStartCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		quarter, due, notes       string
	)
	cmd := &cobra.Command{
		Use:   "start",
		Short: "Start a new access-review cycle and snapshot every (user, role) pair",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			dueAt, err := parseAccessReviewDate(due)
			if err != nil {
				return err
			}
			body := map[string]any{
				"quarter": strings.TrimSpace(quarter),
				"due_at":  dueAt.Format(time.RFC3339),
			}
			if notes != "" {
				body["notes"] = notes
			}
			var c accessReviewCycleDTO
			if err := apiSend(cmd.Context(), fs, "POST",
				"/v1/orgs/"+fs.orgSlug+"/access-reviews", body, &c); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s started — quarter=%s, %d items seeded, due %s\n",
				c.ID, c.Quarter, c.ItemCounts.Total, c.DueAt.Format(time.RFC3339))
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&quarter, "quarter", "", "Quarter label, e.g. 2026Q3 (required)")
	cmd.Flags().StringVar(&due, "due", "", "Due date (RFC3339 or YYYY-MM-DD) (required)")
	cmd.Flags().StringVar(&notes, "notes", "", "Optional notes recorded on the cycle")
	_ = cmd.MarkFlagRequired("quarter")
	_ = cmd.MarkFlagRequired("due")
	return cmd
}

func newAccessReviewListCmd() *cobra.Command {
	var serverURL, orgSlug, token, format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List access-review cycles for this org",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var rows []accessReviewCycleDTO
			if err := apiGet(cmd.Context(), fs,
				"/v1/orgs/"+fs.orgSlug+"/access-reviews", &rows); err != nil {
				return err
			}
			return printAccessReviewCycles(os.Stdout, rows, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newAccessReviewShowCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		onlyPending, withItems    bool
		systemFilter, format      string
	)
	cmd := &cobra.Command{
		Use:   "show <cycle-id>",
		Short: "Show one cycle and its pending decisions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var c accessReviewCycleDTO
			if err := apiGet(cmd.Context(), fs,
				"/v1/orgs/"+fs.orgSlug+"/access-reviews/"+args[0], &c); err != nil {
				return err
			}
			var items []accessReviewItemDTO
			if withItems {
				q := url.Values{}
				if onlyPending {
					q.Set("pending", "true")
				}
				if systemFilter != "" {
					q.Set("system", systemFilter)
				}
				path := "/v1/orgs/" + fs.orgSlug + "/access-reviews/" + args[0] + "/items"
				if len(q) > 0 {
					path += "?" + q.Encode()
				}
				if err := apiGet(cmd.Context(), fs, path, &items); err != nil {
					return err
				}
			}
			if format == "json" {
				return json.NewEncoder(os.Stdout).Encode(map[string]any{
					"cycle": c, "items": items,
				})
			}
			printOneAccessReviewCycle(os.Stdout, c)
			if withItems {
				fmt.Fprintln(os.Stdout, "\nItems:")
				printAccessReviewItems(os.Stdout, items)
			}
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().BoolVar(&withItems, "items", true, "Include the per-(user,role) item list")
	cmd.Flags().BoolVar(&onlyPending, "pending", false, "List only items awaiting a decision")
	cmd.Flags().StringVar(&systemFilter, "system", "", "Filter items by system (e.g. concord:org, concord:project)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newAccessReviewDecideCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token  string
		decision, justification    string
	)
	cmd := &cobra.Command{
		Use:   "decide <cycle-id> <item-id>",
		Short: "Record a decision (keep|revoke|escalate) for one review item",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{"decision": strings.TrimSpace(decision)}
			if justification != "" {
				body["justification"] = justification
			}
			var item accessReviewItemDTO
			if err := apiSend(cmd.Context(), fs, "POST",
				"/v1/orgs/"+fs.orgSlug+"/access-reviews/"+args[0]+"/items/"+args[1]+"/decision",
				body, &item); err != nil {
				return err
			}
			d := ""
			if item.Decision != nil {
				d = *item.Decision
			}
			fmt.Fprintf(os.Stdout, "%s: %s → %s\n", item.SubjectEmail, item.RoleName, d)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&decision, "decision", "", "keep|revoke|escalate (required)")
	cmd.Flags().StringVar(&justification, "justification", "", "Required for revoke; recommended for escalate")
	_ = cmd.MarkFlagRequired("decision")
	return cmd
}

func newAccessReviewCompleteCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "complete <cycle-id>",
		Short: "Close a cycle (fails if any items remain undecided)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var c accessReviewCycleDTO
			if err := apiSend(cmd.Context(), fs, "POST",
				"/v1/orgs/"+fs.orgSlug+"/access-reviews/"+args[0]+"/complete", nil, &c); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s completed — %d total items\n", c.ID, c.ItemCounts.Total)
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func newAccessReviewCancelCmd() *cobra.Command {
	var serverURL, orgSlug, token string
	cmd := &cobra.Command{
		Use:   "cancel <cycle-id>",
		Short: "Cancel an in-progress cycle",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			if err := apiDelete(cmd.Context(), fs,
				"/v1/orgs/"+fs.orgSlug+"/access-reviews/"+args[0]); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s cancelled\n", args[0])
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	return cmd
}

func parseAccessReviewDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t.UTC().Add(23 * time.Hour), nil
	}
	return time.Time{}, fmt.Errorf("--due must be RFC3339 or YYYY-MM-DD")
}

func printAccessReviewCycles(w io.Writer, rows []accessReviewCycleDTO, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "no access-review cycles")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tQUARTER\tSTATUS\tDUE\tPENDING/TOTAL\tREVOKE")
	for _, c := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d/%d\t%d\n",
			c.ID, c.Quarter, c.Status,
			c.DueAt.Format("2006-01-02"),
			c.ItemCounts.Pending, c.ItemCounts.Total,
			c.ItemCounts.Revoke)
	}
	return tw.Flush()
}

func printOneAccessReviewCycle(w io.Writer, c accessReviewCycleDTO) {
	fmt.Fprintf(w, "Cycle      : %s\n", c.ID)
	fmt.Fprintf(w, "Quarter    : %s\n", c.Quarter)
	fmt.Fprintf(w, "Status     : %s\n", c.Status)
	fmt.Fprintf(w, "Started    : %s\n", c.StartedAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Due        : %s\n", c.DueAt.Format(time.RFC3339))
	if c.CompletedAt != nil {
		fmt.Fprintf(w, "Completed  : %s\n", c.CompletedAt.Format(time.RFC3339))
	}
	if c.Notes != "" {
		fmt.Fprintf(w, "Notes      : %s\n", c.Notes)
	}
	fmt.Fprintf(w, "Items      : total=%d pending=%d keep=%d revoke=%d escalate=%d\n",
		c.ItemCounts.Total, c.ItemCounts.Pending,
		c.ItemCounts.Keep, c.ItemCounts.Revoke, c.ItemCounts.Escalate)
}

func printAccessReviewItems(w io.Writer, items []accessReviewItemDTO) {
	if len(items) == 0 {
		fmt.Fprintln(w, "  (none)")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ITEM ID\tEMAIL\tSYSTEM\tROLE\tDECISION\tDECIDED")
	for _, it := range items {
		decision := "—"
		if it.Decision != nil {
			decision = *it.Decision
		}
		decided := "—"
		if it.DecidedAt != nil {
			decided = it.DecidedAt.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			it.ID, it.SubjectEmail, it.System, it.RoleName, decision, decided)
	}
	_ = tw.Flush()
}
