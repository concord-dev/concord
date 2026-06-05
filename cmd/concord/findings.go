package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/cli/credentials"
)

// findingDTO mirrors store.Finding on the platform side. We unmarshal what we
// need without binding to the platform module.
type findingDTO struct {
	ID                      string    `json:"id"`
	ControlID               string    `json:"control_id"`
	Framework               string    `json:"framework"`
	Severity                string    `json:"severity"`
	Status                  string    `json:"status"`
	CurrentEvaluationStatus string    `json:"current_evaluation_status"`
	SuppressedUntil         *time.Time `json:"suppressed_until,omitempty"`
	Justification           string    `json:"justification,omitempty"`
	LastMessages            []string  `json:"last_messages,omitempty"`
	FirstSeenAt             time.Time `json:"first_seen_at"`
	LastSeenAt              time.Time `json:"last_seen_at"`
}

type findingEventDTO struct {
	OccurredAt    time.Time `json:"occurred_at"`
	EventKind     string    `json:"event_kind"`
	FromStatus    string    `json:"from_status,omitempty"`
	ToStatus      string    `json:"to_status,omitempty"`
	Justification string    `json:"justification,omitempty"`
	ActorKind     string    `json:"actor_kind"`
}

type findingsServer struct {
	url     string
	orgSlug string
	token   string
}

func resolveFindingsServer(serverURL, orgSlug, token string) (findingsServer, error) {
	fs := findingsServer{url: serverURL, orgSlug: orgSlug, token: token}
	if fs.url != "" && fs.orgSlug != "" && fs.token != "" {
		return fs, nil
	}
	file, err := credentials.Load()
	if err == nil {
		if p, perr := file.CurrentProfile(); perr == nil {
			if fs.url == "" {
				fs.url = p.Server
			}
			if fs.orgSlug == "" {
				fs.orgSlug = p.DefaultOrg
			}
			if fs.token == "" {
				fs.token = p.Token
			}
		}
	}
	switch {
	case fs.url == "":
		return fs, errors.New("--server is required (or run `concord login`)")
	case fs.orgSlug == "":
		return fs, errors.New("--org-slug is required (or run `concord orgs use <slug>`)")
	case fs.token == "":
		return fs, errors.New("--token is required (or run `concord login`)")
	}
	return fs, nil
}

func newFindingsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "List and manage persistent finding state (suppress, accept, resolve)",
	}
	cmd.AddCommand(newFindingsListCmd())
	cmd.AddCommand(newFindingsShowCmd())
	cmd.AddCommand(newFindingsAcceptCmd())
	cmd.AddCommand(newFindingsReopenCmd())
	cmd.AddCommand(newFindingsDeferCmd())
	cmd.AddCommand(newFindingsResolveCmd())
	cmd.AddCommand(newFindingsFalsePositiveCmd())
	return cmd
}

func newFindingsListCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		statusFilter, frameworkFilter []string
		format string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List persistent findings (across all runs)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			for _, s := range statusFilter {
				q.Add("status", s)
			}
			for _, f := range frameworkFilter {
				q.Add("framework", f)
			}
			rows, err := getFindings(cmd.Context(), fs, q)
			if err != nil {
				return err
			}
			return printFindings(os.Stdout, rows, format)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringSliceVar(&statusFilter, "status", nil, "Filter by lifecycle status (repeatable)")
	cmd.Flags().StringSliceVar(&frameworkFilter, "framework", nil, "Filter by framework id (repeatable)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	return cmd
}

func newFindingsShowCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		showEvents bool
	)
	cmd := &cobra.Command{
		Use:   "show <finding-id>",
		Short: "Show one finding plus optional history",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			var f findingDTO
			if err := apiGet(cmd.Context(), fs, "/v1/orgs/"+fs.orgSlug+"/finding-state/"+args[0], &f); err != nil {
				return err
			}
			printOneFinding(os.Stdout, f)
			if showEvents {
				var events []findingEventDTO
				if err := apiGet(cmd.Context(), fs, "/v1/orgs/"+fs.orgSlug+"/finding-state/"+args[0]+"/events", &events); err != nil {
					return err
				}
				printEvents(os.Stdout, events)
			}
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().BoolVar(&showEvents, "events", false, "Also print the append-only history")
	return cmd
}

func newFindingsAcceptCmd() *cobra.Command   { return newFindingsTransitionCmd("accept", "accepted_risk", "Accept risk on a finding for a bounded window", true) }
func newFindingsDeferCmd() *cobra.Command    { return newFindingsTransitionCmd("defer", "deferred", "Defer a finding for a bounded window (similar to accept but no risk assessment yet)", true) }
func newFindingsReopenCmd() *cobra.Command   { return newFindingsTransitionCmd("reopen", "open", "Reopen a finding previously accepted/deferred/resolved/false-positive", false) }
func newFindingsResolveCmd() *cobra.Command  { return newFindingsTransitionCmd("resolve", "resolved", "Mark a finding as resolved (manual override; auto-resolve usually handles this)", false) }
func newFindingsFalsePositiveCmd() *cobra.Command {
	return newFindingsTransitionCmd("false-positive", "false_positive", "Mark a finding as a false positive (suppressed forever)", false)
}

func newFindingsTransitionCmd(name, status, short string, wantsExpiry bool) *cobra.Command {
	var (
		serverURL, orgSlug, token string
		justification string
		until         string
	)
	cmd := &cobra.Command{
		Use:   name + " <finding-id>",
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			body := map[string]any{"status": status}
			if justification != "" {
				body["justification"] = justification
			}
			if wantsExpiry && until != "" {
				t, err := parseUntil(until)
				if err != nil {
					return err
				}
				body["suppressed_until"] = t.Format(time.RFC3339)
			}
			var updated findingDTO
			if err := apiPatch(cmd.Context(), fs, "/v1/orgs/"+fs.orgSlug+"/finding-state/"+args[0], body, &updated); err != nil {
				return err
			}
			fmt.Fprintf(os.Stdout, "%s → %s\n", updated.ID, updated.Status)
			if updated.SuppressedUntil != nil {
				fmt.Fprintf(os.Stdout, "  suppressed until: %s\n", updated.SuppressedUntil.Format(time.RFC3339))
			}
			return nil
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringVar(&justification, "justification", "", "Human-readable reason recorded on the finding event")
	if wantsExpiry {
		cmd.Flags().StringVar(&until, "until", "", "Suppression expiry (RFC3339 timestamp or duration like 30d / 8w / 6mo)")
	}
	return cmd
}

func addFindingsServerFlags(cmd *cobra.Command, serverURL, orgSlug, token *string) {
	cmd.Flags().StringVar(serverURL, "server", "", "Concord server URL (default: from `concord login` profile)")
	cmd.Flags().StringVar(orgSlug, "org-slug", "", "Org slug (default: from `concord orgs use`)")
	cmd.Flags().StringVar(token, "token", "", "API token (default: from `concord login` profile)")
}

func getFindings(ctx context.Context, fs findingsServer, q url.Values) ([]findingDTO, error) {
	path := "/v1/orgs/" + fs.orgSlug + "/finding-state"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out []findingDTO
	if err := apiGet(ctx, fs, path, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func apiGet(ctx context.Context, fs findingsServer, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(fs.url, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+fs.token)
	return doJSON(req, out)
}

func apiPatch(ctx context.Context, fs findingsServer, path string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch,
		strings.TrimRight(fs.url, "/")+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+fs.token)
	req.Header.Set("Content-Type", "application/json")
	return doJSON(req, out)
}

func doJSON(req *http.Request, out any) error {
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func printFindings(w io.Writer, rows []findingDTO, format string) error {
	if format == "json" {
		return json.NewEncoder(w).Encode(rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "no findings")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tFRAMEWORK\tCONTROL\tEVAL\tSTATUS\tSUPPRESSED-UNTIL")
	for _, f := range rows {
		expiry := "—"
		if f.SuppressedUntil != nil {
			expiry = f.SuppressedUntil.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.ID, f.Framework, f.ControlID, f.CurrentEvaluationStatus, f.Status, expiry)
	}
	return tw.Flush()
}

func printOneFinding(w io.Writer, f findingDTO) {
	fmt.Fprintf(w, "Finding   : %s\n", f.ID)
	fmt.Fprintf(w, "Control   : %s (%s, severity=%s)\n", f.ControlID, f.Framework, f.Severity)
	fmt.Fprintf(w, "Eval      : %s (last seen %s)\n", f.CurrentEvaluationStatus, f.LastSeenAt.Format(time.RFC3339))
	fmt.Fprintf(w, "Status    : %s\n", f.Status)
	if f.SuppressedUntil != nil {
		fmt.Fprintf(w, "Suppressed: until %s\n", f.SuppressedUntil.Format(time.RFC3339))
	}
	if f.Justification != "" {
		fmt.Fprintf(w, "Reason    : %s\n", f.Justification)
	}
	if len(f.LastMessages) > 0 {
		fmt.Fprintln(w, "Messages  :")
		for _, m := range f.LastMessages {
			fmt.Fprintf(w, "  - %s\n", m)
		}
	}
}

func printEvents(w io.Writer, events []findingEventDTO) {
	fmt.Fprintln(w, "\nHistory:")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "OCCURRED\tKIND\tFROM\tTO\tACTOR\tJUSTIFICATION")
	for _, e := range events {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			e.OccurredAt.Format(time.RFC3339), e.EventKind,
			dashIfEmpty(e.FromStatus), dashIfEmpty(e.ToStatus),
			e.ActorKind, e.Justification,
		)
	}
	_ = tw.Flush()
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// parseUntil accepts an RFC3339 timestamp or a friendly duration like
// "30d", "8w", "6mo", "1y".
func parseUntil(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().UTC().Add(d), nil
	}
	// Friendly suffixes Go's time.ParseDuration doesn't accept.
	var n int
	var unit string
	if _, err := fmt.Sscanf(s, "%d%s", &n, &unit); err != nil {
		return time.Time{}, fmt.Errorf("cannot parse --until %q (use RFC3339 or 30d / 8w / 6mo / 1y)", s)
	}
	switch unit {
	case "d":
		return time.Now().UTC().AddDate(0, 0, n), nil
	case "w":
		return time.Now().UTC().AddDate(0, 0, n*7), nil
	case "mo":
		return time.Now().UTC().AddDate(0, n, 0), nil
	case "y":
		return time.Now().UTC().AddDate(n, 0, 0), nil
	}
	return time.Time{}, fmt.Errorf("unknown duration suffix %q in %q", unit, s)
}
