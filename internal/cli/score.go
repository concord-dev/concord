package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

type complianceScoreDTO struct {
	Framework          string     `json:"framework"`
	Score              float64    `json:"score"`
	PassingControls    int        `json:"passing_controls"`
	FailingControls    int        `json:"failing_controls"`
	WarningControls    int        `json:"warning_controls"`
	TotalInScope       int        `json:"total_in_scope"`
	OpenFindings       int        `json:"open_findings"`
	SuppressedFindings int        `json:"suppressed_findings"`
	LastRunAt          *time.Time `json:"last_run_at,omitempty"`
	RecomputedAt       time.Time  `json:"recomputed_at"`
}

func newScoreCmd() *cobra.Command {
	var (
		serverURL, orgSlug, projectSlug, token string
		framework                              string
		format                                 string
		recompute                              bool
	)
	cmd := &cobra.Command{
		Use:   "score",
		Short: "Show the compliance readiness score for a project",
		Long: `Read the persisted compliance score for one framework, or the
list for all frameworks when --framework is unset. --recompute forces
a fresh scan of finding state before responding.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveServer(serverURL, orgSlug, projectSlug, token)
			if err != nil {
				return err
			}
			endpoint := fs.url + fs.projectBase() + "/compliance-score"
			q := url.Values{}
			if framework != "" {
				q.Set("framework", framework)
			}
			if recompute {
				q.Set("recompute", "true")
			}
			if len(q) > 0 {
				endpoint += "?" + q.Encode()
			}
			req, _ := http.NewRequestWithContext(cmd.Context(), http.MethodGet, endpoint, nil)
			req.Header.Set("Authorization", "Bearer "+fs.token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode < 200 || resp.StatusCode >= 300 {
				return fmt.Errorf("score %d: %s", resp.StatusCode, body)
			}
			return renderScore(os.Stdout, body, framework, format)
		},
	}
	cmd.Flags().StringVar(&serverURL, "server", "", "Concord platform base URL")
	cmd.Flags().StringVar(&orgSlug, "org-slug", "", "org slug")
	cmd.Flags().StringVar(&projectSlug, "project", "", `project slug (default: profile's default project, then "default")`)
	cmd.Flags().StringVar(&token, "token", "", "API token")
	cmd.Flags().StringVar(&framework, "framework", "", "Show only one framework (e.g. soc2)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json")
	cmd.Flags().BoolVar(&recompute, "recompute", false, "Recompute the score before returning")
	return cmd
}

func renderScore(w io.Writer, body []byte, framework, format string) error {
	if format == "json" {
		_, err := w.Write(body)
		return err
	}
	if framework != "" {
		var s complianceScoreDTO
		if err := json.Unmarshal(body, &s); err != nil {
			return err
		}
		renderOneScore(w, &s)
		return nil
	}
	var rows []complianceScoreDTO
	if err := json.Unmarshal(body, &rows); err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(w, "no compliance score recorded yet — push a run first")
		return nil
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Framework < rows[j].Framework })
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FRAMEWORK\tSCORE\tPASS\tFAIL\tIN SCOPE\tOPEN\tSUPPRESSED\tLAST RUN")
	for _, s := range rows {
		last := "—"
		if s.LastRunAt != nil {
			last = s.LastRunAt.Format(time.RFC3339)
		}
		fmt.Fprintf(tw, "%s\t%5.1f%%\t%d\t%d\t%d\t%d\t%d\t%s\n",
			s.Framework, s.Score*100, s.PassingControls, s.FailingControls,
			s.TotalInScope, s.OpenFindings, s.SuppressedFindings, last)
	}
	return tw.Flush()
}

func renderOneScore(w io.Writer, s *complianceScoreDTO) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "framework\t%s\n", s.Framework)
	fmt.Fprintf(tw, "score\t%.1f%%\n", s.Score*100)
	fmt.Fprintf(tw, "passing\t%d\n", s.PassingControls)
	fmt.Fprintf(tw, "failing\t%d\n", s.FailingControls)
	fmt.Fprintf(tw, "warning\t%d\n", s.WarningControls)
	fmt.Fprintf(tw, "in_scope\t%d\n", s.TotalInScope)
	fmt.Fprintf(tw, "open_findings\t%d\n", s.OpenFindings)
	fmt.Fprintf(tw, "suppressed_findings\t%d\n", s.SuppressedFindings)
	if s.LastRunAt != nil {
		fmt.Fprintf(tw, "last_run_at\t%s\n", s.LastRunAt.Format(time.RFC3339))
	}
	fmt.Fprintf(tw, "recomputed_at\t%s\n", s.RecomputedAt.Format(time.RFC3339))
	tw.Flush()
}
