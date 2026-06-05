package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

func newAuditPacketCmd() *cobra.Command {
	var (
		serverURL, orgSlug, token string
		frameworks                []string
		period, since, until      string
		out                       string
	)
	cmd := &cobra.Command{
		Use:   "audit-packet",
		Short: "Download a zipped audit packet (findings + remediations + risks + evidence)",
		RunE: func(cmd *cobra.Command, args []string) error {
			fs, err := resolveFindingsServer(serverURL, orgSlug, token)
			if err != nil {
				return err
			}
			q := url.Values{}
			for _, f := range frameworks {
				if f != "" {
					q.Add("framework", f)
				}
			}
			if period != "" {
				s, u, err := parsePeriod(period)
				if err != nil {
					return err
				}
				q.Set("since", s.Format(time.RFC3339))
				q.Set("until", u.Format(time.RFC3339))
			}
			if since != "" {
				t, err := time.Parse(time.RFC3339, since)
				if err != nil {
					return fmt.Errorf("--since must be RFC3339: %w", err)
				}
				q.Set("since", t.Format(time.RFC3339))
			}
			if until != "" {
				t, err := time.Parse(time.RFC3339, until)
				if err != nil {
					return fmt.Errorf("--until must be RFC3339: %w", err)
				}
				q.Set("until", t.Format(time.RFC3339))
			}
			path := "/v1/orgs/" + fs.orgSlug + "/audit-package"
			if len(q) > 0 {
				path += "?" + q.Encode()
			}
			return downloadAuditPacket(cmd.Context(), fs, path, out)
		},
	}
	addFindingsServerFlags(cmd, &serverURL, &orgSlug, &token)
	cmd.Flags().StringSliceVar(&frameworks, "framework", nil, "Restrict findings/remediations/risks to these frameworks (repeatable)")
	cmd.Flags().StringVar(&period, "period", "", "Period shorthand (e.g. 2026Q1, 2026)")
	cmd.Flags().StringVar(&since, "since", "", "Window start (RFC3339)")
	cmd.Flags().StringVar(&until, "until", "", "Window end (RFC3339)")
	cmd.Flags().StringVarP(&out, "output", "o", "", "Output file path (required)")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

func downloadAuditPacket(ctx context.Context, fs findingsServer, path, out string) error {
	if out == "" {
		return fmt.Errorf("--output is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(fs.url, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+fs.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "wrote %s (%d bytes)\n", out, n)
	return nil
}

// parsePeriod accepts "2026Q1" / "2026Q2" / ... / "2026" and returns the
// half-open [since, until) window in UTC.
func parsePeriod(s string) (time.Time, time.Time, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if len(s) == 4 {
		var year int
		if _, err := fmt.Sscanf(s, "%d", &year); err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("invalid period %q (want e.g. 2026 or 2026Q1)", s)
		}
		return time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC),
			time.Date(year+1, 1, 1, 0, 0, 0, 0, time.UTC), nil
	}
	var year, q int
	if _, err := fmt.Sscanf(s, "%dQ%d", &year, &q); err != nil || q < 1 || q > 4 {
		return time.Time{}, time.Time{}, fmt.Errorf("invalid period %q (want e.g. 2026Q1)", s)
	}
	startMonth := time.Month(1 + (q-1)*3)
	endMonth := startMonth + 3
	endYear := year
	if endMonth > 12 {
		endMonth -= 12
		endYear++
	}
	return time.Date(year, startMonth, 1, 0, 0, 0, 0, time.UTC),
		time.Date(endYear, endMonth, 1, 0, 0, 0, 0, time.UTC), nil
}
