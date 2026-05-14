package report

import (
	"fmt"
	"io"
	"time"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// MarkdownRenderer emits an auditor-friendly audit pack.
type MarkdownRenderer struct{}

// Render implements Renderer.
func (MarkdownRenderer) Render(w io.Writer, findings []apiv1.Finding) (Summary, error) {
	s := Summarize(findings)
	now := time.Now().UTC().Format(time.RFC3339)

	fmt.Fprintln(w, "# Concord Assessment Results")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "**Generated:** %s\n\n", now)
	fmt.Fprintf(w, "**Summary:** %d passed · %d failed · %d errored · %d warnings\n\n", s.Pass, s.Fail, s.Err, s.Warn)
	fmt.Fprintln(w, "---")
	fmt.Fprintln(w)

	for _, f := range findings {
		statusBadge := ""
		switch f.Status {
		case apiv1.StatusPass:
			statusBadge = "✅ PASS"
		case apiv1.StatusFail:
			statusBadge = "❌ FAIL"
		case apiv1.StatusError:
			statusBadge = "⚠️ ERROR"
		}
		fmt.Fprintf(w, "## %s — %s\n\n", f.ControlID, f.Title)
		fmt.Fprintf(w, "- **Framework:** %s\n", f.Framework)
		fmt.Fprintf(w, "- **Severity:** %s\n", f.Severity)
		fmt.Fprintf(w, "- **Status:** %s\n", statusBadge)
		fmt.Fprintf(w, "- **Evaluated:** %s (%dms)\n\n", f.EvaluatedAt.Format(time.RFC3339), f.DurationMs)

		if len(f.Messages) > 0 {
			fmt.Fprintln(w, "**Findings:**")
			for _, m := range f.Messages {
				fmt.Fprintf(w, "- %s\n", m)
			}
			fmt.Fprintln(w)
		}
		if len(f.Warnings) > 0 {
			fmt.Fprintln(w, "**Warnings:**")
			for _, m := range f.Warnings {
				fmt.Fprintf(w, "- %s\n", m)
			}
			fmt.Fprintln(w)
		}
	}
	return s, nil
}
