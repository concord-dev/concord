// Package report renders findings to stdout.
package report

import (
	"fmt"
	"io"

	"github.com/fatih/color"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Summary captures aggregate counts across findings.
type Summary struct {
	Pass int
	Fail int
	Err  int
	Warn int
}

// Print writes findings as a human-readable summary to w.
func Print(w io.Writer, findings []apiv1.Finding) Summary {
	var s Summary
	for _, f := range findings {
		s.Warn += len(f.Warnings)
		switch f.Status {
		case apiv1.StatusPass:
			s.Pass++
			fmt.Fprintf(w, "  %s  %-22s %s  (%dms)\n",
				color.GreenString("✔"), f.ControlID, f.Title, f.DurationMs)
			for _, m := range f.Warnings {
				fmt.Fprintf(w, "     %s %s\n", color.YellowString("⚠"), m)
			}
		case apiv1.StatusFail:
			s.Fail++
			fmt.Fprintf(w, "  %s  %-22s %s  (%dms)\n",
				color.RedString("✖"), f.ControlID, f.Title, f.DurationMs)
			for _, m := range f.Messages {
				fmt.Fprintf(w, "     %s %s\n", color.RedString("└"), m)
			}
			for _, m := range f.Warnings {
				fmt.Fprintf(w, "     %s %s\n", color.YellowString("⚠"), m)
			}
		case apiv1.StatusError:
			s.Err++
			fmt.Fprintf(w, "  %s  %-22s %s  (error)\n",
				color.YellowString("!"), f.ControlID, f.Title)
			for _, m := range f.Messages {
				fmt.Fprintf(w, "     %s %s\n", color.YellowString("└"), m)
			}
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s passed · %s failed · %s errored · %s warnings\n",
		color.GreenString("%d", s.Pass),
		color.RedString("%d", s.Fail),
		color.YellowString("%d", s.Err),
		color.YellowString("%d", s.Warn))
	return s
}
