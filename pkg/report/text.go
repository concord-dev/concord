package report

import (
	"fmt"
	"io"

	"github.com/fatih/color"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type TextRenderer struct{}

func (TextRenderer) Render(w io.Writer, findings []apiv1.Finding) (Summary, error) {
	s := Summarize(findings)
	for _, f := range findings {
		switch f.Status {
		case apiv1.StatusPass:
			fmt.Fprintf(w, "  %s  %-22s %s  (%dms)\n",
				color.GreenString("✔"), f.ControlID, f.Title, f.DurationMs)
			for _, m := range f.Warnings {
				fmt.Fprintf(w, "     %s %s\n", color.YellowString("⚠"), m)
			}
		case apiv1.StatusFail:
			fmt.Fprintf(w, "  %s  %-22s %s  (%dms)\n",
				color.RedString("✖"), f.ControlID, f.Title, f.DurationMs)
			for _, m := range f.Messages {
				fmt.Fprintf(w, "     %s %s\n", color.RedString("└"), m)
			}
			for _, m := range f.Warnings {
				fmt.Fprintf(w, "     %s %s\n", color.YellowString("⚠"), m)
			}
		case apiv1.StatusError:
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
	return s, nil
}
