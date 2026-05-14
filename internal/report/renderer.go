// Package report renders findings in human and machine formats.
package report

import (
	"fmt"
	"io"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Summary captures aggregate counts across findings.
type Summary struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Err  int `json:"error"`
	Warn int `json:"warnings"`
}

// Summarize returns a Summary for findings without rendering anything.
func Summarize(findings []apiv1.Finding) Summary {
	var s Summary
	for _, f := range findings {
		s.Warn += len(f.Warnings)
		switch f.Status {
		case apiv1.StatusPass:
			s.Pass++
		case apiv1.StatusFail:
			s.Fail++
		case apiv1.StatusError:
			s.Err++
		}
	}
	return s
}

// Renderer formats a set of findings to a writer and returns the aggregate Summary.
type Renderer interface {
	Render(w io.Writer, findings []apiv1.Finding) (Summary, error)
}

// Opts carries renderer configuration that doesn't fit on the Renderer interface
// itself (e.g., org name for the public trust portal).
type Opts struct {
	OrgName string
}

// RendererFor returns the renderer for the named format.
// "" / "text" → coloured TTY output; "json" / "oscal" / "markdown" / "md" →
// machine or doc output; "trust-portal" → public-facing HTML page.
func RendererFor(format string, opts Opts) (Renderer, error) {
	switch format {
	case "", "text":
		return TextRenderer{}, nil
	case "json":
		return JSONRenderer{}, nil
	case "oscal":
		return OSCALRenderer{}, nil
	case "markdown", "md":
		return MarkdownRenderer{}, nil
	case "trust-portal":
		return TrustPortalRenderer{OrgName: opts.OrgName}, nil
	default:
		return nil, fmt.Errorf("unknown format %q (want one of text|json|oscal|markdown|trust-portal)", format)
	}
}
