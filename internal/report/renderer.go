package report

import (
	"fmt"
	"io"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type Summary struct {
	Pass int `json:"pass"`
	Fail int `json:"fail"`
	Err  int `json:"error"`
	Warn int `json:"warnings"`
}

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

type Renderer interface {
	Render(w io.Writer, findings []apiv1.Finding) (Summary, error)
}

type Opts struct {
	OrgName string
}

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
		return TrustPortalRenderer(opts), nil
	default:
		return nil, fmt.Errorf("unknown format %q (want one of text|json|oscal|markdown|trust-portal)", format)
	}
}
