package report

import (
	"fmt"
	"html/template"
	"io"
	"sort"
	"time"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// TrustPortalRenderer produces a self-contained, public-facing HTML page
// suitable for hosting at trust.<your-domain>. Internal evidence (deny
// messages, bucket names, user emails) is deliberately omitted — only
// control ID, title, framework, and pass/fail badge are surfaced.
type TrustPortalRenderer struct {
	OrgName string
}

// Render writes the trust-portal HTML to w.
func (r TrustPortalRenderer) Render(w io.Writer, findings []apiv1.Finding) (Summary, error) {
	s := Summarize(findings)

	byFramework := make(map[string][]apiv1.Finding)
	for _, f := range findings {
		byFramework[f.Framework] = append(byFramework[f.Framework], f)
	}
	frameworks := make([]string, 0, len(byFramework))
	for fw := range byFramework {
		frameworks = append(frameworks, fw)
	}
	sort.Strings(frameworks)
	for _, fws := range byFramework {
		sort.Slice(fws, func(i, j int) bool { return fws[i].ControlID < fws[j].ControlID })
	}

	orgName := r.OrgName
	if orgName == "" {
		orgName = "Your Organization"
	}

	data := struct {
		OrgName       string
		GeneratedAt   string
		Summary       Summary
		TotalControls int
		ByFramework   map[string][]apiv1.Finding
		Frameworks    []string
	}{
		OrgName:       orgName,
		GeneratedAt:   time.Now().UTC().Format("January 2, 2006 15:04 MST"),
		Summary:       s,
		TotalControls: len(findings),
		ByFramework:   byFramework,
		Frameworks:    frameworks,
	}
	if err := trustPortalTemplate.Execute(w, data); err != nil {
		return s, fmt.Errorf("rendering trust portal: %w", err)
	}
	return s, nil
}

var trustPortalTemplate = template.Must(template.New("trust").Funcs(template.FuncMap{
	"frameworkName": frameworkDisplayName,
	"statusClass":   statusCSSClass,
	"statusLabel":   statusUserLabel,
}).Parse(trustPortalHTML))

func frameworkDisplayName(slug string) string {
	switch slug {
	case "soc2":
		return "SOC 2 Type I"
	case "iso42001":
		return "ISO 42001"
	case "cis-aws":
		return "CIS AWS Foundations"
	case "eu-ai-act":
		return "EU AI Act"
	}
	return slug
}

func statusCSSClass(s apiv1.FindingStatus) string {
	switch s {
	case apiv1.StatusPass:
		return "pass"
	case apiv1.StatusFail:
		return "fail"
	case apiv1.StatusError:
		return "error"
	}
	return "skip"
}

func statusUserLabel(s apiv1.FindingStatus) string {
	switch s {
	case apiv1.StatusPass:
		return "Compliant"
	case apiv1.StatusFail:
		return "Gap identified"
	case apiv1.StatusError:
		return "Unable to verify"
	}
	return string(s)
}

const trustPortalHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ .OrgName }} — Trust & Compliance</title>
<style>
*, *::before, *::after { box-sizing: border-box; }
body {
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  background: #fafafa; color: #18181b; margin: 0;
}
.container { max-width: 960px; margin: 0 auto; padding: 48px 24px; }
header { margin-bottom: 32px; }
.brand { font-size: 12px; text-transform: uppercase; letter-spacing: 1px; color: #71717a; }
h1 { font-size: 28px; margin: 4px 0 0; font-weight: 600; letter-spacing: -0.5px; }
.subtitle { color: #52525b; margin-top: 6px; font-size: 15px; }
.meta { margin-top: 12px; color: #71717a; font-size: 12px; }
.summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 32px 0; }
@media (max-width: 600px) { .summary { grid-template-columns: repeat(2, 1fr); } }
.stat { background: white; border: 1px solid #e4e4e7; border-radius: 8px; padding: 16px; }
.stat-value { font-size: 30px; font-weight: 600; line-height: 1; }
.stat-label { font-size: 11px; color: #71717a; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 6px; }
.stat.pass .stat-value { color: #16a34a; }
.stat.fail .stat-value { color: #dc2626; }
.stat.error .stat-value { color: #ca8a04; }
.framework { margin-bottom: 36px; }
.framework-header {
  display: flex; align-items: baseline; justify-content: space-between;
  border-bottom: 1px solid #e4e4e7; padding-bottom: 10px; margin-bottom: 12px;
}
.framework-header h2 { font-size: 18px; margin: 0; font-weight: 600; }
.framework-count { font-size: 12px; color: #71717a; }
.controls { display: flex; flex-direction: column; gap: 6px; }
.control {
  display: flex; align-items: center; justify-content: space-between;
  background: white; border: 1px solid #e4e4e7; border-radius: 6px;
  padding: 12px 14px;
}
.control-meta { flex: 1; min-width: 0; }
.control-id { font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 11px; color: #71717a; }
.control-title { margin-top: 2px; font-size: 14px; color: #18181b; }
.badge {
  display: inline-block; padding: 3px 10px; border-radius: 999px; font-size: 11px;
  font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
  flex-shrink: 0; margin-left: 12px;
}
.badge.pass { background: #dcfce7; color: #166534; }
.badge.fail { background: #fee2e2; color: #991b1b; }
.badge.error { background: #fef3c7; color: #854d0e; }
footer {
  margin-top: 56px; padding-top: 16px; border-top: 1px solid #e4e4e7;
  color: #71717a; font-size: 11px; line-height: 1.6;
}
footer a { color: #52525b; text-decoration: none; }
footer a:hover { text-decoration: underline; }
</style>
</head>
<body>
<div class="container">
  <header>
    <div class="brand">Trust & Compliance</div>
    <h1>{{ .OrgName }}</h1>
    <p class="subtitle">Continuously evaluated against {{ len .Frameworks }} compliance frameworks.</p>
    <p class="meta">Last evaluated: {{ .GeneratedAt }}</p>
  </header>

  <div class="summary">
    <div class="stat pass">
      <div class="stat-value">{{ .Summary.Pass }}</div>
      <div class="stat-label">Compliant</div>
    </div>
    <div class="stat fail">
      <div class="stat-value">{{ .Summary.Fail }}</div>
      <div class="stat-label">Gaps identified</div>
    </div>
    <div class="stat error">
      <div class="stat-value">{{ .Summary.Err }}</div>
      <div class="stat-label">Unable to verify</div>
    </div>
    <div class="stat">
      <div class="stat-value">{{ .TotalControls }}</div>
      <div class="stat-label">Total controls</div>
    </div>
  </div>

  {{ range .Frameworks }}
  <section class="framework">
    <div class="framework-header">
      <h2>{{ frameworkName . }}</h2>
      <span class="framework-count">{{ len (index $.ByFramework .) }} controls</span>
    </div>
    <div class="controls">
      {{ range index $.ByFramework . }}
      <div class="control">
        <div class="control-meta">
          <div class="control-id">{{ .ControlID }}</div>
          <div class="control-title">{{ .Title }}</div>
        </div>
        <span class="badge {{ statusClass .Status }}">{{ statusLabel .Status }}</span>
      </div>
      {{ end }}
    </div>
  </section>
  {{ end }}

  <footer>
    Compliance evidence is collected automatically from infrastructure on each evaluation cycle.
    For details on individual controls or audit-ready evidence, contact security@{{ .OrgName }}.<br>
    Generated by <a href="https://concord.dev">Concord</a> — open-source compliance-as-code.
  </footer>
</div>
</body>
</html>
`
