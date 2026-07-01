package scaffold

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/concord-dev/concord/internal/scaffold/lib"
)

func writeBytes(path string, content []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, content, 0o644)
}

func Config(destPath string, force bool) (bool, error) {
	if !force {
		if _, err := os.Stat(destPath); err == nil {
			return false, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return false, err
	}
	return true, os.WriteFile(destPath, []byte(configTemplate), 0o644)
}

// ControlInput specifies the placeholder values for a `concord scaffold control` invocation.
type ControlInput struct {
	Pack        string
	ID          string
	Title       string
	Framework   string
	Severity    string
	Author      string
	Description string
	Template    ControlTemplate
}

// ControlResult records the files written by Control.
type ControlResult struct {
	YAML     string
	Rego     string
	PassFix  string
	FailFix  string
	LibFiles []string
}

// Control writes a control YAML + Rego skeleton + pass/fail fixture pair under destDir.
// destDir is treated as the control-pack root; the four files land at:
//
//	controls/<id>.yaml
//	policies/<slug>.rego
//	tests/fixtures/<slug>-pass.json
//	tests/fixtures/<slug>-fail.json
//
// Returns an error if any target file already exists and force is false.
func Control(destDir string, in ControlInput, force bool) (ControlResult, error) {
	var r ControlResult
	if strings.TrimSpace(in.ID) == "" {
		return r, fmt.Errorf("control id is required")
	}
	if strings.TrimSpace(in.Pack) == "" {
		return r, fmt.Errorf("pack name is required (used as the rego package prefix)")
	}

	slug := regoSlug(in.ID)
	title := in.Title
	if title == "" {
		title = in.ID
	}
	framework := in.Framework
	if framework == "" {
		framework = in.Pack
	}
	severity := in.Severity
	if severity == "" {
		severity = "medium"
	}
	author := in.Author
	if author == "" {
		author = "concord-dev"
	}
	description := in.Description
	if description == "" {
		description = fmt.Sprintf("TODO: describe what %s enforces.", in.ID)
	}

	r.YAML = filepath.Join(destDir, "controls", slug+".yaml")
	r.Rego = filepath.Join(destDir, "policies", slug+".rego")
	r.PassFix = filepath.Join(destDir, "tests", "fixtures", slug+"-pass.json")
	r.FailFix = filepath.Join(destDir, "tests", "fixtures", slug+"-fail.json")

	targets := []string{r.YAML, r.Rego, r.PassFix, r.FailFix}
	if !force {
		for _, p := range targets {
			if _, err := os.Stat(p); err == nil {
				return r, fmt.Errorf("destination %s already exists (pass --force to overwrite)", p)
			}
		}
	}

	evidenceKey := regoPackagePiece(slug)
	regoPackage := fmt.Sprintf("concord.%s.%s", regoPackagePiece(in.Pack), evidenceKey)
	parts := partsFor(in.Template, regoPackage, in.ID, evidenceKey)

	yamlBody := renderControlYAMLWithParts(in, slug, title, framework, severity, author, description, regoPackage, parts)

	for path, body := range map[string]string{
		r.YAML:    yamlBody,
		r.Rego:    parts.regoBody,
		r.PassFix: parts.passBody,
		r.FailFix: parts.failBody,
	} {
		if err := writeBytes(path, []byte(body)); err != nil {
			return r, fmt.Errorf("writing %s: %w", path, err)
		}
	}

	libPaths, err := writeLibFiles(destDir, force)
	if err != nil {
		return r, fmt.Errorf("writing rego helper library: %w", err)
	}
	r.LibFiles = libPaths
	return r, nil
}

func renderControlYAMLWithParts(in ControlInput, slug, title, framework, severity, author, description, regoPackage string, parts templateParts) string {
	paramsBlock := ""
	if parts.evidenceParams != "" {
		paramsBlock = "      params:\n" + indentBlock(parts.evidenceParams, "        ") + "\n"
		if strings.Contains(parts.evidenceParams, "    - id:") {
			paramsBlock = parts.evidenceParams + "\n"
		}
	}
	return fmt.Sprintf(`apiVersion: concord.dev/v1
kind: Control

metadata:
  id: %s
  name: %s
  title: %s
  framework: %s
  severity: %s
  tags: []
  owners:
    - team: %s

spec:
  description: |
    %s

  evidence:
    - id: %s
      source: %s
      type: %s
      fixture: ../tests/fixtures/%s-pass.json
%s
  policy:
    engine: rego
    package: %s
    file: ../policies/%s.rego

  remediation:
    runbook: docs/remediation/%s.md
    auto_fix: false
    estimated_effort: 30m

  status: draft
  blocking: false
`, in.ID, slug, title, framework, severity, author, description,
		parts.evidenceID, parts.evidenceSrc, parts.evidenceType, slug,
		paramsBlock, regoPackage, slug, slug)
}

func indentBlock(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, ln := range lines {
		lines[i] = prefix + ln
	}
	return strings.Join(lines, "\n")
}

func writeLibFiles(destDir string, force bool) ([]string, error) {
	files, err := lib.Files()
	if err != nil {
		return nil, err
	}
	var written []string
	for name, body := range files {
		path := filepath.Join(destDir, "policies", "lib", name)
		if !force {
			if _, err := os.Stat(path); err == nil {
				written = append(written, path)
				continue
			}
		}
		if err := writeBytes(path, []byte(body)); err != nil {
			return written, err
		}
		written = append(written, path)
	}
	return written, nil
}

func regoSlug(id string) string {
	s := strings.ToLower(id)
	out := make([]rune, 0, len(s))
	prevDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
			prevDash = false
		case r == '-' || r == '_' || r == '.' || r == ' ':
			if !prevDash && len(out) > 0 {
				out = append(out, '-')
				prevDash = true
			}
		}
	}
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return "control"
	}
	return string(out)
}

func regoPackagePiece(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			out = append(out, r)
		case r == '-' || r == '_' || r == '.' || r == ' ':
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "custom"
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = append([]rune{'_'}, out...)
	}
	return string(out)
}

func GitHubAction(destPath string, force bool) (bool, error) {
	if !force {
		if _, err := os.Stat(destPath); err == nil {
			return false, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return false, err
	}
	return true, os.WriteFile(destPath, []byte(githubActionTemplate), 0o644)
}

const configTemplate = `apiVersion: concord.dev/v1
kind: Config
metadata:
  name: my-repo

controls:
  path: ./controls

  # Override per-control policy parameters here. Each entry below is keyed
  # by control ID and contains parameters the control's Rego policy reads
  # from input._concord.params. Defaults are defined in each .rego file
  # — uncomment to tighten or loosen.
  #
  # params:
  #   SOC2-CC8.1:
  #     min_reviewers: 2
  #   ISO42001-6.1:
  #     max_age_days: 90

# Concord reads CONCORD_GITHUB_TOKEN (preferred) or GITHUB_TOKEN for the
# github collector. For AWS the standard credential chain (env vars,
# ~/.aws/credentials, IAM role) is honored. Set CONCORD_REPO=owner/name
# in env to populate the ${env.CONCORD_REPO} references in shipped controls.
`

const githubActionTemplate = `name: Concord Compliance Check

on:
  pull_request:
  push:
    branches: [main]

jobs:
  concord:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4

      - name: Install Concord
        run: |
          # TODO: replace with release URL once published.
          go install github.com/concord-dev/concord/cmd/concord@latest

      - name: Run Concord checks
        env:
          CONCORD_REPO: ${{ github.repository }}
          CONCORD_GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: concord check --controls ./controls
`
