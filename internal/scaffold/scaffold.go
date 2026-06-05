package scaffold

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type Result struct {
	Written []string
	Skipped []string
}

func Frameworks(src fs.FS, destDir string, allowed []string, force bool) (Result, error) {
	allow := toSet(allowed)
	var r Result

	walkErr := fs.WalkDir(src, "controls/frameworks", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel := strings.TrimPrefix(p, "controls/")
		if !frameworkAllowed(rel, allow) {
			return nil
		}

		destPath := filepath.Join(destDir, rel)
		if !force {
			if _, statErr := os.Stat(destPath); statErr == nil {
				r.Skipped = append(r.Skipped, destPath)
				return nil
			}
		}

		if err := copyEmbedFile(src, p, destPath); err != nil {
			return fmt.Errorf("copying %s: %w", p, err)
		}
		r.Written = append(r.Written, destPath)
		return nil
	})
	if walkErr != nil {
		return r, walkErr
	}
	return r, nil
}

type UpgradeResult struct {
	New       []string
	Modified  []string
	Unchanged []string
}

func Upgrade(src fs.FS, destDir string, allowed []string, apply bool) (UpgradeResult, error) {
	allow := toSet(allowed)
	var r UpgradeResult

	walkErr := fs.WalkDir(src, "controls/frameworks", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel := strings.TrimPrefix(p, "controls/")
		if !frameworkAllowed(rel, allow) {
			return nil
		}

		embedContent, err := fs.ReadFile(src, p)
		if err != nil {
			return err
		}

		destPath := filepath.Join(destDir, rel)
		diskContent, err := os.ReadFile(destPath)
		switch {
		case os.IsNotExist(err):
			r.New = append(r.New, destPath)
			if apply {
				if err := writeBytes(destPath, embedContent); err != nil {
					return err
				}
			}
		case err != nil:
			return err
		case bytes.Equal(embedContent, diskContent):
			r.Unchanged = append(r.Unchanged, destPath)
		default:
			r.Modified = append(r.Modified, destPath)
			if apply {
				if err := writeBytes(destPath, embedContent); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return r, walkErr
}

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
}

// ControlResult records the four files written by Control.
type ControlResult struct {
	YAML     string
	Rego     string
	PassFix  string
	FailFix  string
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
	yamlBody := renderControlYAML(in, slug, title, framework, severity, author, description, regoPackage)
	regoBody := renderControlRego(regoPackage, in.ID, evidenceKey)
	passFixture := renderControlFixture(evidenceKey, true)
	failFixture := renderControlFixture(evidenceKey, false)

	for path, body := range map[string]string{
		r.YAML:    yamlBody,
		r.Rego:    regoBody,
		r.PassFix: passFixture,
		r.FailFix: failFixture,
	} {
		if err := writeBytes(path, []byte(body)); err != nil {
			return r, fmt.Errorf("writing %s: %w", path, err)
		}
	}
	return r, nil
}

func renderControlYAML(in ControlInput, slug, title, framework, severity, author, description, regoPackage string) string {
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
      source: TODO
      type: TODO
      fixture: ../tests/fixtures/%s-pass.json

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
`, in.ID, slug, title, framework, severity, author, description, slug, slug, regoPackage, slug, slug)
}

func renderControlRego(pkg, controlID, evidenceKey string) string {
	return fmt.Sprintf(`package %s

import rego.v1

# %s — TODO: describe the rule.
# input.%s is the normalized evidence payload from the control's collector.

deny contains msg if {
    not input.%s
    msg := "no evidence collected for %s"
}

deny contains msg if {
    some item in input.%s.items
    not item.compliant
    msg := sprintf("%s: %%q is non-compliant", [item.id])
}
`, pkg, controlID, evidenceKey, evidenceKey, controlID, evidenceKey, controlID)
}

func renderControlFixture(slug string, pass bool) string {
	if pass {
		return fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "items": [
      { "id": "example-1", "compliant": true }
    ]
  }
}
`, slug)
	}
	return fmt.Sprintf(`{
  "%s": {
    "fetched_at": "2026-01-01T00:00:00Z",
    "items": [
      { "id": "example-1", "compliant": false }
    ]
  }
}
`, slug)
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

func copyEmbedFile(src fs.FS, srcPath, destPath string) error {
	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return err
	}
	in, err := src.Open(srcPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func toSet(values []string) map[string]bool {
	if len(values) == 0 {
		return nil
	}
	m := make(map[string]bool, len(values))
	for _, v := range values {
		m[v] = true
	}
	return m
}

func frameworkAllowed(rel string, allow map[string]bool) bool {
	if len(allow) == 0 {
		return true
	}
	parts := strings.SplitN(rel, "/", 3)
	if len(parts) < 2 {
		return false
	}
	return allow[parts[1]]
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
