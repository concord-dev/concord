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
