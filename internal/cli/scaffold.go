package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const templateRefBase = "https://github.com/concord-dev/concord-%s-template"

func newPluginScaffoldCmd() *cobra.Command {
	return newScaffoldCmd("plugin", "concord-plugin-template", "Plugin source identifier (e.g. datadog)")
}

func newControlpackScaffoldCmd() *cobra.Command {
	return newScaffoldCmd("controlpack", "concord-controlpack-template", "Framework identifier (e.g. hipaa)")
}

func newFrameworkScaffoldCmd() *cobra.Command {
	return newScaffoldCmd("framework", "concord-framework-template", "Framework identifier (e.g. hipaa)")
}

func newScaffoldCmd(kind, templateRepo, nameHelp string) *cobra.Command {
	var (
		outputDir string
		name      string
		org       string
	)
	cmd := &cobra.Command{
		Use:   "scaffold",
		Short: fmt.Sprintf("Create a new Concord %s repo from concord-dev/%s", kind, templateRepo),
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required (%s)", nameHelp)
			}
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			dest := outputDir
			if dest == "" {
				dest = fmt.Sprintf("./concord-%s-%s", kind, name)
			}
			if _, err := os.Stat(dest); err == nil {
				return fmt.Errorf("destination %s already exists", dest)
			}
			tarURL := fmt.Sprintf("https://codeload.github.com/concord-dev/%s/tar.gz/refs/heads/main", templateRepo)
			if err := fetchAndUnpackTemplate(ctx, tarURL, dest); err != nil {
				return fmt.Errorf("fetching template: %w", err)
			}
			if err := substitutePlaceholders(dest, kind, name, org); err != nil {
				return fmt.Errorf("substituting placeholders: %w", err)
			}
			fmt.Fprintf(os.Stdout, "Scaffolded %s/%s at %s\n", org, name, dest)
			fmt.Fprintln(os.Stdout, "Next steps:")
			fmt.Fprintf(os.Stdout, "  cd %s\n", dest)
			fmt.Fprintln(os.Stdout, "  # edit main.go (for plugins) or pack.yaml (for control packs)")
			fmt.Fprintln(os.Stdout, "  git init && gh repo create ... && git push --tags")
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", nameHelp)
	cmd.Flags().StringVar(&outputDir, "output", "", "Override destination directory")
	cmd.Flags().StringVar(&org, "org", "concord-dev", "GitHub owner that will host the new repo")
	return cmd
}

func fetchAndUnpackTemplate(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: HTTP %d", url, resp.StatusCode)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	return extractTemplateTarball(resp.Body, dest)
}

func substitutePlaceholders(root, kind, name, org string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		s := string(raw)
		s = strings.ReplaceAll(s, "__SOURCE__", name)
		s = strings.ReplaceAll(s, "__FRAMEWORK__", name)
		s = strings.ReplaceAll(s, "__ID__", name)
		s = strings.ReplaceAll(s, "__NAME__", name)
		s = strings.ReplaceAll(s, "__ORG__", org)
		s = strings.ReplaceAll(s, "__TYPE__", "TODO")
		s = strings.ReplaceAll(s, "__SOURCES_CSV__", "TODO")
		s = strings.ReplaceAll(s, "__DESCRIPTION__", fmt.Sprintf("Concord %s for %s.", kind, name))
		s = strings.ReplaceAll(s, "__PLUGIN__", "TODO")
		s = strings.ReplaceAll(s, "__REASON__", "TODO")
		s = strings.ReplaceAll(s, "__AUTHOR__", org)
		s = strings.ReplaceAll(s, "__FRAMEWORK_LABEL__", name)
		if string(raw) != s {
			if err := os.WriteFile(path, []byte(s), info.Mode()); err != nil {
				return err
			}
		}
		return nil
	})
}
