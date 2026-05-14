package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/config"
	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/policy"
	"github.com/concord-dev/concord/internal/report"
	"github.com/concord-dev/concord/internal/runner"
)

func newCheckCmd() *cobra.Command {
	var (
		controlsDir  string
		configPath   string
		fixturesOnly bool
		format       string
		outputPath   string
		quiet        bool
	)
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Evaluate compliance controls against collected evidence",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			renderer, err := report.RendererFor(format, report.Opts{OrgName: cfg.Metadata.Name})
			if err != nil {
				return err
			}

			loaded, err := controls.Load(controlsDir)
			if err != nil {
				return fmt.Errorf("loading controls: %w", err)
			}
			if len(loaded) == 0 {
				return fmt.Errorf("no controls found in %s", controlsDir)
			}

			reg := buildRegistry(fixturesOnly)
			if !quiet {
				describeMode(os.Stderr, reg, fixturesOnly)
				fmt.Fprintf(os.Stderr, "Checking %d control(s)...\n\n", len(loaded))
			}

			r := runner.New(policy.New(), reg).SetParams(cfg.Controls.Params)
			findings := r.RunAll(context.Background(), loaded)

			out, closeFn, err := openOutput(outputPath)
			if err != nil {
				return err
			}
			defer closeFn()

			summary, err := renderer.Render(out, findings)
			if err != nil {
				return fmt.Errorf("rendering: %w", err)
			}

			if summary.Fail > 0 || summary.Err > 0 {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&controlsDir, "controls", "./controls", "Path to controls directory")
	cmd.Flags().StringVar(&configPath, "config", "./concord.yaml", "Path to concord.yaml")
	cmd.Flags().BoolVar(&fixturesOnly, "fixtures", false, "Force fixture-only mode (skip live collectors)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text|json|oscal|markdown|trust-portal")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Write findings to this file (default: stdout)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress prelude (Mode + Checking lines)")
	return cmd
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "" {
		return os.Stdout, func() {}, nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, fmt.Errorf("creating output dir: %w", err)
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("creating %s: %w", path, err)
	}
	return f, func() { _ = f.Close() }, nil
}

func buildRegistry(fixturesOnly bool) *evidence.Registry {
	reg := evidence.NewRegistry()
	if fixturesOnly {
		reg.SetFixturesOnly(true)
		return reg
	}
	if token := githubToken(); token != "" {
		reg.Register("github", evidence.NewGitHubCollector(token))
	}
	if hasAWSCredentials() {
		if c, err := evidence.NewAWSCollector(context.Background(), os.Getenv("AWS_REGION")); err == nil {
			reg.Register("aws", c)
		} else {
			fmt.Fprintln(os.Stderr, "warning: AWS credentials detected but config load failed:", err)
		}
	}
	if uri := os.Getenv("MLFLOW_TRACKING_URI"); uri != "" {
		reg.Register("mlflow", evidence.NewMLflowCollector(uri, os.Getenv("MLFLOW_TRACKING_TOKEN")))
	}
	if org, token := os.Getenv("OKTA_ORG_URL"), os.Getenv("OKTA_API_TOKEN"); org != "" && token != "" {
		reg.Register("okta", evidence.NewOktaCollector(org, token))
	}
	if tok := os.Getenv("SNYK_TOKEN"); tok != "" {
		reg.Register("snyk", evidence.NewSnykCollector(tok))
	}
	return reg
}

func hasAWSCredentials() bool {
	for _, e := range []string{"AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"} {
		if os.Getenv(e) != "" {
			return true
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		if _, err := os.Stat(filepath.Join(home, ".aws", "credentials")); err == nil {
			return true
		}
	}
	return false
}

func describeMode(w io.Writer, reg *evidence.Registry, fixturesOnly bool) {
	if fixturesOnly {
		fmt.Fprintln(w, "Mode: fixtures-only")
		return
	}
	sources := reg.Sources()
	if len(sources) == 0 {
		fmt.Fprintln(w, "Mode: live (no live collectors configured — fixtures will be used where declared)")
		return
	}
	fmt.Fprintf(w, "Mode: live · collectors: %v\n", sources)
}

func githubToken() string {
	if t := os.Getenv("CONCORD_GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GITHUB_TOKEN")
}
