package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	awsev "github.com/concord-dev/concord/internal/evidence/aws"
	ghev "github.com/concord-dev/concord/internal/evidence/github"
	hfev "github.com/concord-dev/concord/internal/evidence/huggingface"
	mlflowev "github.com/concord-dev/concord/internal/evidence/mlflow"
	oktaev "github.com/concord-dev/concord/internal/evidence/okta"
	snykev "github.com/concord-dev/concord/internal/evidence/snyk"
	wandbev "github.com/concord-dev/concord/internal/evidence/wandb"
	"github.com/concord-dev/concord/internal/evidence/wiring"
	"github.com/concord-dev/concord/internal/plugins"
	"github.com/concord-dev/concord/pkg/config"
	"github.com/concord-dev/concord/pkg/controls"
)

type prober interface {
	Probe(ctx context.Context) (string, error)
}

func newDoctorCmd() *cobra.Command {
	var (
		controlsDir string
		configPath  string
	)
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose Concord setup: config, controls, and collector reachability",
		Long: `doctor runs every preflight check needed before "concord check" can succeed:

  - concord.yaml exists and parses
  - controls/ tree validates without errors
  - each detectable collector (in-tree or installed as a plugin) is reachable

Exits non-zero if any check fails.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			d := &doctor{w: os.Stdout, ctx: cmd.Context()}
			if d.ctx == nil {
				d.ctx = context.Background()
			}
			d.runConfig(configPath)
			d.runControls(controlsDir)
			d.runInTreeCollectors()
			d.runPluginCollectors()
			d.printSummary()
			if d.failed > 0 {
				os.Exit(1)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&controlsDir, "controls", "./controls", "Path to controls directory")
	cmd.Flags().StringVar(&configPath, "config", "./concord.yaml", "Path to concord.yaml")
	return cmd
}

type doctor struct {
	w      io.Writer
	ctx    context.Context
	passed int
	warned int
	failed int
}

func (d *doctor) section(title string) {
	bold := color.New(color.Bold).SprintFunc()
	fmt.Fprintln(d.w)
	fmt.Fprintln(d.w, bold(title))
}

func (d *doctor) pass(label, detail string) {
	d.passed++
	d.line(color.GreenString("✓"), label, detail)
}

func (d *doctor) warn(label, detail string) {
	d.warned++
	d.line(color.YellowString("⚠"), label, detail)
}

func (d *doctor) fail(label, detail string) {
	d.failed++
	d.line(color.RedString("✗"), label, detail)
}

func (d *doctor) line(symbol, label, detail string) {
	fmt.Fprintf(d.w, "  %s %s", symbol, label)
	if detail != "" {
		fmt.Fprintf(d.w, " — %s", color.New(color.Faint).Sprint(detail))
	}
	fmt.Fprintln(d.w)
}

func (d *doctor) runConfig(path string) {
	d.section("Configuration")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		d.warn(fmt.Sprintf("concord.yaml not found at %s", path), "run `concord init` or pass --config")
		return
	}
	cfg, err := config.Load(path)
	if err != nil {
		d.fail(fmt.Sprintf("concord.yaml at %s", path), err.Error())
		return
	}
	detail := ""
	if cfg.Metadata.Name != "" {
		detail = "metadata.name=" + cfg.Metadata.Name
	}
	d.pass(fmt.Sprintf("concord.yaml parsed (%s)", path), detail)
	if len(cfg.Controls.Params) > 0 {
		d.pass(fmt.Sprintf("%d control param override(s) declared", len(cfg.Controls.Params)), "")
	}
}

func (d *doctor) runControls(dir string) {
	d.section("Controls")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		d.fail(fmt.Sprintf("controls/ not found at %s", dir), "run `concord init` to scaffold the bundled library")
		return
	}
	loaded, err := controls.Load(dir)
	if err != nil {
		d.fail(fmt.Sprintf("controls/ at %s", dir), err.Error())
		return
	}
	if len(loaded) == 0 {
		d.warn(fmt.Sprintf("controls/ at %s is empty", dir), "no .yaml controls found")
		return
	}
	frameworks := map[string]int{}
	for _, l := range loaded {
		frameworks[l.Control.Metadata.Framework]++
	}
	d.pass(fmt.Sprintf("%d control(s) parsed and validated", len(loaded)), summarizeFrameworks(frameworks))
}

type inTreeProbe struct {
	source string
	probe  func() (prober, []string, string)
	hint   string
}

func (d *doctor) runInTreeCollectors() {
	d.section("In-tree collectors")
	for _, p := range inTreeProbes() {
		c, missing, info := p.probe()
		if c == nil {
			d.warn(p.source, info)
			continue
		}
		if len(missing) > 0 {
			d.warn(p.source, "missing env: "+strings.Join(missing, ", "))
			continue
		}
		d.runProbe(p.source, c, p.hint)
	}
}

func (d *doctor) runPluginCollectors() {
	mgr := plugins.New(plugins.Options{})
	if err := mgr.Discover(); err != nil {
		d.section("Plugin collectors")
		d.fail("plugin discovery", err.Error())
		return
	}
	defer func() { _ = mgr.Shutdown(d.ctx) }()

	available := mgr.Available()
	if len(available) == 0 {
		return
	}
	d.section("Plugin collectors")
	for _, src := range available {
		caps, err := mgr.Capabilities(d.ctx, src)
		if err != nil {
			d.fail(src, "capabilities: "+err.Error())
			continue
		}
		label := src
		if len(caps.EmbedsBinaries) > 0 {
			label = fmt.Sprintf("%s (bundled: %s)", src, strings.Join(caps.EmbedsBinaries, ", "))
		}
		if missing := missingEnv(caps.RequiredEnv); len(missing) > 0 {
			d.warn(label, "missing required env: "+strings.Join(missing, ", "))
			continue
		}
		pc, err := mgr.Get(d.ctx, src)
		if err != nil {
			d.fail(label, "spawn: "+err.Error())
			continue
		}
		d.runProbe(label, pc, "see "+caps.DocsURL)
	}
}

func (d *doctor) runProbe(name string, p prober, hint string) {
	info, err := p.Probe(d.ctx)
	if err != nil {
		d.fail(name, err.Error()+" · "+hint)
		return
	}
	d.pass(name, info)
}

func (d *doctor) printSummary() {
	bold := color.New(color.Bold).SprintFunc()
	fmt.Fprintln(d.w)
	fmt.Fprintln(d.w, bold("Summary"))
	fmt.Fprintf(d.w, "  %s  %d   %s  %d   %s  %d\n",
		color.GreenString("ok"), d.passed,
		color.YellowString("warn"), d.warned,
		color.RedString("error"), d.failed,
	)
	fmt.Fprintln(d.w)
	switch {
	case d.failed > 0:
		fmt.Fprintln(d.w, color.RedString("doctor found %d blocking issue(s)", d.failed))
	case d.warned > 0:
		fmt.Fprintln(d.w, color.YellowString("doctor is happy, but %d source(s) will fall back to fixtures", d.warned))
	default:
		fmt.Fprintln(d.w, color.GreenString("doctor is happy — ready to run `concord check`"))
	}
}

func inTreeProbes() []inTreeProbe {
	return []inTreeProbe{
		{
			source: "github",
			probe: func() (prober, []string, string) {
				tok := wiring.GitHubToken()
				if tok == "" {
					return nil, nil, "no token in CONCORD_GITHUB_TOKEN or GITHUB_TOKEN — controls using source=github will fall back to fixtures"
				}
				return ghev.New(tok), nil, ""
			},
			hint: "set CONCORD_GITHUB_TOKEN or GITHUB_TOKEN",
		},
		{
			source: "aws",
			probe: func() (prober, []string, string) {
				if !wiring.HasAWSCredentials() {
					return nil, nil, "no AWS credentials detected (env, profile, or ~/.aws/credentials) — controls using source=aws will fall back to fixtures"
				}
				c, err := awsev.New(context.Background(), os.Getenv("AWS_REGION"))
				if err != nil {
					return nil, nil, "loading SDK config: " + err.Error()
				}
				return c, nil, ""
			},
			hint: "verify AWS profile, region, and IAM perms (see examples/iam-readonly-policy.json)",
		},
		{
			source: "mlflow",
			probe: func() (prober, []string, string) {
				uri := os.Getenv("MLFLOW_TRACKING_URI")
				if uri == "" {
					return nil, nil, "MLFLOW_TRACKING_URI not set — controls using source=mlflow will fall back to fixtures"
				}
				return mlflowev.New(uri, os.Getenv("MLFLOW_TRACKING_TOKEN")), nil, ""
			},
			hint: "verify MLFLOW_TRACKING_URI and (optional) MLFLOW_TRACKING_TOKEN",
		},
		{
			source: "okta",
			probe: func() (prober, []string, string) {
				org, tok := os.Getenv("OKTA_ORG_URL"), os.Getenv("OKTA_API_TOKEN")
				switch {
				case org != "" && tok != "":
					return oktaev.New(org, tok), nil, ""
				case org != "" || tok != "":
					return nil, nil, "only one of OKTA_ORG_URL / OKTA_API_TOKEN set — both are required"
				}
				return nil, nil, "OKTA_ORG_URL and OKTA_API_TOKEN not set — controls using source=okta will fall back to fixtures"
			},
			hint: "verify OKTA_ORG_URL and OKTA_API_TOKEN",
		},
		{
			source: "snyk",
			probe: func() (prober, []string, string) {
				tok := os.Getenv("SNYK_TOKEN")
				if tok == "" {
					return nil, nil, "SNYK_TOKEN not set — controls using source=snyk will fall back to fixtures"
				}
				return snykev.New(tok), nil, ""
			},
			hint: "verify SNYK_TOKEN is valid for your org",
		},
		{
			source: "wandb",
			probe: func() (prober, []string, string) {
				key := os.Getenv("WANDB_API_KEY")
				if key == "" {
					return nil, nil, "WANDB_API_KEY not set — controls using source=wandb will fall back to fixtures"
				}
				return wandbev.New(os.Getenv("WANDB_BASE_URL"), key), nil, ""
			},
			hint: "verify WANDB_API_KEY at wandb.me/authorize",
		},
		{
			source: "huggingface",
			probe: func() (prober, []string, string) {
				tok := os.Getenv("HUGGINGFACE_TOKEN")
				if tok == "" {
					return nil, nil, "HUGGINGFACE_TOKEN not set — anonymous reads still work, but rate-limited"
				}
				return hfev.New(os.Getenv("HUGGINGFACE_BASE_URL"), tok), nil, ""
			},
			hint: "verify HUGGINGFACE_TOKEN at huggingface.co/settings/tokens",
		},
	}
}

func missingEnv(required []string) []string {
	var missing []string
	for _, k := range required {
		if os.Getenv(k) == "" {
			missing = append(missing, k)
		}
	}
	return missing
}

func summarizeFrameworks(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}
