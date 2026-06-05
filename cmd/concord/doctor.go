package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/config"
	"github.com/concord-dev/concord/internal/controls"
	awsev "github.com/concord-dev/concord/internal/evidence/aws"
	ghev "github.com/concord-dev/concord/internal/evidence/github"
	hfev "github.com/concord-dev/concord/internal/evidence/huggingface"
	mlflowev "github.com/concord-dev/concord/internal/evidence/mlflow"
	oktaev "github.com/concord-dev/concord/internal/evidence/okta"
	snykev "github.com/concord-dev/concord/internal/evidence/snyk"
	wandbev "github.com/concord-dev/concord/internal/evidence/wandb"
	"github.com/concord-dev/concord/internal/evidence/wiring"
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
  - each detectable collector (GitHub, AWS, MLflow, Okta) is reachable
    and the supplied credentials work against a low-cost probe

Exits non-zero if any check fails.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			d := &doctor{w: os.Stdout, ctx: cmd.Context()}
			if d.ctx == nil {
				d.ctx = context.Background()
			}
			d.runConfig(configPath)
			d.runControls(controlsDir)
			d.runCollectors()
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
	fmt.Fprintf(d.w, "  %s %s", color.GreenString("✓"), label)
	if detail != "" {
		fmt.Fprintf(d.w, " — %s", color.New(color.Faint).Sprint(detail))
	}
	fmt.Fprintln(d.w)
}

func (d *doctor) warn(label, detail string) {
	d.warned++
	fmt.Fprintf(d.w, "  %s %s", color.YellowString("⚠"), label)
	if detail != "" {
		fmt.Fprintf(d.w, " — %s", color.New(color.Faint).Sprint(detail))
	}
	fmt.Fprintln(d.w)
}

func (d *doctor) fail(label, detail string) {
	d.failed++
	fmt.Fprintf(d.w, "  %s %s", color.RedString("✗"), label)
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

func (d *doctor) runCollectors() {
	d.section("Collectors")

	if tok := wiring.GitHubToken(); tok != "" {
		c := ghev.New(tok)
		d.probe("github", c, "set CONCORD_GITHUB_TOKEN or GITHUB_TOKEN")
	} else {
		d.warn("github", "no token in CONCORD_GITHUB_TOKEN or GITHUB_TOKEN — controls using source=github will fall back to fixtures")
	}

	if wiring.HasAWSCredentials() {
		c, err := awsev.New(d.ctx, os.Getenv("AWS_REGION"))
		if err != nil {
			d.fail("aws", "loading SDK config: "+err.Error())
		} else {
			d.probe("aws", c, "verify AWS profile, region, and IAM perms (see examples/iam-readonly-policy.json)")
		}
	} else {
		d.warn("aws", "no AWS credentials detected (env, profile, or ~/.aws/credentials) — controls using source=aws will fall back to fixtures")
	}

	if uri := os.Getenv("MLFLOW_TRACKING_URI"); uri != "" {
		c := mlflowev.New(uri, os.Getenv("MLFLOW_TRACKING_TOKEN"))
		d.probe("mlflow", c, "verify MLFLOW_TRACKING_URI and (optional) MLFLOW_TRACKING_TOKEN")
	} else {
		d.warn("mlflow", "MLFLOW_TRACKING_URI not set — controls using source=mlflow will fall back to fixtures")
	}

	org, otok := os.Getenv("OKTA_ORG_URL"), os.Getenv("OKTA_API_TOKEN")
	switch {
	case org != "" && otok != "":
		c := oktaev.New(org, otok)
		d.probe("okta", c, "verify OKTA_ORG_URL and OKTA_API_TOKEN")
	case org != "" || otok != "":
		d.warn("okta", "only one of OKTA_ORG_URL / OKTA_API_TOKEN set — both are required")
	default:
		d.warn("okta", "OKTA_ORG_URL and OKTA_API_TOKEN not set — controls using source=okta will fall back to fixtures")
	}

	if tok := os.Getenv("SNYK_TOKEN"); tok != "" {
		c := snykev.New(tok)
		d.probe("snyk", c, "verify SNYK_TOKEN is valid for your org")
	} else {
		d.warn("snyk", "SNYK_TOKEN not set — controls using source=snyk will fall back to fixtures")
	}

	if key := os.Getenv("WANDB_API_KEY"); key != "" {
		c := wandbev.New(os.Getenv("WANDB_BASE_URL"), key)
		d.probe("wandb", c, "verify WANDB_API_KEY at wandb.me/authorize")
	} else {
		d.warn("wandb", "WANDB_API_KEY not set — controls using source=wandb will fall back to fixtures")
	}

	if tok := os.Getenv("HUGGINGFACE_TOKEN"); tok != "" {
		c := hfev.New(os.Getenv("HUGGINGFACE_BASE_URL"), tok)
		d.probe("huggingface", c, "verify HUGGINGFACE_TOKEN at huggingface.co/settings/tokens")
	} else {
		d.warn("huggingface", "HUGGINGFACE_TOKEN not set — anonymous reads still work, but rate-limited")
	}
}

func (d *doctor) probe(name string, p prober, hint string) {
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
	if d.failed > 0 {
		fmt.Fprintln(d.w)
		fmt.Fprintln(d.w, color.RedString("doctor found %d blocking issue(s)", d.failed))
	} else if d.warned > 0 {
		fmt.Fprintln(d.w)
		fmt.Fprintln(d.w, color.YellowString("doctor is happy, but %d source(s) will fall back to fixtures", d.warned))
	} else {
		fmt.Fprintln(d.w)
		fmt.Fprintln(d.w, color.GreenString("doctor is happy — ready to run `concord check`"))
	}
}

func summarizeFrameworks(m map[string]int) string {
	if len(m) == 0 {
		return ""
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j-1] > keys[j]; j-- {
			keys[j-1], keys[j] = keys[j], keys[j-1]
		}
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return out
}
