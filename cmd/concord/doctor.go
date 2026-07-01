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
  - each installed plugin collector is reachable

Exits non-zero if any check fails.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			d := &doctor{w: os.Stdout, ctx: cmd.Context()}
			if d.ctx == nil {
				d.ctx = context.Background()
			}
			d.runConfig(configPath)
			d.runControls(controlsDir)
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
		d.fail(fmt.Sprintf("controls/ not found at %s", dir), "run `concord add <framework>` to install a control pack")
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
