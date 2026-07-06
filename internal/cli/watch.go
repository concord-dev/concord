package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/concord-dev/concord/internal/evidence/wiring"
	"github.com/concord-dev/concord/internal/notify"
	"github.com/concord-dev/concord/internal/policy"
	"github.com/concord-dev/concord/internal/runner"
	"github.com/concord-dev/concord/internal/watcher"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
	"github.com/concord-dev/concord/pkg/config"
	"github.com/concord-dev/concord/pkg/controls"
)

func newWatchCmd() *cobra.Command {
	var (
		controlsDir  string
		configPath   string
		fixturesOnly bool
		interval     time.Duration
		outputDir    string
		once         bool
		slackWebhook string
		genericHook  string
		frameworks   []string
		severities   []string
		tags         []string
		controlIDs   []string
		push         pushOpts
	)
	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Continuously evaluate compliance controls on a schedule",
		Long: `watch is concord's continuous-compliance mode. It evaluates every
control on --interval (default 1h), persists findings to --output-dir/last-run.json,
and emits a one-line event to stderr whenever a control transitions between
pass/fail/error since the previous run.

Pass --to / --org-slug / --token (plus optionally --key-id + --key to sign) to
also push every iteration's findings to a Concord server — agent mode.

Use --once for cron-style scheduling: a single iteration that exits after writing
findings. Use the default loop mode under a process supervisor (systemd, Docker)
for an always-on agent.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(configPath)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			// Use the same control set as check/apply — the --controls dir plus
			// every installed pack — so watch never silently evaluates a smaller
			// set than a one-shot check.
			roots, err := controlRoots(controlsDir)
			if err != nil {
				return err
			}
			loaded, err := controls.LoadFrom(roots)
			if err != nil {
				return fmt.Errorf("loading controls: %w", err)
			}
			totalLoaded := len(loaded)
			if totalLoaded == 0 {
				return fmt.Errorf("no controls found in %s or any installed pack", controlsDir)
			}
			filter := controls.Filter{
				Frameworks: frameworks,
				Severities: severities,
				Tags:       tags,
				IDs:        controlIDs,
			}
			loaded = filter.Apply(loaded)
			if len(loaded) == 0 {
				return fmt.Errorf("filter excluded every control (%d loaded, 0 matched)", totalLoaded)
			}
			push.resolveFromCredentials()
			if effective, applied := applySourceIntervals(interval, cfg.Sources, controls.NeededSources(loaded), os.Stderr); applied {
				interval = effective
			}
			fmt.Fprintf(os.Stderr, "watching %d control(s) every %s; output → %s\n",
				len(loaded), interval, outputDir)
			if push.serverURL != "" {
				fmt.Fprintf(os.Stderr, "agent mode: pushing each run → %s (org=%s)\n",
					push.serverURL, push.orgSlug)
			}

			built := wiring.BuildRegistry(cmd.Context(), wiring.Opts{
				FixturesOnly:  fixturesOnly,
				NeededSources: controls.NeededSources(loaded),
				Warn:          os.Stderr,
			})
			defer built.Shutdown()

			liveSources := built.Registry.Sources()
			check := func(ctx context.Context) ([]apiv1.Finding, error) {
				started := time.Now().UTC()
				r := runner.New(policy.New(), built.Registry).SetParams(cfg.Controls.Params)
				findings := r.RunAll(ctx, loaded)
				completed := time.Now().UTC()

				if push.serverURL != "" {
					if err := pushFindings(ctx, push, findings, started, completed); err != nil {
						fmt.Fprintln(os.Stderr, "push failed (continuing):", err)
					}
					// Heartbeat live sources each iteration so evidence freshness
					// tracks the watch cadence.
					pushEvidenceHeartbeats(ctx, push, liveSources, started, completed)
				}
				return findings, nil
			}

			sinks := []notify.Sink{notify.Stderr(os.Stderr)}
			if slackWebhook != "" {
				sinks = append(sinks, notify.Slack(slackWebhook, nil, os.Stderr))
			}
			if genericHook != "" {
				sinks = append(sinks, notify.Webhook(genericHook, nil, os.Stderr))
			}

			w := watcher.New(check, watcher.Options{
				Interval:  interval,
				OutputDir: outputDir,
				Once:      once,
				EventSink: notify.Multi(sinks...),
			})

			ctx, cancel := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer cancel()
			return w.Run(ctx)
		},
	}
	cmd.Flags().StringVar(&controlsDir, "controls", "./controls", "Path to controls directory")
	cmd.Flags().StringVar(&configPath, "config", "./concord.yaml", "Path to concord.yaml")
	cmd.Flags().BoolVar(&fixturesOnly, "fixtures", false, "Force fixture-only mode (skip live collectors)")
	cmd.Flags().DurationVar(&interval, "interval", time.Hour, "Time between runs (e.g. 30m, 1h, 24h)")
	cmd.Flags().StringVar(&outputDir, "output-dir", ".concord", "Directory to persist last-run.json")
	cmd.Flags().BoolVar(&once, "once", false, "Run a single iteration and exit (suitable for cron)")
	cmd.Flags().StringVar(&slackWebhook, "slack-webhook", "", "Slack incoming-webhook URL to receive state-change events")
	cmd.Flags().StringVar(&genericHook, "webhook", "", "Generic HTTP endpoint to receive each event as JSON")
	cmd.Flags().StringSliceVar(&frameworks, "framework", nil, "Only watch controls whose metadata.framework matches (repeatable)")
	cmd.Flags().StringSliceVar(&severities, "severity", nil, "Only watch controls of these severities (repeatable)")
	cmd.Flags().StringSliceVar(&tags, "tag", nil, "Only watch controls carrying any of these tags (repeatable)")
	cmd.Flags().StringSliceVar(&controlIDs, "control-id", nil, "Only watch controls with these ids (repeatable)")
	addPushFlags(cmd, &push)
	return cmd
}

// applySourceIntervals reads per-source interval overrides from concord.yaml
// (the `sources.<name>.interval` map) and returns the minimum across the
// global --interval and every configured source that the loaded controls
// actually use. Per-source caching is a follow-up (Φ-3.1); for now the
// loop ticks at the fastest required rate and every tick still re-evaluates
// every control. Wasteful for daily-cadence sources but never stale.
func applySourceIntervals(globalInterval time.Duration, sources map[string]config.SourceConfig, needed []string, log io.Writer) (time.Duration, bool) {
	if len(sources) == 0 {
		return globalInterval, false
	}
	min := globalInterval
	applied := false
	for _, src := range needed {
		cfg, ok := sources[src]
		if !ok || cfg.Interval == "" {
			continue
		}
		d, err := time.ParseDuration(cfg.Interval)
		if err != nil {
			fmt.Fprintf(log, "warn: ignoring sources.%s.interval=%q: %v\n", src, cfg.Interval, err)
			continue
		}
		fmt.Fprintf(log, "source %s configured interval=%s\n", src, d)
		applied = true
		if d < min {
			min = d
		}
	}
	if applied && min != globalInterval {
		fmt.Fprintf(log, "watch loop ticks at %s (min of configured per-source intervals + --interval)\n", min)
	}
	return min, applied
}
