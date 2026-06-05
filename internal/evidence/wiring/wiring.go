package wiring

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/concord-dev/concord/internal/evidence"
	awsev "github.com/concord-dev/concord/internal/evidence/aws"
	ghev "github.com/concord-dev/concord/internal/evidence/github"
	hfev "github.com/concord-dev/concord/internal/evidence/huggingface"
	mlflowev "github.com/concord-dev/concord/internal/evidence/mlflow"
	oktaev "github.com/concord-dev/concord/internal/evidence/okta"
	prowlerev "github.com/concord-dev/concord/internal/evidence/prowler"
	snykev "github.com/concord-dev/concord/internal/evidence/snyk"
	steampipeev "github.com/concord-dev/concord/internal/evidence/steampipe"
	wandbev "github.com/concord-dev/concord/internal/evidence/wandb"
	"github.com/concord-dev/concord/internal/plugins"
)

// Opts tunes how BuildRegistry assembles the collector set.
type Opts struct {
	// FixturesOnly skips every live collector and serves the file
	// fixture path on every evidence ref.
	FixturesOnly bool

	// NeededSources is the set of source names the current run will
	// touch. Used to lazy-spawn only the plugins this run requires.
	// Empty means "skip plugin discovery" — callers using the legacy
	// signature get backwards-compatible behaviour.
	NeededSources []string

	// PluginDirs overrides the plugin discovery directories. Empty
	// means default (~/.concord/plugins and ./.concord/plugins).
	PluginDirs []string

	// Warn receives non-fatal startup warnings.
	Warn io.Writer
}

// Built is the bundle BuildRegistry returns: the registry plus a
// Shutdown hook the caller must defer (plugin processes are spawned
// children that need a clean exit).
type Built struct {
	Registry *evidence.Registry
	Manager  *plugins.Manager // nil when no plugins discovered or fixtures-only
	Shutdown func()
}

// BuildRegistry assembles the evidence registry for one run. In-tree
// collectors register eagerly (they're cheap). Plugin-backed
// collectors discover from disk and spawn lazily — only sources named
// in opts.NeededSources actually start a process.
//
// CONCORD_PREFER_PLUGINS=1 causes plugin registrations to overwrite an
// in-tree collector with the same source name (the migration knob).
func BuildRegistry(ctx context.Context, opts Opts) Built {
	warn := opts.Warn
	if warn == nil {
		warn = io.Discard
	}
	reg := evidence.NewRegistry()
	built := Built{Registry: reg, Shutdown: func() {}}

	if opts.FixturesOnly {
		reg.SetFixturesOnly(true)
		return built
	}

	registerInTree(ctx, reg, warn)

	mgr, shutdown, err := registerPlugins(reg, opts, warn)
	if err != nil {
		fmt.Fprintln(warn, "warning: plugin discovery failed:", err)
		return built
	}
	if mgr != nil {
		built.Manager = mgr
		built.Shutdown = shutdown
	}
	return built
}

func registerInTree(ctx context.Context, reg *evidence.Registry, warn io.Writer) {
	if tok := GitHubToken(); tok != "" {
		reg.Register("github", ghev.New(tok))
	}
	if HasAWSCredentials() {
		if c, err := awsev.New(ctx, os.Getenv("AWS_REGION")); err == nil {
			reg.Register("aws", c)
		} else {
			fmt.Fprintln(warn, "warning: AWS credentials detected but config load failed:", err)
		}
	}
	if uri := os.Getenv("MLFLOW_TRACKING_URI"); uri != "" {
		reg.Register("mlflow", mlflowev.New(uri, os.Getenv("MLFLOW_TRACKING_TOKEN")))
	}
	if org, tok := os.Getenv("OKTA_ORG_URL"), os.Getenv("OKTA_API_TOKEN"); org != "" && tok != "" {
		reg.Register("okta", oktaev.New(org, tok))
	}
	if tok := os.Getenv("SNYK_TOKEN"); tok != "" {
		reg.Register("snyk", snykev.New(tok))
	}
	if key := os.Getenv("WANDB_API_KEY"); key != "" {
		reg.Register("wandb", wandbev.New(os.Getenv("WANDB_BASE_URL"), key))
	}
	reg.Register("huggingface", hfev.New(os.Getenv("HUGGINGFACE_BASE_URL"), os.Getenv("HUGGINGFACE_TOKEN")))

	if HasBinary("steampipe", os.Getenv("CONCORD_STEAMPIPE_BIN")) {
		reg.Register("steampipe", steampipeev.New(steampipeev.Config{
			Binary:    envOr("CONCORD_STEAMPIPE_BIN", "steampipe"),
			Workspace: os.Getenv("CONCORD_STEAMPIPE_WORKSPACE"),
		}))
	}
	if HasBinary("prowler", os.Getenv("CONCORD_PROWLER_BIN")) {
		reg.Register("prowler", prowlerev.New(prowlerev.Config{
			Binary:  envOr("CONCORD_PROWLER_BIN", "prowler"),
			WorkDir: os.Getenv("CONCORD_PROWLER_WORKDIR"),
		}))
	}
}

// registerPlugins discovers installed plugin binaries and registers a
// PluginCollector for each source the run actually needs. Plugins
// override in-tree collectors only when CONCORD_PREFER_PLUGINS=1.
// Returns (nil, noop, nil) when no needed sources are listed.
func registerPlugins(reg *evidence.Registry, opts Opts, warn io.Writer) (*plugins.Manager, func(), error) {
	if len(opts.NeededSources) == 0 {
		return nil, func() {}, nil
	}
	prefer := os.Getenv("CONCORD_PREFER_PLUGINS") == "1"

	mgr := plugins.New(plugins.Options{Dirs: opts.PluginDirs})
	if err := mgr.Discover(); err != nil {
		return nil, func() {}, err
	}
	if len(mgr.Available()) == 0 {
		return nil, func() {}, nil
	}

	var ensure []string
	for _, src := range opts.NeededSources {
		if !mgr.Has(src) {
			continue
		}
		if reg.Has(src) && !prefer {
			continue
		}
		ensure = append(ensure, src)
	}
	if len(ensure) == 0 {
		return nil, func() {}, nil
	}

	ctx := context.Background()
	if err := mgr.Ensure(ctx, ensure); err != nil {
		fmt.Fprintln(warn, "warning: plugin spawn failed:", err)
	}
	for _, src := range ensure {
		c, err := mgr.Get(ctx, src)
		if err != nil {
			fmt.Fprintf(warn, "warning: plugin %s unavailable: %v\n", src, err)
			continue
		}
		reg.Register(src, c)
	}
	return mgr, func() { _ = mgr.Shutdown(context.Background()) }, nil
}

func GitHubToken() string {
	if t := os.Getenv("CONCORD_GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GITHUB_TOKEN")
}

func HasAWSCredentials() bool {
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

// HasBinary reports whether name (or override, when set) is on PATH.
func HasBinary(name, override string) bool {
	if override != "" {
		_, err := os.Stat(override)
		return err == nil
	}
	_, err := exec.LookPath(name)
	return err == nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
