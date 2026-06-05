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

// Opts tune how BuildRegistry assembles the collector set for one run.
type Opts struct {
	FixturesOnly  bool
	NeededSources []string
	PluginDirs    []string
	Warn          io.Writer
}

// Built bundles the registry with the lifecycle hook callers must defer.
type Built struct {
	Registry *evidence.Registry
	Manager  *plugins.Manager
	Shutdown func()
}

// BuildRegistry assembles the evidence registry. In-tree collectors register
// eagerly; plugins for sources in opts.NeededSources spawn lazily. Set
// CONCORD_PREFER_PLUGINS=1 to let plugins override in-tree collectors.
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

	if mgr, shutdown, err := registerPlugins(reg, opts, warn); err != nil {
		fmt.Fprintln(warn, "warning: plugin discovery failed:", err)
	} else if mgr != nil {
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

// GitHubToken returns the user-configured GitHub credential, preferring CONCORD_GITHUB_TOKEN.
func GitHubToken() string {
	if t := os.Getenv("CONCORD_GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GITHUB_TOKEN")
}

// HasAWSCredentials reports whether the AWS SDK would find usable credentials at runtime.
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
