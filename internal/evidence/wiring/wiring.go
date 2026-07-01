package wiring

import (
	"context"
	"fmt"
	"io"

	"github.com/concord-dev/concord/internal/evidence"
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

// BuildRegistry assembles the evidence registry: the built-in file collector plus
// plugins for the sources in opts.NeededSources, which spawn lazily.
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

	if mgr, shutdown, err := registerPlugins(reg, opts, warn); err != nil {
		fmt.Fprintln(warn, "warning: plugin discovery failed:", err)
	} else if mgr != nil {
		built.Manager = mgr
		built.Shutdown = shutdown
	}
	return built
}

func registerPlugins(reg *evidence.Registry, opts Opts, warn io.Writer) (*plugins.Manager, func(), error) {
	if len(opts.NeededSources) == 0 {
		return nil, func() {}, nil
	}

	mgr := plugins.New(plugins.Options{Dirs: opts.PluginDirs})
	if err := mgr.Discover(); err != nil {
		return nil, func() {}, err
	}
	if len(mgr.Available()) == 0 {
		return nil, func() {}, nil
	}

	var ensure []string
	for _, src := range opts.NeededSources {
		if mgr.Has(src) {
			ensure = append(ensure, src)
		}
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
