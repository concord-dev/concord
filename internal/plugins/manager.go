package plugins

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"
	"time"

	hclog "github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"

	sdkplugin "github.com/concord-dev/concord/pkg/plugin"
	pluginv1 "github.com/concord-dev/concord/proto/concord/plugin/v1"
)

// Manager discovers plugin binaries on disk and spawns them on demand.
type Manager struct {
	dirs []string

	mu         sync.Mutex
	discovered map[string]*entry
	running    map[string]*client
}

type entry struct {
	source  string
	version string
	path    string
}

type client struct {
	gpc       *goplugin.Client
	collector pluginv1.CollectorClient
	wrapper   *PluginCollector
}

// Options tune the manager.
type Options struct {
	Dirs    []string
	Timeout time.Duration
	Logger  *slog.Logger
}

// New returns a manager with no plugins discovered yet. Call Discover before Get.
func New(opts Options) *Manager {
	if len(opts.Dirs) == 0 {
		opts.Dirs = defaultDirs()
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 120 * time.Second
	}
	return &Manager{
		dirs:       opts.Dirs,
		discovered: make(map[string]*entry),
		running:    make(map[string]*client),
	}
}

func defaultDirs() []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".concord", "plugins"))
	}
	if wd, err := os.Getwd(); err == nil {
		dirs = append(dirs, filepath.Join(wd, ".concord", "plugins"))
	}
	return dirs
}

// Discover walks the configured dirs and records every plugin binary found.
func (m *Manager) Discover() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.discovered = make(map[string]*entry)
	for _, dir := range m.dirs {
		if err := m.scanDir(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("scanning %s: %w", dir, err)
		}
	}
	return nil
}

func (m *Manager) scanDir(dir string) error {
	sources, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, src := range sources {
		if !src.IsDir() {
			continue
		}
		versions, err := os.ReadDir(filepath.Join(dir, src.Name()))
		if err != nil {
			continue
		}
		var versionDirs []string
		for _, v := range versions {
			if v.IsDir() {
				versionDirs = append(versionDirs, v.Name())
			}
		}
		if len(versionDirs) == 0 {
			continue
		}
		sort.Strings(versionDirs)
		ver := versionDirs[len(versionDirs)-1]

		bin := filepath.Join(dir, src.Name(), ver, "concord-plugin-"+src.Name())
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		m.discovered[src.Name()] = &entry{source: src.Name(), version: ver, path: bin}
	}
	return nil
}

// Available lists discovered plugin sources, sorted.
func (m *Manager) Available() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.discovered))
	for s := range m.discovered {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Has reports whether a plugin for source has been discovered.
func (m *Manager) Has(source string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.discovered[source]
	return ok
}

// Ensure pre-warms each named source by spawning its plugin.
func (m *Manager) Ensure(ctx context.Context, sources []string) error {
	var errs []error
	for _, s := range sources {
		if _, err := m.Get(ctx, s); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s, err))
		}
	}
	return errors.Join(errs...)
}

// Get returns the running PluginCollector for source, spawning lazily on first call.
func (m *Manager) Get(_ context.Context, source string) (*PluginCollector, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if c, ok := m.running[source]; ok {
		return c.wrapper, nil
	}

	e, ok := m.discovered[source]
	if !ok {
		return nil, fmt.Errorf("no plugin discovered for source %q", source)
	}

	c, err := m.spawn(e)
	if err != nil {
		return nil, err
	}
	m.running[source] = c
	return c.wrapper, nil
}

func (m *Manager) spawn(e *entry) (*client, error) {
	gpc := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig: sdkplugin.HandshakeConfig,
		Plugins: map[string]goplugin.Plugin{
			sdkplugin.PluginName: &sdkplugin.CollectorPlugin{},
		},
		Cmd:              exec.Command(e.path),
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
		Managed:          true,
		Logger:           hclog.NewNullLogger(),
	})
	conn, err := gpc.Client()
	if err != nil {
		gpc.Kill()
		return nil, fmt.Errorf("connecting to plugin %s: %w", e.source, err)
	}
	raw, err := conn.Dispense(sdkplugin.PluginName)
	if err != nil {
		gpc.Kill()
		return nil, fmt.Errorf("dispensing plugin %s: %w", e.source, err)
	}
	stub, ok := raw.(pluginv1.CollectorClient)
	if !ok {
		gpc.Kill()
		return nil, fmt.Errorf("plugin %s: client is %T, want CollectorClient", e.source, raw)
	}
	return &client{
		gpc:       gpc,
		collector: stub,
		wrapper:   NewPluginCollector(e.source, stub, 120*time.Second),
	}, nil
}

// Capabilities returns source's self-declared capabilities, spawning the plugin if needed.
func (m *Manager) Capabilities(ctx context.Context, source string) (Capabilities, error) {
	pc, err := m.Get(ctx, source)
	if err != nil {
		return Capabilities{}, err
	}
	return pc.Capabilities(ctx)
}

// Shutdown terminates every running plugin. Safe to call repeatedly.
func (m *Manager) Shutdown(_ context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.running {
		c.gpc.Kill()
	}
	m.running = make(map[string]*client)
	return nil
}
