//go:build integration

package plugins

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/concord-dev/concord/internal/evidence"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// TestHelloPlugin spawns the real concord-plugin-hello binary installed
// under ~/.concord/plugins/hello/v0.1.0/ and exercises Probe + Collect.
// Run with:  go test -tags integration ./internal/plugins/...
func TestHelloPlugin(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	bin := filepath.Join(home, ".concord", "plugins", "hello", "v0.1.0", "concord-plugin-hello")
	if _, err := os.Stat(bin); err != nil {
		t.Skipf("hello plugin not installed at %s — run `make install` in concord-plugin-hello", bin)
	}

	mgr := New(Options{Dirs: []string{filepath.Join(home, ".concord", "plugins")}})
	if err := mgr.Discover(); err != nil {
		t.Fatalf("Discover: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Shutdown(context.Background()) })

	avail := mgr.Available()
	if len(avail) == 0 {
		t.Fatalf("Discover found no plugins in %s/.concord/plugins", home)
	}
	if !mgr.Has("hello") {
		t.Fatalf("Has(hello)=false; available=%v", avail)
	}

	pc, err := mgr.Get(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Get(hello): %v", err)
	}

	info, err := pc.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if info == "" {
		t.Fatal("Probe returned empty info")
	}
	t.Logf("Probe → %s", info)

	val, err := pc.Collect(evidence.Context{ControlDir: "."}, apiv1.EvidenceRef{
		ID:     "g1",
		Source: "hello",
		Type:   "greeting",
		Params: map[string]any{"name": "concord"},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	m, ok := val.(map[string]any)
	if !ok {
		t.Fatalf("Collect returned %T, want map[string]any", val)
	}
	if got, want := m["message"], "hello, concord"; got != want {
		t.Fatalf("message=%v, want %v", got, want)
	}
	t.Logf("Collect → %v", m)

	_, err = pc.Collect(evidence.Context{}, apiv1.EvidenceRef{
		Source: "hello",
		Type:   "not-a-real-type",
	})
	if err == nil {
		t.Fatal("Collect with unsupported type returned nil error; want ErrUnsupportedType")
	}
	if !isUnsupportedType(err) {
		t.Fatalf("Collect unsupported err = %v; want wraps evidence.ErrUnsupportedType", err)
	}
}

func isUnsupportedType(err error) bool {
	for e := err; e != nil; {
		if e == evidence.ErrUnsupportedType {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := e.(unwrapper)
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}
