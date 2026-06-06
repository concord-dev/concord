// Package plugintest exercises a SimpleCollector in-process for fast plugin tests.
package plugintest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	plugin "github.com/concord-dev/concord/pkg/plugin"
)

// Case describes one input/expected pair the harness replays through a plugin.
type Case struct {
	Name         string
	Ref          plugin.EvidenceRef
	Env          map[string]string
	Expected     any
	ExpectError  bool
	ExpectErrorIs error
}

// Run drives a SimpleCollector through every case and asserts the result.
func Run(t *testing.T, impl plugin.SimpleCollector, cases []Case) {
	t.Helper()
	adapter := plugin.NewSimpleAdapter(impl)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.Name, func(t *testing.T) {
			t.Helper()
			restore := setEnv(t, tc.Env)
			defer restore()

			got, err := adapter.Collect(context.Background(), tc.Ref)
			if tc.ExpectError || tc.ExpectErrorIs != nil {
				if err == nil {
					t.Fatalf("expected error, got nil; result=%v", got)
				}
				if tc.ExpectErrorIs != nil && !errors.Is(err, tc.ExpectErrorIs) {
					t.Fatalf("expected error %v, got %v", tc.ExpectErrorIs, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.Expected == nil {
				return
			}
			if !equalJSON(t, got, tc.Expected) {
				t.Fatalf("evidence mismatch:\n  got:      %s\n  expected: %s",
					marshal(got), marshal(tc.Expected))
			}
		})
	}
}

// Probe verifies the plugin's Probe call passes under the supplied env.
func Probe(t *testing.T, impl plugin.SimpleCollector, env map[string]string) {
	t.Helper()
	adapter := plugin.NewSimpleAdapter(impl)
	restore := setEnv(t, env)
	defer restore()
	if _, err := adapter.Probe(context.Background()); err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
}

// FixturesDir loads every JSON file under dir as one Case keyed by filename.
// The expected payload lives next to each input as <name>.expected.json.
func FixturesDir(t *testing.T, dir string, refTemplate plugin.EvidenceRef) []Case {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read fixtures dir %s: %v", dir, err)
	}
	var cases []Case
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		if strings.HasSuffix(e.Name(), ".expected.json") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".json")
		inputPath := filepath.Join(dir, e.Name())
		expectedPath := filepath.Join(dir, name+".expected.json")
		raw, err := os.ReadFile(inputPath)
		if err != nil {
			t.Fatalf("read %s: %v", inputPath, err)
		}
		var params map[string]any
		if err := json.Unmarshal(raw, &params); err != nil {
			t.Fatalf("parse %s: %v", inputPath, err)
		}
		ref := refTemplate
		if ref.Params == nil {
			ref.Params = map[string]any{}
		}
		for k, v := range params {
			ref.Params[k] = v
		}
		c := Case{Name: name, Ref: ref}
		if exp, err := os.ReadFile(expectedPath); err == nil {
			var expected any
			if err := json.Unmarshal(exp, &expected); err != nil {
				t.Fatalf("parse %s: %v", expectedPath, err)
			}
			c.Expected = expected
		}
		cases = append(cases, c)
	}
	return cases
}

func setEnv(t *testing.T, env map[string]string) func() {
	t.Helper()
	restore := map[string]string{}
	missing := map[string]bool{}
	for k, v := range env {
		if old, ok := os.LookupEnv(k); ok {
			restore[k] = old
		} else {
			missing[k] = true
		}
		if err := os.Setenv(k, v); err != nil {
			t.Fatalf("setenv %s: %v", k, err)
		}
	}
	return func() {
		for k := range env {
			if missing[k] {
				_ = os.Unsetenv(k)
				continue
			}
			_ = os.Setenv(k, restore[k])
		}
	}
}

func equalJSON(t *testing.T, a, b any) bool {
	t.Helper()
	return marshal(a) == marshal(b)
}

func marshal(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("<marshal-error: %v>", err)
	}
	return string(raw)
}
