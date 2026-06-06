package policy

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/open-policy-agent/opa/rego"
)

type Engine struct{}

func New() *Engine {
	return &Engine{}
}

type Result struct {
	Deny []string
	Warn []string
	Pass bool
}

func (e *Engine) EvaluateFile(ctx context.Context, regoFile, pkg string, input map[string]any) (Result, error) {
	src, err := os.ReadFile(regoFile)
	if err != nil {
		return Result{}, fmt.Errorf("reading policy %s: %w", regoFile, err)
	}
	return e.EvaluateSource(ctx, string(src), pkg, input)
}

func (e *Engine) EvaluateSource(ctx context.Context, src, pkg string, input map[string]any) (Result, error) {
	return e.EvaluateWithModules(ctx, map[string]string{"policy.rego": src}, pkg, input)
}

// EvaluateWithModules runs the deny/warn queries against pkg using every module in mods.
// Use this when the policy imports library helpers that live in separate files.
func (e *Engine) EvaluateWithModules(ctx context.Context, mods map[string]string, pkg string, input map[string]any) (Result, error) {
	deny, err := query(ctx, mods, fmt.Sprintf("data.%s.deny", pkg), input)
	if err != nil {
		return Result{}, fmt.Errorf("deny query: %w", err)
	}
	warn, _ := query(ctx, mods, fmt.Sprintf("data.%s.warn", pkg), input)
	sort.Strings(deny)
	sort.Strings(warn)
	return Result{Deny: deny, Warn: warn, Pass: len(deny) == 0}, nil
}

func query(ctx context.Context, mods map[string]string, q string, input map[string]any) ([]string, error) {
	opts := []func(*rego.Rego){rego.Query(q), rego.Input(input)}
	for name, src := range mods {
		opts = append(opts, rego.Module(name, src))
	}
	r := rego.New(opts...)
	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, err
	}
	return collectMessages(rs), nil
}

func collectMessages(rs rego.ResultSet) []string {
	var out []string
	for _, r := range rs {
		for _, e := range r.Expressions {
			switch v := e.Value.(type) {
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok {
						out = append(out, s)
					}
				}
			case string:
				out = append(out, v)
			}
		}
	}
	return out
}
