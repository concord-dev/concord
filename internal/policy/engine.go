// Package policy evaluates compliance policies using OPA / Rego.
package policy

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/open-policy-agent/opa/rego"
)

// Engine evaluates Rego policies against typed inputs.
type Engine struct{}

// New returns a new policy engine.
func New() *Engine {
	return &Engine{}
}

// Result captures what a policy returned.
type Result struct {
	Deny []string
	Warn []string
	Pass bool
}

// EvaluateFile loads a .rego file and runs the deny + warn queries against input.
func (e *Engine) EvaluateFile(ctx context.Context, regoFile, pkg string, input map[string]any) (Result, error) {
	src, err := os.ReadFile(regoFile)
	if err != nil {
		return Result{}, fmt.Errorf("reading policy %s: %w", regoFile, err)
	}
	return e.EvaluateSource(ctx, string(src), pkg, input)
}

// EvaluateSource compiles and evaluates rego source against input.
func (e *Engine) EvaluateSource(ctx context.Context, src, pkg string, input map[string]any) (Result, error) {
	deny, err := query(ctx, src, fmt.Sprintf("data.%s.deny", pkg), input)
	if err != nil {
		return Result{}, fmt.Errorf("deny query: %w", err)
	}
	warn, _ := query(ctx, src, fmt.Sprintf("data.%s.warn", pkg), input)

	sort.Strings(deny)
	sort.Strings(warn)
	return Result{Deny: deny, Warn: warn, Pass: len(deny) == 0}, nil
}

func query(ctx context.Context, src, q string, input map[string]any) ([]string, error) {
	r := rego.New(
		rego.Query(q),
		rego.Module("policy.rego", src),
		rego.Input(input),
	)
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
