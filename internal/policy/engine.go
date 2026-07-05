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
	// Resources holds per-resource verdicts when the policy defines an optional
	// `resource_findings` rule (a set of {resource, status, messages} objects).
	// Empty for control-level policies, which keeps the deny/warn contract and
	// the one-finding-per-control behavior unchanged.
	Resources []ResourceVerdict
}

// ResourceVerdict is one resource's outcome under a control (e.g. one S3 bucket,
// one identity-provider user). status is "pass" | "fail" | "warn".
type ResourceVerdict struct {
	Resource string
	Status   string
	Messages []string
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
	resources, err := queryResources(ctx, mods, fmt.Sprintf("data.%s.resource_findings", pkg), input)
	if err != nil {
		return Result{}, fmt.Errorf("resource_findings query: %w", err)
	}
	sort.Strings(deny)
	sort.Strings(warn)
	return Result{Deny: deny, Warn: warn, Pass: len(deny) == 0, Resources: resources}, nil
}

// queryResources evaluates the optional `resource_findings` rule and decodes its
// set of {resource, status, messages} objects. An undefined rule yields no
// results (not an error), so control-level policies simply return nil.
func queryResources(ctx context.Context, mods map[string]string, q string, input map[string]any) ([]ResourceVerdict, error) {
	opts := []func(*rego.Rego){rego.Query(q), rego.Input(input)}
	for name, src := range mods {
		opts = append(opts, rego.Module(name, src))
	}
	rs, err := rego.New(opts...).Eval(ctx)
	if err != nil {
		return nil, err
	}
	var out []ResourceVerdict
	for _, r := range rs {
		for _, e := range r.Expressions {
			items, ok := e.Value.([]any)
			if !ok {
				continue
			}
			for _, item := range items {
				m, ok := item.(map[string]any)
				if !ok {
					continue
				}
				v := ResourceVerdict{}
				if s, ok := m["resource"].(string); ok {
					v.Resource = s
				}
				if s, ok := m["status"].(string); ok {
					v.Status = s
				}
				if msgs, ok := m["messages"].([]any); ok {
					for _, mm := range msgs {
						if s, ok := mm.(string); ok {
							v.Messages = append(v.Messages, s)
						}
					}
				}
				if v.Resource != "" {
					out = append(out, v)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Resource < out[j].Resource })
	return out, nil
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
