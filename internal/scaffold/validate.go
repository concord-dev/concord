package scaffold

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/concord-dev/concord/internal/policy"
	"github.com/concord-dev/concord/pkg/controls"
)

// ValidationReport summarises a `concord control validate` run.
type ValidationReport struct {
	YAMLPath    string
	ControlID   string
	RegoPath    string
	RegoLoaded  bool
	PassFixture string
	FailFixture string
	PassResult  *FixtureResult
	FailResult  *FixtureResult
	Errors      []string
}

// FixtureResult records the outcome of running one fixture through the Rego.
type FixtureResult struct {
	Path    string
	Pass    bool
	Deny    []string
	Warn    []string
}

// AllGreen reports whether every check passed.
func (r ValidationReport) AllGreen() bool {
	if len(r.Errors) > 0 {
		return false
	}
	if r.PassResult == nil || !r.PassResult.Pass {
		return false
	}
	if r.FailResult == nil || r.FailResult.Pass {
		return false
	}
	return true
}

// ValidateControl loads a control YAML, compiles its Rego, and runs both fixtures.
func ValidateControl(ctx context.Context, yamlPath string) (ValidationReport, error) {
	r := ValidationReport{YAMLPath: yamlPath}
	c, err := controls.LoadFile(yamlPath)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("yaml schema: %v", err))
		return r, nil
	}
	r.ControlID = c.Metadata.ID

	packDir := packDirFromYAMLPath(yamlPath)
	regoRel := strings.TrimPrefix(c.Spec.Policy.File, "../")
	regoPath := filepath.Join(packDir, regoRel)
	r.RegoPath = regoPath
	src, err := os.ReadFile(regoPath)
	if err != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("rego file: %v", err))
		return r, nil
	}
	r.RegoLoaded = true

	slug := slugFromYAML(yamlPath)
	pass := findFixture(packDir, slug, "pass")
	fail := findFixture(packDir, slug, "fail")
	r.PassFixture = pass
	r.FailFixture = fail

	mods, modErr := collectModules(packDir, regoPath, string(src))
	if modErr != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("collect lib modules: %v", modErr))
		return r, nil
	}
	engine := policy.New()
	if pass != "" {
		res, err := evalFixture(ctx, engine, mods, c.Spec.Policy.Package, pass)
		if err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("pass fixture %s: %v", pass, err))
		} else {
			r.PassResult = res
		}
	}
	if fail != "" {
		res, err := evalFixture(ctx, engine, mods, c.Spec.Policy.Package, fail)
		if err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("fail fixture %s: %v", fail, err))
		} else {
			r.FailResult = res
		}
	}
	if pass == "" {
		r.Errors = append(r.Errors, "no pass fixture found (expected tests/fixtures/<slug>-pass.json)")
	}
	if fail == "" {
		r.Errors = append(r.Errors, "no fail fixture found (expected tests/fixtures/<slug>-fail.json)")
	}
	return r, nil
}

func evalFixture(ctx context.Context, engine *policy.Engine, mods map[string]string, pkg, fixturePath string) (*FixtureResult, error) {
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		return nil, err
	}
	var input map[string]any
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	res, err := engine.EvaluateWithModules(ctx, mods, pkg, input)
	if err != nil {
		return nil, err
	}
	return &FixtureResult{
		Path: fixturePath,
		Pass: res.Pass,
		Deny: res.Deny,
		Warn: res.Warn,
	}, nil
}

func collectModules(packDir, regoPath, regoSrc string) (map[string]string, error) {
	mods := map[string]string{"policy.rego": regoSrc}
	libDir := filepath.Join(packDir, "policies", "lib")
	entries, err := os.ReadDir(libDir)
	if err != nil {
		if os.IsNotExist(err) {
			return mods, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rego") {
			continue
		}
		p := filepath.Join(libDir, e.Name())
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		mods["lib_"+e.Name()] = string(raw)
	}
	return mods, nil
}

func packDirFromYAMLPath(yamlPath string) string {
	abs, err := filepath.Abs(yamlPath)
	if err != nil {
		abs = yamlPath
	}
	return filepath.Dir(filepath.Dir(abs))
}

func slugFromYAML(yamlPath string) string {
	base := filepath.Base(yamlPath)
	return strings.TrimSuffix(strings.TrimSuffix(base, ".yaml"), ".yml")
}

func findFixture(packDir, slug, kind string) string {
	candidate := filepath.Join(packDir, "tests", "fixtures", slug+"-"+kind+".json")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}
