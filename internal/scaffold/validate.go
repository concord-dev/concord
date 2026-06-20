package scaffold

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/concord-dev/concord/internal/policy"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
	"github.com/concord-dev/concord/pkg/controls"
	"github.com/concord-dev/concord/pkg/evidencetype"
)

// ValidationReport summarises a `concord control validate` run.
type ValidationReport struct {
	YAMLPath     string
	ControlID    string
	RegoPath     string
	RegoLoaded   bool
	PassFixture  string
	FailFixture  string
	PassResult   *FixtureResult
	FailResult   *FixtureResult
	SchemaChecks []SchemaCheck
	Errors       []string
}

// SchemaCheck records validating one fixture's evidence payload against the
// EvidenceType schema declared for its (source, type).
type SchemaCheck struct {
	Fixture    string
	EvidenceID string
	TypeRef    string
	OK         bool
	Err        string
}

// FixtureResult records the outcome of running one fixture through the Rego.
type FixtureResult struct {
	Path string
	Pass bool
	Deny []string
	Warn []string
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
	for _, sc := range r.SchemaChecks {
		if !sc.OK {
			return false
		}
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
	pass, fail := fixturesForControl(c, packDir, slug)
	r.PassFixture = pass
	r.FailFixture = fail

	mods, modErr := collectModules(packDir, regoPath, string(src))
	if modErr != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("collect lib modules: %v", modErr))
		return r, nil
	}
	engine := policy.New()
	evidenceIDs := evidenceIDsFor(c)
	if pass != "" {
		res, err := evalFixture(ctx, engine, mods, c.Spec.Policy.Package, pass, evidenceIDs)
		if err != nil {
			r.Errors = append(r.Errors, fmt.Sprintf("pass fixture %s: %v", pass, err))
		} else {
			r.PassResult = res
		}
	}
	if fail != "" {
		res, err := evalFixture(ctx, engine, mods, c.Spec.Policy.Package, fail, evidenceIDs)
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

	reg, regErr := evidencetype.LoadDir(filepath.Join(packDir, "evidence-types"))
	if regErr != nil {
		r.Errors = append(r.Errors, fmt.Sprintf("loading evidence types: %v", regErr))
	} else if reg.Len() > 0 {
		for _, fx := range []string{pass, fail} {
			if fx == "" {
				continue
			}
			r.SchemaChecks = append(r.SchemaChecks, schemaChecks(reg, c, fx, evidenceIDs)...)
		}
	}
	return r, nil
}

// schemaChecks validates each evidence payload in a fixture against the
// EvidenceType schema declared for its (source, type). Evidence refs without
// a registered type are skipped, so the check is opt-in per pack.
//
// Payload attribution is deterministic to avoid false failures: a fixture is
// "wrapped" only when its top-level keys are exactly the evidence ids, in
// which case each payload is parsed[id]. A "bare" fixture carries a single
// payload, so it is validated only when exactly one evidence ref has a
// registered type (otherwise it cannot be attributed unambiguously and is
// skipped). This sidesteps the wrapped-vs-bare ambiguity of the Rego-input
// normaliser, which tolerates shape differences that strict schema
// validation does not.
func schemaChecks(reg *evidencetype.Registry, c apiv1.Control, fixturePath string, evidenceIDs []string) []SchemaCheck {
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		return []SchemaCheck{{Fixture: fixturePath, OK: false, Err: err.Error()}}
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return []SchemaCheck{{Fixture: fixturePath, OK: false, Err: "parse: " + err.Error()}}
	}

	typed := make([]apiv1.EvidenceRef, 0, len(c.Spec.Evidence))
	for _, ev := range c.Spec.Evidence {
		if ev.Type != "" && reg.Has(evidencetype.RefFor(ev.Source, ev.Type)) {
			typed = append(typed, ev)
		}
	}
	if len(typed) == 0 {
		return nil
	}

	var out []SchemaCheck
	if fixtureIsWrapped(parsed, evidenceIDs) {
		for _, ev := range typed {
			payload, ok := parsed[ev.ID]
			if !ok {
				continue
			}
			out = append(out, checkPayload(reg, ev, fixturePath, payload))
		}
		return out
	}
	// Bare fixture: a single payload. Attribute it only when unambiguous.
	if len(typed) == 1 {
		out = append(out, checkPayload(reg, typed[0], fixturePath, parsed))
	}
	return out
}

func checkPayload(reg *evidencetype.Registry, ev apiv1.EvidenceRef, fixturePath string, payload any) SchemaCheck {
	ref := evidencetype.RefFor(ev.Source, ev.Type)
	sc := SchemaCheck{Fixture: fixturePath, EvidenceID: ev.ID, TypeRef: ref, OK: true}
	if err := reg.ValidatePayload(ref, payload); err != nil {
		sc.OK = false
		sc.Err = err.Error()
	}
	return sc
}

// fixtureIsWrapped reports whether a fixture's top-level keys are exactly the
// evidence ids — the only unambiguous signal that it carries one payload per
// evidence rather than a single bare payload.
func fixtureIsWrapped(parsed map[string]any, evidenceIDs []string) bool {
	if len(evidenceIDs) == 0 || len(parsed) != len(evidenceIDs) {
		return false
	}
	for _, id := range evidenceIDs {
		if _, ok := parsed[id]; !ok {
			return false
		}
	}
	return true
}

func evalFixture(ctx context.Context, engine *policy.Engine, mods map[string]string, pkg, fixturePath string, evidenceIDs []string) (*FixtureResult, error) {
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		return nil, err
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	input := normaliseFixture(parsed, evidenceIDs)
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

// normaliseFixture wraps raw evidence under the control's evidence IDs to
// match the runtime CollectAll behaviour. If the parsed fixture already
// contains every evidence id at top level it is returned unchanged so the
// scaffold-emitted pre-wrapped fixtures keep working.
func normaliseFixture(parsed map[string]any, evidenceIDs []string) map[string]any {
	if alreadyWrapped(parsed, evidenceIDs) {
		return parsed
	}
	if len(evidenceIDs) == 1 {
		return map[string]any{evidenceIDs[0]: parsed}
	}
	return parsed
}

func alreadyWrapped(parsed map[string]any, evidenceIDs []string) bool {
	if len(evidenceIDs) == 0 {
		return true
	}
	for _, id := range evidenceIDs {
		if _, ok := parsed[id]; !ok {
			return false
		}
	}
	return true
}

func evidenceIDsFor(c apiv1.Control) []string {
	out := make([]string, 0, len(c.Spec.Evidence))
	for _, ev := range c.Spec.Evidence {
		if ev.ID != "" {
			out = append(out, ev.ID)
		}
	}
	return out
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

// fixturesForControl resolves pass + fail fixture paths, preferring the YAML's
// explicit fixture: field and deriving the fail variant from it; otherwise
// falling back to the <slug>-{pass,fail}.json convention.
func fixturesForControl(c apiv1.Control, packDir, slug string) (string, string) {
	for _, ev := range c.Spec.Evidence {
		if ev.Fixture == "" {
			continue
		}
		passPath := resolveRelative(packDir, ev.Fixture, slug)
		if passPath == "" {
			continue
		}
		base := filepath.Base(passPath)
		dir := filepath.Dir(passPath)
		failName := strings.Replace(base, "-pass.json", "-fail.json", 1)
		if failName == base {
			failName = strings.TrimSuffix(base, ".json") + "-fail.json"
		}
		failPath := filepath.Join(dir, failName)
		if _, err := os.Stat(failPath); err != nil {
			failPath = ""
		}
		return passPath, failPath
	}
	return findFixture(packDir, slug, "pass"), findFixture(packDir, slug, "fail")
}

// resolveRelative anchors a fixture path declared in YAML to packDir + controls/.
func resolveRelative(packDir, fixture, _ string) string {
	if filepath.IsAbs(fixture) {
		if _, err := os.Stat(fixture); err == nil {
			return fixture
		}
		return ""
	}
	candidate := filepath.Clean(filepath.Join(packDir, "controls", fixture))
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}
