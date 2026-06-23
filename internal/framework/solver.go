package framework

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/concord-dev/concord/internal/controlpacks"
	"github.com/concord-dev/concord/internal/ociart"
)

// MaxExtendsDepth caps `extends:` recursion to avoid runaway expansion of cyclic graphs.
const MaxExtendsDepth = 8

// Plan is what the solver produces: a flat set of pinned artifacts to install.
type Plan struct {
	Frameworks   []ResolvedFramework
	ControlPacks []ResolvedArtifact
	Plugins      []ResolvedArtifact
}

// ResolvedFramework is a workspace-declared (or extended) framework with its concrete version.
type ResolvedFramework struct {
	ID         string
	Source     string
	Version    string
	Constraint string
	Manifest   *Manifest
	Digest     string
}

// ResolvedArtifact is one pinned control pack or plugin in the plan.
type ResolvedArtifact struct {
	Source      string
	Version     string
	Constraints []string
	RequestedBy []string
}

// WorkspaceRef is what the solver consumes for each top-level entry of concord.yaml's frameworks list.
type WorkspaceRef struct {
	Source  string
	Version string
}

// SolveOptions tune Solve.
type SolveOptions struct {
	PlainHTTP bool
}

// Solve resolves a workspace's framework list into a complete, deduplicated install plan.
func Solve(ctx context.Context, refs []WorkspaceRef, opts SolveOptions) (*Plan, error) {
	r := newResolver(opts)
	for _, ref := range refs {
		if err := r.resolveFramework(ctx, ref.Source, ref.Version, "workspace", 0); err != nil {
			return nil, err
		}
	}
	if err := r.resolvePlugins(ctx); err != nil {
		return nil, err
	}
	return r.plan(), nil
}

type resolver struct {
	opts             SolveOptions
	frameworks       map[string]*resolvedFramework
	frameworkOrder   []string
	controlPacks     map[string]*constrained
	controlPackOrder []string
	plugins          map[string]*constrained
	pluginOrder      []string
}

type resolvedFramework struct {
	id         string
	source     string
	version    string
	constraint string
	manifest   *Manifest
	digest     string
}

type constrained struct {
	source      string
	constraints []string
	requestedBy []string
}

func newResolver(opts SolveOptions) *resolver {
	return &resolver{
		opts:         opts,
		frameworks:   make(map[string]*resolvedFramework),
		controlPacks: make(map[string]*constrained),
		plugins:      make(map[string]*constrained),
	}
}

func (r *resolver) resolveFramework(ctx context.Context, source, constraint, requestedBy string, depth int) error {
	if depth > MaxExtendsDepth {
		return fmt.Errorf("framework extends recursion limit (%d) hit at %s — likely a cycle", MaxExtendsDepth, source)
	}

	version, err := ResolveTag(ctx, source, constraint, r.opts.PlainHTTP)
	if err != nil {
		return fmt.Errorf("resolving %s@%s: %w", source, constraint, err)
	}

	if existing, ok := r.frameworks[source]; ok {
		if existing.version != version {
			return fmt.Errorf("framework %s requested at incompatible versions: %s (by %s) and %s (by %s)",
				source, existing.version, existing.constraint, version, constraint)
		}
		return nil
	}

	pulled, err := ociart.Pull(ctx, source+":"+version, ociart.PullOptions{Platform: "any", PlainHTTP: r.opts.PlainHTTP})
	if err != nil {
		return fmt.Errorf("pulling framework %s:%s: %w", source, version, err)
	}
	manifest, err := ParseManifest(pulled.Layer.Bytes)
	if err != nil {
		return fmt.Errorf("framework %s:%s: %w", source, version, err)
	}

	rf := &resolvedFramework{
		id:         manifest.Metadata.ID,
		source:     source,
		version:    version,
		constraint: constraint,
		manifest:   manifest,
		digest:     pulled.Digest,
	}
	r.frameworks[source] = rf
	r.frameworkOrder = append(r.frameworkOrder, source)

	for _, dep := range manifest.Spec.Extends {
		if err := r.resolveFramework(ctx, dep.Source, dep.Version, manifest.Metadata.ID, depth+1); err != nil {
			return err
		}
	}
	for _, dep := range manifest.Spec.ControlPacks {
		r.addConstraint(r.controlPacks, &r.controlPackOrder, dep.Source, dep.Version, manifest.Metadata.ID)
	}
	for _, dep := range manifest.Spec.Plugins {
		r.addConstraint(r.plugins, &r.pluginOrder, dep.Source, dep.Version, manifest.Metadata.ID)
	}
	return nil
}

// resolvePlugins fetches each control pack's pack.yaml, unions its evidence_sources
// into the plugin constraint set, and resolves every plugin source to a concrete tag.
func (r *resolver) resolvePlugins(ctx context.Context) error {
	for _, source := range r.controlPackOrder {
		c := r.controlPacks[source]
		version, err := IntersectAndResolveTag(ctx, source, c.constraints, r.opts.PlainHTTP)
		if err != nil {
			return fmt.Errorf("resolving control pack %s [%s]: %w", source, strings.Join(c.constraints, ", "), err)
		}
		c.constraints = append(c.constraints, "="+version)

		pulled, err := ociart.Pull(ctx, source+":"+version, ociart.PullOptions{Platform: "any", PlainHTTP: r.opts.PlainHTTP})
		if err != nil {
			return fmt.Errorf("pulling control pack %s:%s: %w", source, version, err)
		}
		pack, err := extractPackYAML(pulled.Layer.Bytes)
		if err != nil {
			return fmt.Errorf("inspecting %s:%s: %w", source, version, err)
		}
		for _, es := range pack.Spec.EvidenceSources {
			pluginSource := pluginOCIRefFor(es.Source)
			r.addConstraint(r.plugins, &r.pluginOrder, pluginSource, es.Version, pack.Metadata.ID)
		}
	}
	for _, source := range r.pluginOrder {
		c := r.plugins[source]
		version, err := IntersectAndResolveTag(ctx, source, c.constraints, r.opts.PlainHTTP)
		if err != nil {
			return fmt.Errorf("resolving plugin %s [%s]: %w", source, strings.Join(c.constraints, ", "), err)
		}
		c.constraints = append(c.constraints, "="+version)
	}
	return nil
}

func (r *resolver) addConstraint(set map[string]*constrained, order *[]string, source, constraint, requestedBy string) {
	if c, ok := set[source]; ok {
		c.constraints = append(c.constraints, constraint)
		c.requestedBy = append(c.requestedBy, requestedBy)
		return
	}
	set[source] = &constrained{source: source, constraints: []string{constraint}, requestedBy: []string{requestedBy}}
	*order = append(*order, source)
}

func (r *resolver) plan() *Plan {
	p := &Plan{}
	for _, s := range r.frameworkOrder {
		f := r.frameworks[s]
		p.Frameworks = append(p.Frameworks, ResolvedFramework{
			ID:         f.id,
			Source:     f.source,
			Version:    f.version,
			Constraint: f.constraint,
			Manifest:   f.manifest,
			Digest:     f.digest,
		})
	}
	for _, s := range r.controlPackOrder {
		c := r.controlPacks[s]
		version := concreteVersion(c.constraints)
		p.ControlPacks = append(p.ControlPacks, ResolvedArtifact{
			Source: s, Version: version, Constraints: c.constraints, RequestedBy: dedup(c.requestedBy),
		})
	}
	for _, s := range r.pluginOrder {
		c := r.plugins[s]
		version := concreteVersion(c.constraints)
		p.Plugins = append(p.Plugins, ResolvedArtifact{
			Source: s, Version: version, Constraints: c.constraints, RequestedBy: dedup(c.requestedBy),
		})
	}
	return p
}

// ResolveTag picks the highest tag in source that satisfies constraint.
// Constraint accepts "vX.Y.Z" (exact), "^vX.Y.Z" (caret), "~vX.Y" (tilde),
// ">=vX.Y,<vA.B" (range), or "" (latest).
func ResolveTag(ctx context.Context, source, constraint string, plainHTTP bool) (string, error) {
	return IntersectAndResolveTag(ctx, source, []string{constraint}, plainHTTP)
}

// IntersectAndResolveTag picks the highest tag satisfying every constraint in the set.
func IntersectAndResolveTag(ctx context.Context, source string, constraints []string, plainHTTP bool) (string, error) {
	if v, ok := allEqual(constraints); ok {
		return v, nil
	}
	tags, err := listTags(ctx, source, plainHTTP)
	if err != nil {
		return "", err
	}
	parsed, err := parseConstraints(constraints)
	if err != nil {
		return "", err
	}
	matching := filterMatching(tags, parsed)
	if len(matching) == 0 {
		return "", fmt.Errorf("no tag in %s satisfies %s (available: %s)",
			source, strings.Join(constraints, ", "), strings.Join(tags, ", "))
	}
	sort.Sort(byVersionDesc(matching))
	return tagString(matching[0]), nil
}

func allEqual(constraints []string) (string, bool) {
	pinned := ""
	for _, c := range constraints {
		if strings.HasPrefix(c, "=") {
			candidate := strings.TrimPrefix(c, "=")
			if pinned == "" {
				pinned = candidate
			} else if pinned != candidate {
				return "", false
			}
		}
	}
	return pinned, pinned != ""
}

func listTags(ctx context.Context, source string, plainHTTP bool) ([]string, error) {
	ref, err := ociart.ParseRef(source + ":any")
	if err != nil {
		return nil, err
	}
	repo, err := remote.NewRepository(ref.Host + "/" + ref.Repo)
	if err != nil {
		return nil, err
	}
	repo.PlainHTTP = plainHTTP

	var tags []string
	err = repo.Tags(ctx, "", func(page []string) error {
		tags = append(tags, page...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing tags for %s: %w", source, err)
	}
	return tags, nil
}

type semverTag struct {
	tag string
	v   *semver.Version
}

type byVersionDesc []semverTag

func (b byVersionDesc) Len() int           { return len(b) }
func (b byVersionDesc) Less(i, j int) bool { return b[i].v.GreaterThan(b[j].v) }
func (b byVersionDesc) Swap(i, j int)      { b[i], b[j] = b[j], b[i] }

func parseConstraints(constraints []string) ([]*semver.Constraints, error) {
	out := make([]*semver.Constraints, 0, len(constraints))
	for _, c := range constraints {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.HasPrefix(c, "=") {
			c = strings.TrimPrefix(c, "=")
		}
		cleaned := strings.ReplaceAll(c, "v", "")
		parsed, err := semver.NewConstraint(cleaned)
		if err != nil {
			return nil, fmt.Errorf("invalid constraint %q: %w", c, err)
		}
		out = append(out, parsed)
	}
	return out, nil
}

func filterMatching(tags []string, constraints []*semver.Constraints) []semverTag {
	var out []semverTag
	for _, t := range tags {
		v, err := semver.NewVersion(t)
		if err != nil {
			continue
		}
		if v.Prerelease() != "" {
			continue
		}
		ok := true
		for _, c := range constraints {
			if !c.Check(v) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, semverTag{tag: t, v: v})
		}
	}
	return out
}

func tagString(t semverTag) string {
	if strings.HasPrefix(t.tag, "v") {
		return t.tag
	}
	return "v" + t.v.String()
}

func concreteVersion(constraints []string) string {
	for _, c := range constraints {
		if strings.HasPrefix(c, "=") {
			return strings.TrimPrefix(c, "=")
		}
	}
	return ""
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// pluginOCIRefFor turns a source name (e.g. "snyk") into the canonical OCI
// artifact ref for that plugin. Used when control packs declare evidence
// dependencies by source name rather than full ref.
func pluginOCIRefFor(source string) string {
	if strings.Contains(source, "/") {
		return source
	}
	return "ghcr.io/concord-dev/concord-plugin-" + source
}

func extractPackYAML(tgz []byte) (*controlpacks.Pack, error) {
	pack, err := controlpacks.ParsePackTarball(tgz)
	if err != nil {
		return nil, err
	}
	if pack == nil {
		return nil, errors.New("pack.yaml not found in tarball")
	}
	return pack, nil
}
