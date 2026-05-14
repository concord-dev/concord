package evidence

import (
	"errors"
	"fmt"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Registry dispatches evidence collection to the right collector by source.
// It implements Collector so the runner stays unaware of the dispatch logic.
type Registry struct {
	collectors    map[string]Collector
	fileCollector *FileCollector
	fixturesOnly  bool
}

// NewRegistry returns a Registry with the file source pre-registered.
func NewRegistry() *Registry {
	r := &Registry{
		collectors:    make(map[string]Collector),
		fileCollector: NewFileCollector(),
	}
	r.collectors["file"] = r.fileCollector
	return r
}

// Register binds a collector to a source name.
func (r *Registry) Register(source string, c Collector) {
	r.collectors[source] = c
}

// SetFixturesOnly forces every evidence ref to be served by the file collector.
func (r *Registry) SetFixturesOnly(b bool) {
	r.fixturesOnly = b
}

// Sources returns the registered source names (excluding the file fallback).
func (r *Registry) Sources() []string {
	out := make([]string, 0, len(r.collectors))
	for s := range r.collectors {
		if s == "file" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Collect routes the ref to the right collector. Order:
//  1. fixtures-only → file collector
//  2. registered collector for ref.Source → use it; on ErrUnsupportedType fall through
//  3. ref.Fixture set → fall back to file collector
//  4. otherwise → error
func (r *Registry) Collect(cctx Context, ref apiv1.EvidenceRef) (any, error) {
	if r.fixturesOnly {
		return r.fileCollector.Collect(cctx, ref)
	}
	if c, ok := r.collectors[ref.Source]; ok {
		v, err := c.Collect(cctx, ref)
		if err == nil {
			return v, nil
		}
		if !errors.Is(err, ErrUnsupportedType) {
			return nil, err
		}
	}
	if ref.Fixture != "" {
		return r.fileCollector.Collect(cctx, ref)
	}
	return nil, fmt.Errorf("no collector registered for source %q and no fixture set", ref.Source)
}
