package evidence

import (
	"errors"
	"fmt"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type Registry struct {
	collectors    map[string]Collector
	fileCollector *FileCollector
	fixturesOnly  bool
}

func NewRegistry() *Registry {
	r := &Registry{
		collectors:    make(map[string]Collector),
		fileCollector: NewFileCollector(),
	}
	r.collectors["file"] = r.fileCollector
	return r
}

func (r *Registry) Register(source string, c Collector) {
	r.collectors[source] = c
}

func (r *Registry) SetFixturesOnly(b bool) {
	r.fixturesOnly = b
}

// Has reports whether a non-file collector is registered for source.
func (r *Registry) Has(source string) bool {
	if source == "file" {
		return false
	}
	_, ok := r.collectors[source]
	return ok
}

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
