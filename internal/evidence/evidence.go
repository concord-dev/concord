// Package evidence loads evidence in the shape policies consume.
package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

// Context is the per-control environment passed to collectors.
type Context struct {
	ControlDir string
}

// Collector resolves one EvidenceRef to a value usable as policy input.
type Collector interface {
	Collect(cctx Context, ref apiv1.EvidenceRef) (any, error)
}

// FileCollector reads evidence from JSON files on disk. This is the v0
// collector — real cloud collectors (AWS, GitHub, MLflow) plug in alongside.
type FileCollector struct{}

// NewFileCollector returns a FileCollector.
func NewFileCollector() *FileCollector {
	return &FileCollector{}
}

// Collect resolves ref.Fixture relative to cctx.ControlDir and parses JSON.
// The fixture path is env-substituted (${env.X}) before resolution, so
// production deployments can point at CI-generated artifacts via env vars.
func (c *FileCollector) Collect(cctx Context, ref apiv1.EvidenceRef) (any, error) {
	if ref.Fixture == "" {
		return nil, fmt.Errorf("no fixture path set")
	}
	path := ResolveEnv(ref.Fixture)
	if path == "" {
		return nil, fmt.Errorf("fixture path %q resolved to empty (env var unset?)", ref.Fixture)
	}
	if !filepath.IsAbs(path) {
		path = filepath.Join(cctx.ControlDir, path)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading fixture: %w", err)
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parsing fixture %s: %w", path, err)
	}
	return v, nil
}

// CollectAll runs each ref through c and returns a map keyed by ref.ID.
// Refs marked optional are skipped silently on error.
func CollectAll(c Collector, cctx Context, refs []apiv1.EvidenceRef) (map[string]any, error) {
	out := make(map[string]any, len(refs))
	var errs []error
	for _, ref := range refs {
		v, err := c.Collect(cctx, ref)
		if err != nil {
			if ref.Optional {
				continue
			}
			errs = append(errs, fmt.Errorf("%s: %w", ref.ID, err))
			continue
		}
		out[ref.ID] = v
	}
	if len(errs) > 0 {
		return out, errors.Join(errs...)
	}
	return out, nil
}
