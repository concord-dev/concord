package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

type Context struct {
	ControlDir string
}

type Collector interface {
	Collect(cctx Context, ref apiv1.EvidenceRef) (any, error)
}

type FileCollector struct{}

func NewFileCollector() *FileCollector {
	return &FileCollector{}
}

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
