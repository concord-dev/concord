package openapi

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"

	"sigs.k8s.io/yaml"
)

//go:embed *.yaml
var specFS embed.FS

var (
	specOnce  sync.Once
	specBytes []byte
	specErr   error
)

func SpecYAML() ([]byte, error) {
	specOnce.Do(func() {
		specBytes, specErr = mergeChunks()
	})
	return specBytes, specErr
}

func mergeChunks() ([]byte, error) {
	entries, err := fs.ReadDir(specFS, ".")
	if err != nil {
		return nil, fmt.Errorf("reading embedded spec dir: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	merged := map[string]any{}
	for _, n := range names {
		raw, err := specFS.ReadFile(n)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", n, err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", n, err)
		}
		if err := deepMerge(merged, doc, n); err != nil {
			return nil, err
		}
	}
	return yaml.Marshal(merged)
}

func deepMerge(dst, src map[string]any, srcName string) error {
	for k, v := range src {
		existing, hasExisting := dst[k]
		if !hasExisting {
			dst[k] = v
			continue
		}
		dstMap, dstOK := existing.(map[string]any)
		srcMap, srcOK := v.(map[string]any)
		if dstOK && srcOK {
			if err := deepMerge(dstMap, srcMap, srcName); err != nil {
				return err
			}
			continue
		}
		return fmt.Errorf("duplicate key %q across spec chunks (last seen in %s); "+
			"only nested objects may merge", k, srcName)
	}
	return nil
}
