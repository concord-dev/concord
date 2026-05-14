// Package openapi embeds the Concord HTTP API specification.
//
// The spec is split across multiple YAML chunks (base.yaml, schemas.yaml,
// paths_public.yaml, paths_org.yaml, paths_admin.yaml) so no single file
// breaks the per-file LOC budget. They're combined at startup by a
// recursive-map merger and the result is cached for subsequent requests.
//
// The split files are not generated artifacts — every new route lands in
// one of the chunks alongside its handler in the same change.
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

// SpecYAML returns the merged spec bytes. First call walks the embedded
// chunks; subsequent calls return the cached blob.
func SpecYAML() ([]byte, error) {
	specOnce.Do(func() {
		specBytes, specErr = mergeChunks()
	})
	return specBytes, specErr
}

// mergeChunks reads every embedded *.yaml file, parses it as a top-level
// object, and deep-merges them into one document. Chunks are loaded in
// lexical filename order so the merge result is deterministic.
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

// deepMerge folds src into dst. Maps recurse; scalar keys collide loudly so
// accidental duplicates across files don't silently overwrite each other.
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
