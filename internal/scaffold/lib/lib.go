// Package lib embeds the concord.lib.* Rego helpers so scaffold can drop them into new packs.
package lib

import "embed"

//go:embed *.rego
var FS embed.FS

// Files returns every (filename, contents) helper pair embedded in this package.
func Files() (map[string]string, error) {
	out := map[string]string{}
	entries, err := FS.ReadDir(".")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := FS.ReadFile(e.Name())
		if err != nil {
			return nil, err
		}
		out[e.Name()] = string(raw)
	}
	return out, nil
}
