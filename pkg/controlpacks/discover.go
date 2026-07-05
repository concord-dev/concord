package controlpacks

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Discovered describes a single control pack found on disk.
type Discovered struct {
	Framework string
	Version   string
	Dir       string
	Pack      *Pack
}

// ResolveInstallRoot returns the pack install root, defaulting to
// ~/.concord/controlpacks when root is empty.
func ResolveInstallRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home dir: %w", err)
	}
	return filepath.Join(home, ".concord", "controlpacks"), nil
}

// Discover walks installRoot and returns every readable, schema-valid pack
// (newest version per framework). An absent root is not an error — it yields
// no packs, so a consumer can call it unconditionally.
func Discover(installRoot string) ([]Discovered, error) {
	root, err := ResolveInstallRoot(installRoot)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading %s: %w", root, err)
	}
	var out []Discovered
	for _, fwEntry := range entries {
		if !fwEntry.IsDir() {
			continue
		}
		discovered := newestVersion(filepath.Join(root, fwEntry.Name()), fwEntry.Name())
		if discovered != nil {
			out = append(out, *discovered)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Framework < out[j].Framework })
	return out, nil
}

func newestVersion(frameworkDir, framework string) *Discovered {
	versionEntries, err := os.ReadDir(frameworkDir)
	if err != nil {
		return nil
	}
	var versionDirs []string
	for _, v := range versionEntries {
		if v.IsDir() {
			versionDirs = append(versionDirs, v.Name())
		}
	}
	if len(versionDirs) == 0 {
		return nil
	}
	sort.Strings(versionDirs)
	ver := versionDirs[len(versionDirs)-1]
	dir := filepath.Join(frameworkDir, ver)

	pack, err := ParsePack(filepath.Join(dir, PackFile))
	if err != nil {
		return nil
	}
	return &Discovered{Framework: framework, Version: ver, Dir: dir, Pack: pack}
}

// ControlsDirs returns the directories containing per-control YAML for a
// control loader to walk: each pack's controls/ subdir, or the pack root when
// that subdir is absent.
func ControlsDirs(packs []Discovered) []string {
	out := make([]string, 0, len(packs))
	for _, p := range packs {
		controlsDir := filepath.Join(p.Dir, "controls")
		if info, err := os.Stat(controlsDir); err == nil && info.IsDir() {
			out = append(out, controlsDir)
			continue
		}
		out = append(out, p.Dir)
	}
	return out
}
