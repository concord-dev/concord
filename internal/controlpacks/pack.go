// Package controlpacks installs, manages, and enumerates Concord control packs
// distributed as OCI artifacts. The manifest schema and read-only on-disk
// discovery now live in the public pkg/controlpacks so other modules (the
// platform server) can read an installed catalog; this package re-exports them
// and adds the OCI fetch + cosign-verify install path that stays internal.
package controlpacks

import pcp "github.com/concord-dev/concord/pkg/controlpacks"

// PackFile is the metadata file at the root of every control pack.
const PackFile = pcp.PackFile

// Re-exported manifest + discovery types so existing internal/CLI callers keep
// their controlpacks.Pack / controlpacks.Discovered spellings.
type (
	Pack           = pcp.Pack
	PackMetadata   = pcp.PackMetadata
	PackSpec       = pcp.PackSpec
	EvidenceSource = pcp.EvidenceSource
	Discovered     = pcp.Discovered
)

// ParsePack reads and validates a pack.yaml file.
func ParsePack(path string) (*Pack, error) { return pcp.ParsePack(path) }

// ParsePackTarball reads pack.yaml from a gzipped tar byte slice.
func ParsePackTarball(tgz []byte) (*Pack, error) { return pcp.ParsePackTarball(tgz) }

// PackDir is the on-disk location for an installed pack.
func PackDir(installRoot, framework, version string) string {
	return pcp.PackDir(installRoot, framework, version)
}

// Discover walks installRoot and returns every readable, schema-valid pack.
func Discover(installRoot string) ([]Discovered, error) { return pcp.Discover(installRoot) }

// ControlsDirs returns the dirs containing per-control YAML for the loader to walk.
func ControlsDirs(packs []Discovered) []string { return pcp.ControlsDirs(packs) }

// resolveInstallRoot resolves the pack install root (default ~/.concord/controlpacks).
func resolveInstallRoot(root string) (string, error) { return pcp.ResolveInstallRoot(root) }
