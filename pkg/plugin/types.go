package plugin

import (
	"context"
	"errors"
)

// Collector is the interface a plugin author implements.
type Collector interface {
	Capabilities() Capabilities
	Probe(ctx context.Context) (string, error)
	Collect(ctx context.Context, ref EvidenceRef) (any, error)
}

// Capabilities declares what a plugin can do and what env it needs.
type Capabilities struct {
	Source         string
	Version        string
	SupportedTypes []string
	RequiredEnv    []string
	OptionalEnv    []string
	Permissions    Permissions
	DocsURL        string
	// EmbedsBinaries lists upstream tools bundled inside the plugin's OCI
	// artifact (e.g. "prowler@v5.7.5"). Advisory; consumed by `concord
	// doctor` so users see "bundled" instead of "missing on PATH".
	EmbedsBinaries []string
}

// Permissions advertises a plugin's runtime needs. Host-side enforcement lives at internal/plugins/env.go.
type Permissions struct {
	Network    []string
	Filesystem string
	Subprocess bool
}

// EvidenceRef mirrors apiv1.EvidenceRef for plugin authors.
type EvidenceRef struct {
	ID       string
	Source   string
	Type     string
	Optional bool
	Params   map[string]any
	Fixture  string
}

// ErrUnsupportedType is the sentinel a plugin returns when asked for an EvidenceRef.Type it doesn't handle.
var ErrUnsupportedType = errors.New("plugin: evidence type not supported by this collector")
