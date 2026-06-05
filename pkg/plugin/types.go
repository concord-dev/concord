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

// Capabilities is returned from Capabilities() — declares what the
// plugin can do and what env it needs.
type Capabilities struct {
	Source         string
	Version        string
	SupportedTypes []string
	RequiredEnv    []string
	OptionalEnv    []string
	Permissions    Permissions
	DocsURL        string
}

// Permissions describes what the plugin needs at runtime. Currently
// advisory; capability enforcement is host-side and lives at
// internal/plugins/env.go.
type Permissions struct {
	Network    []string
	Filesystem string
	Subprocess bool
}

// EvidenceRef mirrors apiv1.EvidenceRef but lives in this public SDK
// package so plugin authors don't depend on internal/.
type EvidenceRef struct {
	ID       string
	Source   string
	Type     string
	Optional bool
	Params   map[string]any
	Fixture  string
}

// ErrUnsupportedType is the sentinel a plugin returns when asked for
// an EvidenceRef.Type it doesn't handle. The host translates this to
// the legacy evidence.ErrUnsupportedType so existing fixture-fallback
// semantics survive.
var ErrUnsupportedType = errors.New("plugin: evidence type not supported by this collector")
