package plugin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
)

// SimpleCollector is the high-level plugin interface introduced in SDK v2.
// Implementers declare what they handle, the SDK takes care of routing,
// unsupported-type errors, and capability synthesis.
type SimpleCollector interface {
	Source() string
	Version() string
	Probe(ctx context.Context) error
	Handlers() []TypeHandler
}

// TypeHandler binds an evidence type name to the function that produces evidence for it.
type TypeHandler struct {
	Type        string
	Description string
	Handle      func(ctx context.Context, ref EvidenceRef) (any, error)
}

// SimpleOption customises the SDK wrapper.
type SimpleOption func(*simpleAdapter)

// WithDocs sets the DocsURL field reported in Capabilities.
func WithDocs(url string) SimpleOption { return func(s *simpleAdapter) { s.docs = url } }

// WithRequiredEnv records required env vars in Capabilities and fails Probe when any are missing.
func WithRequiredEnv(keys ...string) SimpleOption {
	return func(s *simpleAdapter) { s.requiredEnv = append(s.requiredEnv, keys...) }
}

// WithOptionalEnv records optional env vars in Capabilities.
func WithOptionalEnv(keys ...string) SimpleOption {
	return func(s *simpleAdapter) { s.optionalEnv = append(s.optionalEnv, keys...) }
}

// WithPermissions advertises the runtime permissions Concord should grant.
func WithPermissions(p Permissions) SimpleOption { return func(s *simpleAdapter) { s.perms = p } }

// WithEmbedsBinaries lists upstream binaries bundled inside the plugin's OCI artifact.
func WithEmbedsBinaries(bins ...string) SimpleOption {
	return func(s *simpleAdapter) { s.embedsBinaries = append(s.embedsBinaries, bins...) }
}

// ServeSimple runs the plugin's main loop using the high-level adapter.
func ServeSimple(impl SimpleCollector, opts ...SimpleOption) {
	if impl == nil {
		panic("plugin.ServeSimple: nil SimpleCollector")
	}
	Serve(NewSimpleAdapter(impl, opts...))
}

// NewSimpleAdapter wraps a SimpleCollector as the low-level Collector interface.
// Useful for tests that exercise the plugin without spinning up gRPC.
func NewSimpleAdapter(impl SimpleCollector, opts ...SimpleOption) Collector {
	a := &simpleAdapter{impl: impl}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

type simpleAdapter struct {
	impl           SimpleCollector
	docs           string
	requiredEnv    []string
	optionalEnv    []string
	perms          Permissions
	embedsBinaries []string
}

func (a *simpleAdapter) Capabilities() Capabilities {
	handlers := a.impl.Handlers()
	types := make([]string, 0, len(handlers))
	for _, h := range handlers {
		types = append(types, h.Type)
	}
	sort.Strings(types)
	return Capabilities{
		Source:         a.impl.Source(),
		Version:        a.impl.Version(),
		SupportedTypes: types,
		RequiredEnv:    append([]string(nil), a.requiredEnv...),
		OptionalEnv:    append([]string(nil), a.optionalEnv...),
		Permissions:    a.perms,
		DocsURL:        a.docs,
		EmbedsBinaries: append([]string(nil), a.embedsBinaries...),
	}
}

func (a *simpleAdapter) Probe(ctx context.Context) (string, error) {
	for _, key := range a.requiredEnv {
		if v := os.Getenv(key); v == "" {
			return "", fmt.Errorf("plugin.simple: required env %s is empty", key)
		}
	}
	if err := a.impl.Probe(ctx); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s %s ready", a.impl.Source(), a.impl.Version()), nil
}

func (a *simpleAdapter) Collect(ctx context.Context, ref EvidenceRef) (any, error) {
	for _, h := range a.impl.Handlers() {
		if h.Type == ref.Type {
			if h.Handle == nil {
				return nil, errors.New("plugin.simple: handler is nil")
			}
			return h.Handle(ctx, ref)
		}
	}
	return nil, ErrUnsupportedType
}
