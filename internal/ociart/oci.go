// Package ociart pulls and verifies generic OCI artifacts — plugin
// binaries, control-pack tarballs, framework manifests — from any
// registry that speaks the distribution spec.
package ociart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// Concord-specific media types.
const (
	MediaTypePluginBinary    = "application/vnd.concord.plugin.binary.v1"
	MediaTypeControlPackTar  = "application/vnd.concord.controlpack.v1.tar.gz"
	MediaTypeFrameworkYAML   = "application/vnd.concord.framework.v1+yaml"
)

// Concord-specific annotation keys.
const (
	AnnotationKind            = "org.concord.dev.artifact.kind"
	AnnotationPluginSource    = "org.concord.dev.plugin.source"
	AnnotationPluginProtocol  = "org.concord.dev.plugin.protocol"
	AnnotationPackFramework   = "org.concord.dev.controlpack.framework"
	AnnotationPackSources     = "org.concord.dev.controlpack.evidence_sources"
	AnnotationFrameworkID     = "org.concord.dev.framework.id"

	KindPlugin      = "plugin"
	KindControlPack = "controlpack"
	KindFramework   = "framework"
)

// ErrPlatformNotFound is returned when an image-index has no manifest matching the requested platform.
var ErrPlatformNotFound = errors.New("no manifest for requested platform")

// PullOptions tune Pull.
type PullOptions struct {
	Platform  string
	PlainHTTP bool
}

// Layer carries one fetched layer's metadata and bytes.
type Layer struct {
	MediaType string
	Digest    string
	Size      int64
	Bytes     []byte
}

// PullResult describes a successfully pulled OCI artifact.
type PullResult struct {
	Reference   string
	Artifact    string
	Tag         string
	Digest      string
	Platform    string
	Annotations map[string]string
	Layer       Layer
}

// Pull resolves ref, picks the right manifest for the requested platform,
// fetches the (single) layer, and returns its bytes plus merged annotations.
func Pull(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	parsed, err := ParseRef(ref)
	if err != nil {
		return nil, err
	}
	platform := opts.Platform
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}

	repo, err := newRepository(parsed.Host+"/"+parsed.Repo, opts.PlainHTTP)
	if err != nil {
		return nil, fmt.Errorf("connecting to registry: %w", err)
	}

	root, err := repo.Resolve(ctx, parsed.Reference)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", ref, err)
	}

	manifestDesc, err := selectManifest(ctx, repo, root, platform)
	if err != nil {
		return nil, err
	}

	manifest, err := fetchManifest(ctx, repo, manifestDesc)
	if err != nil {
		return nil, err
	}
	if len(manifest.Layers) == 0 {
		return nil, fmt.Errorf("manifest %s has no layers", manifestDesc.Digest)
	}

	layerDesc := manifest.Layers[0]
	bytes, err := fetchLayerBytes(ctx, repo, layerDesc)
	if err != nil {
		return nil, err
	}

	return &PullResult{
		Reference:   ref,
		Artifact:    parsed.Host + "/" + parsed.Repo,
		Tag:         parsed.Reference,
		Digest:      manifestDesc.Digest.String(),
		Platform:    platform,
		Annotations: manifest.Annotations,
		Layer: Layer{
			MediaType: layerDesc.MediaType,
			Digest:    layerDesc.Digest.String(),
			Size:      layerDesc.Size,
			Bytes:     bytes,
		},
	}, nil
}

// Ref is a parsed OCI reference: ghcr.io/owner/repo:tag or @digest.
type Ref struct {
	Host      string
	Repo      string
	Reference string
	IsDigest  bool
}

// ParseRef splits ref into host, repo, and tag/digest.
func ParseRef(ref string) (Ref, error) {
	if ref == "" {
		return Ref{}, errors.New("empty OCI ref")
	}
	hostRepo, refPart, ok := splitRef(ref)
	if !ok {
		return Ref{}, fmt.Errorf("missing tag or digest in %q (use repo:tag or repo@sha256:...)", ref)
	}
	slash := strings.Index(hostRepo, "/")
	if slash < 0 {
		return Ref{}, fmt.Errorf("missing registry host in %q", ref)
	}
	return Ref{
		Host:      hostRepo[:slash],
		Repo:      hostRepo[slash+1:],
		Reference: refPart,
		IsDigest:  strings.HasPrefix(refPart, "sha256:"),
	}, nil
}

func splitRef(ref string) (hostRepo, reference string, ok bool) {
	if at := strings.LastIndex(ref, "@"); at >= 0 {
		return ref[:at], ref[at+1:], true
	}
	if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		return ref[:colon], ref[colon+1:], true
	}
	return "", "", false
}

func newRepository(name string, plainHTTP bool) (*remote.Repository, error) {
	repo, err := remote.NewRepository(name)
	if err != nil {
		return nil, err
	}
	repo.PlainHTTP = plainHTTP

	client := &auth.Client{Client: retry.DefaultClient, Cache: auth.NewCache()}
	if store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{}); err == nil {
		client.Credential = credentials.Credential(store)
	}
	repo.Client = client
	return repo, nil
}

func selectManifest(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor, platform string) (ocispec.Descriptor, error) {
	if !isImageIndex(desc.MediaType) {
		return desc, nil
	}
	raw, err := fetchAll(ctx, repo, desc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("fetching index %s: %w", desc.Digest, err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parsing index: %w", err)
	}
	for _, m := range index.Manifests {
		if m.Platform == nil {
			continue
		}
		if m.Platform.OS+"/"+m.Platform.Architecture == platform {
			return m, nil
		}
	}
	return ocispec.Descriptor{}, fmt.Errorf("%w: %s (index %s)", ErrPlatformNotFound, platform, desc.Digest)
}

func fetchManifest(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor) (*ocispec.Manifest, error) {
	raw, err := fetchAll(ctx, repo, desc)
	if err != nil {
		return nil, fmt.Errorf("fetching manifest %s: %w", desc.Digest, err)
	}
	var m ocispec.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	return &m, nil
}

func fetchLayerBytes(ctx context.Context, repo *remote.Repository, layer ocispec.Descriptor) ([]byte, error) {
	raw, err := fetchAll(ctx, repo, layer)
	if err != nil {
		return nil, fmt.Errorf("fetching layer %s: %w", layer.Digest, err)
	}
	return raw, nil
}

func fetchAll(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor) ([]byte, error) {
	rc, err := repo.Fetch(ctx, desc)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func isImageIndex(mediaType string) bool {
	return mediaType == ocispec.MediaTypeImageIndex || mediaType == "application/vnd.docker.distribution.manifest.list.v2+json"
}

// Annotation returns m[key] with a nil-map guard.
func Annotation(m map[string]string, key string) string {
	if m == nil {
		return ""
	}
	return m[key]
}

// DefaultGitHubRepoFromArtifact extracts the owner/repo path from a ghcr.io artifact.
func DefaultGitHubRepoFromArtifact(artifact string) string {
	const prefix = "ghcr.io/"
	if !strings.HasPrefix(artifact, prefix) {
		return ""
	}
	return strings.TrimPrefix(artifact, prefix)
}
