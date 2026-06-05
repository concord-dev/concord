package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"
)

const (
	MediaTypePluginBinary = "application/vnd.concord.plugin.binary.v1"
	MediaTypePluginConfig = "application/vnd.concord.plugin.config.v1+json"

	AnnotationKind     = "org.concord.dev.artifact.kind"
	AnnotationSource   = "org.concord.dev.plugin.source"
	AnnotationProtocol = "org.concord.dev.plugin.protocol"
	AnnotationKindPlugin = "plugin"
)

// PullResult describes a successfully pulled plugin.
type PullResult struct {
	Source     string
	Version    string
	Artifact   string
	Digest     string
	Platform   string
	BinaryPath string
}

// PullOptions tune PullPlugin. Zero values are sensible defaults.
type PullOptions struct {
	InstallRoot string
	Platform    string
	PlainHTTP   bool
}

// PullPlugin fetches a plugin OCI artifact and writes the binary under InstallRoot.
func PullPlugin(ctx context.Context, ref string, opts PullOptions) (*PullResult, error) {
	parsed, err := parseRef(ref)
	if err != nil {
		return nil, err
	}
	root, err := resolveInstallRoot(opts.InstallRoot)
	if err != nil {
		return nil, err
	}
	platform := opts.Platform
	if platform == "" {
		platform = runtime.GOOS + "/" + runtime.GOARCH
	}

	repo, err := newRepository(parsed.host+"/"+parsed.repo, opts.PlainHTTP)
	if err != nil {
		return nil, fmt.Errorf("connecting to registry: %w", err)
	}

	desc, err := repo.Resolve(ctx, parsed.reference)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", ref, err)
	}

	manifestDesc, err := selectPlatformManifest(ctx, repo, desc, platform)
	if err != nil {
		return nil, err
	}

	manifest, err := fetchManifest(ctx, repo, manifestDesc)
	if err != nil {
		return nil, err
	}

	source := annotation(manifest.Annotations, AnnotationSource)
	if source == "" {
		source = parsed.defaultSource()
	}
	if source == "" {
		return nil, fmt.Errorf("artifact missing %s annotation; cannot determine plugin source", AnnotationSource)
	}

	layer, err := findBinaryLayer(manifest)
	if err != nil {
		return nil, err
	}

	version := parsed.tagOrDigest()
	binaryPath := installPath(root, source, version)
	if err := pullLayerToFile(ctx, repo, layer, binaryPath); err != nil {
		return nil, err
	}

	return &PullResult{
		Source:     source,
		Version:    version,
		Artifact:   parsed.host + "/" + parsed.repo,
		Digest:     manifestDesc.Digest.String(),
		Platform:   platform,
		BinaryPath: binaryPath,
	}, nil
}

type parsedRef struct {
	host      string
	repo      string
	reference string
	isDigest  bool
}

func parseRef(ref string) (parsedRef, error) {
	if ref == "" {
		return parsedRef{}, errors.New("empty OCI ref")
	}
	hostRepo, refPart, ok := splitRef(ref)
	if !ok {
		return parsedRef{}, fmt.Errorf("missing tag or digest in %q (use repo:tag or repo@sha256:...)", ref)
	}
	slash := strings.Index(hostRepo, "/")
	if slash < 0 {
		return parsedRef{}, fmt.Errorf("missing registry host in %q", ref)
	}
	return parsedRef{
		host:      hostRepo[:slash],
		repo:      hostRepo[slash+1:],
		reference: refPart,
		isDigest:  strings.HasPrefix(refPart, "sha256:"),
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

func (p parsedRef) defaultSource() string {
	base := p.repo
	if slash := strings.LastIndex(base, "/"); slash >= 0 {
		base = base[slash+1:]
	}
	return strings.TrimPrefix(base, "concord-plugin-")
}

func (p parsedRef) tagOrDigest() string { return p.reference }

func newRepository(name string, plainHTTP bool) (*remote.Repository, error) {
	repo, err := remote.NewRepository(name)
	if err != nil {
		return nil, err
	}
	repo.PlainHTTP = plainHTTP

	store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
	if err == nil {
		repo.Client = &auth.Client{
			Client:     retry.DefaultClient,
			Cache:      auth.NewCache(),
			Credential: credentials.Credential(store),
		}
	} else {
		repo.Client = &auth.Client{Client: retry.DefaultClient, Cache: auth.NewCache()}
	}
	return repo, nil
}

func selectPlatformManifest(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor, platform string) (ocispec.Descriptor, error) {
	if !isImageIndex(desc.MediaType) {
		return desc, nil
	}
	rc, err := repo.Fetch(ctx, desc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("fetching index %s: %w", desc.Digest, err)
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("reading index: %w", err)
	}
	var index ocispec.Index
	if err := json.Unmarshal(raw, &index); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("parsing index: %w", err)
	}
	want := platform
	for _, m := range index.Manifests {
		if m.Platform == nil {
			continue
		}
		got := m.Platform.OS + "/" + m.Platform.Architecture
		if got == want {
			return m, nil
		}
	}
	return ocispec.Descriptor{}, fmt.Errorf("no manifest for platform %s in index %s", want, desc.Digest)
}

func fetchManifest(ctx context.Context, repo *remote.Repository, desc ocispec.Descriptor) (*ocispec.Manifest, error) {
	rc, err := repo.Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("fetching manifest %s: %w", desc.Digest, err)
	}
	defer rc.Close()
	raw, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("reading manifest: %w", err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	return &manifest, nil
}

func findBinaryLayer(manifest *ocispec.Manifest) (ocispec.Descriptor, error) {
	for _, l := range manifest.Layers {
		if l.MediaType == MediaTypePluginBinary {
			return l, nil
		}
	}
	if len(manifest.Layers) == 1 {
		return manifest.Layers[0], nil
	}
	return ocispec.Descriptor{}, fmt.Errorf("manifest has no %s layer (got %d layers)", MediaTypePluginBinary, len(manifest.Layers))
}

func pullLayerToFile(ctx context.Context, repo *remote.Repository, layer ocispec.Descriptor, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("creating install dir: %w", err)
	}
	rc, err := repo.Fetch(ctx, layer)
	if err != nil {
		return fmt.Errorf("fetching layer %s: %w", layer.Digest, err)
	}
	defer rc.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), ".concord-plugin.*")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := io.Copy(tmp, rc); err != nil {
		tmp.Close()
		return fmt.Errorf("downloading layer: %w", err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod binary: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return fmt.Errorf("renaming binary into place: %w", err)
	}
	return nil
}

func resolveInstallRoot(root string) (string, error) {
	if root != "" {
		return root, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolving home dir: %w", err)
	}
	return filepath.Join(home, ".concord", "plugins"), nil
}

func installPath(root, source, version string) string {
	return filepath.Join(root, source, version, "concord-plugin-"+source)
}

func isImageIndex(mediaType string) bool {
	return mediaType == ocispec.MediaTypeImageIndex || mediaType == "application/vnd.docker.distribution.manifest.list.v2+json"
}

func annotation(m map[string]string, key string) string {
	if m == nil {
		return ""
	}
	return m[key]
}
