package plugins

import (
	"context"
	"io"
	"testing"

	"github.com/concord-dev/concord/internal/ociart"
)

// verifyArtifact must fail closed by default: when signature verification is
// required (the CLI default post-P0-C-#11) and no signer identity can be
// derived, install must error rather than silently proceed. --no-verify
// (SkipSignature) is the only way to bypass.
func TestVerifyArtifact_FailsClosedByDefault(t *testing.T) {
	// A non-ghcr ref yields no derivable GitHub identity.
	pulled := &ociart.PullResult{Artifact: "example.com/foo/bar", Digest: "sha256:abc", Tag: "v1"}

	if _, err := verifyArtifact(context.Background(), pulled,
		InstallOptions{RequireSignature: true}, io.Discard); err == nil {
		t.Fatal("expected an error when verification is required but no identity can be determined; got nil (fail-open)")
	}

	// Explicit opt-out skips cleanly.
	if _, err := verifyArtifact(context.Background(), pulled,
		InstallOptions{SkipSignature: true}, io.Discard); err != nil {
		t.Fatalf("--no-verify must skip without error, got %v", err)
	}
}
