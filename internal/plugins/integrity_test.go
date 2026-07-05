package plugins

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyBinaryDigest(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "concord-plugin-demo")
	if err := os.WriteFile(bin, []byte("original-binary"), 0o755); err != nil {
		t.Fatal(err)
	}

	// No recorded digest (legacy install) → accepted.
	if err := verifyBinaryDigest(dir, bin); err != nil {
		t.Fatalf("legacy (no sidecar) must be accepted, got %v", err)
	}

	// Record the digest, then an untouched binary verifies.
	if err := WriteBinaryDigest(dir, []byte("original-binary")); err != nil {
		t.Fatal(err)
	}
	if err := verifyBinaryDigest(dir, bin); err != nil {
		t.Fatalf("untouched binary must verify, got %v", err)
	}

	// Swap the binary on disk → integrity check fails.
	if err := os.WriteFile(bin, []byte("tampered-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyBinaryDigest(dir, bin); err == nil {
		t.Fatal("a swapped binary must fail the integrity check, got nil")
	}
}
