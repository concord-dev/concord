package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// binaryDigestFile holds the hex sha256 of the installed plugin binary. It is
// written at install time (from the verified OCI layer bytes) and re-checked
// before the binary is executed, so a locally swapped/tampered binary is not
// run even though the OCI signature was verified only at download time.
const binaryDigestFile = ".binary.sha256"

// WriteBinaryDigest records the sha256 of content into the version dir sidecar.
func WriteBinaryDigest(versionDir string, content []byte) error {
	sum := sha256.Sum256(content)
	return os.WriteFile(filepath.Join(versionDir, binaryDigestFile),
		[]byte(hex.EncodeToString(sum[:])+"\n"), 0o644)
}

// verifyBinaryDigest re-hashes the on-disk binary and compares it to the
// recorded digest. Returns nil (accept) when no digest was recorded (legacy
// install) so upgrades don't strand existing plugins; returns an error only on
// a genuine mismatch.
func verifyBinaryDigest(versionDir, binPath string) error {
	want, err := os.ReadFile(filepath.Join(versionDir, binaryDigestFile))
	if err != nil {
		if os.IsNotExist(err) {
			return nil // legacy install: no recorded digest to check against
		}
		return err
	}
	f, err := os.Open(binPath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	got := hex.EncodeToString(h.Sum(nil))
	wantHex := strings.TrimSpace(string(want))
	if got != wantHex {
		return fmt.Errorf("plugin binary %s failed integrity check: on-disk sha256 %s != recorded %s",
			binPath, got, wantHex)
	}
	return nil
}
