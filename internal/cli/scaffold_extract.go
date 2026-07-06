package cli

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const scaffoldMaxSize = 50 * 1024 * 1024

// extractTemplateTarball unpacks a GitHub-style codeload tar.gz, stripping the
// top-level <repo>-<sha>/ wrapper so file paths are relative to dest.
func extractTemplateTarball(src io.Reader, dest string) error {
	gz, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("opening gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(&io.LimitedReader{R: gz, N: scaffoldMaxSize})
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}
		stripped := stripTopLevel(hdr.Name)
		if stripped == "" {
			continue
		}
		target, err := safeTemplateJoin(dest, stripped)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", target, err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", filepath.Dir(target), err)
			}
			mode := os.FileMode(hdr.Mode) & 0o777
			if mode == 0 {
				mode = 0o644
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
			if err != nil {
				return fmt.Errorf("creating %s: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("writing %s: %w", target, err)
			}
			if err := f.Close(); err != nil {
				return fmt.Errorf("closing %s: %w", target, err)
			}
		}
	}
}

func stripTopLevel(name string) string {
	slash := strings.Index(name, "/")
	if slash < 0 {
		return ""
	}
	return name[slash+1:]
}

func safeTemplateJoin(root, name string) (string, error) {
	if strings.Contains(name, "..") {
		return "", fmt.Errorf("refusing %s in template tarball: contains ..", name)
	}
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("refusing %s in template tarball: absolute path", name)
	}
	target := filepath.Join(root, name)
	rel, err := filepath.Rel(root, target)
	if err != nil || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("refusing %s in template tarball: escapes dest", name)
	}
	return target, nil
}
