package plugins

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

const (
	defaultOIDCIssuer = "https://token.actions.githubusercontent.com"
)

// ErrCosignMissing is returned when cosign is required but not on PATH.
var ErrCosignMissing = errors.New("cosign binary not found on PATH")

// VerifyOptions tune signature verification.
type VerifyOptions struct {
	Identity       string
	IdentityRegexp string
	OIDCIssuer     string
	CosignBin      string
}

// VerifyResult is what we learned from a successful verification.
type VerifyResult struct {
	Identity   string
	OIDCIssuer string
}

// VerifySignature runs `cosign verify` against ref with keyless verification.
func VerifySignature(ctx context.Context, ref string, opts VerifyOptions) (*VerifyResult, error) {
	bin := opts.CosignBin
	if bin == "" {
		bin = "cosign"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, ErrCosignMissing
	}

	issuer := opts.OIDCIssuer
	if issuer == "" {
		issuer = defaultOIDCIssuer
	}

	args := []string{"verify", "--output", "json", "--certificate-oidc-issuer", issuer}
	switch {
	case opts.Identity != "":
		args = append(args, "--certificate-identity", opts.Identity)
	case opts.IdentityRegexp != "":
		args = append(args, "--certificate-identity-regexp", opts.IdentityRegexp)
	default:
		return nil, errors.New("VerifyOptions requires Identity or IdentityRegexp")
	}
	args = append(args, ref)

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cosign verify failed: %w · %s", err, truncate(stderr.String(), 512))
	}

	identity := extractIdentity(stdout.String(), stderr.String())
	return &VerifyResult{Identity: identity, OIDCIssuer: issuer}, nil
}

// IdentityRegexpForGitHubRepo builds the keyless-identity regex Concord pins by default.
func IdentityRegexpForGitHubRepo(repo string) string {
	return fmt.Sprintf(`^https://github\.com/%s/\.github/workflows/.*@refs/tags/.*$`, regexpEscape(repo))
}

// AssertSignerContinuity refuses an upgrade when the new signer differs from the locked one.
func AssertSignerContinuity(prev, next string) error {
	if prev == "" || next == "" {
		return nil
	}
	if prev == next {
		return nil
	}
	return fmt.Errorf("signer identity changed: %q → %q (re-run with --allow-signer-change to accept)", prev, next)
}

func extractIdentity(stdout, stderr string) string {
	for _, hay := range []string{stdout, stderr} {
		if id := scanForKey(hay, "Subject:"); id != "" {
			return id
		}
		if id := scanForJSONField(hay, `"subject":`); id != "" {
			return id
		}
	}
	return ""
}

func scanForKey(s, key string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key) {
			return strings.TrimSpace(strings.TrimPrefix(line, key))
		}
	}
	return ""
}

func scanForJSONField(s, key string) string {
	idx := strings.Index(s, key)
	if idx < 0 {
		return ""
	}
	tail := s[idx+len(key):]
	tail = strings.TrimLeft(tail, " ")
	if !strings.HasPrefix(tail, `"`) {
		return ""
	}
	tail = tail[1:]
	end := strings.Index(tail, `"`)
	if end < 0 {
		return ""
	}
	return tail[:end]
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func regexpEscape(s string) string { return regexp.QuoteMeta(s) }

// VerifyRefForPlugin verifies a plugin OCI ref published under github.com/<repo>.
func VerifyRefForPlugin(ctx context.Context, ref, githubRepo string, expectedIdentity string) (*VerifyResult, error) {
	if expectedIdentity != "" {
		return VerifySignature(ctx, ref, VerifyOptions{Identity: expectedIdentity})
	}
	return VerifySignature(ctx, ref, VerifyOptions{IdentityRegexp: IdentityRegexpForGitHubRepo(githubRepo)})
}
