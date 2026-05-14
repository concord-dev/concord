package runner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/concord-dev/concord/internal/controls"
	"github.com/concord-dev/concord/internal/evidence"
	"github.com/concord-dev/concord/internal/policy"
	apiv1 "github.com/concord-dev/concord/pkg/api/v1"
)

const cc81Path = "controls/frameworks/soc2/cc8.1-change-management.yaml"

func repoRoot(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs("../..")
	require.NoError(t, err)
	return abs
}

func TestRunCC8_1Pass(t *testing.T) {
	f := runFixture(t, "cc8.1-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
	assert.Empty(t, f.Messages)
}

func TestRunCC8_1NoProtection(t *testing.T) {
	f := runFixture(t, "cc8.1-no-protection.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `default branch "main" is not protected`)
	assert.Len(t, f.Messages, 1, "expected exactly one deny for unprotected branch; got %v", f.Messages)
}

func TestRunCC8_1NoReviews(t *testing.T) {
	f := runFixture(t, "cc8.1-no-reviews.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "default branch requires 0 approving reviews; minimum is 1")
}

func TestRunCC8_1ForcePushAndAdminBypass(t *testing.T) {
	f := runFixture(t, "cc8.1-force-push.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "default branch allows force pushes")
	assert.Contains(t, f.Messages, "default branch allows deletions")
	assert.Contains(t, f.Messages, "branch protection does not apply to administrators (enforce_admins is off)")
}

func TestRunCC8_1ParamOverride_StricterReviewerCount(t *testing.T) {
	controlPath := filepath.Join(repoRoot(t), cc81Path)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)
	c.Spec.Evidence[0].Fixture = "./tests/fixtures/cc8.1-pass.json"

	// The pass fixture has required_approving_review_count = 2.
	// With default min_reviewers = 1, this passes. With override min_reviewers = 3, it must fail.
	r := New(policy.New(), evidence.NewFileCollector()).SetParams(map[string]map[string]any{
		"SOC2-CC8.1": {"min_reviewers": 3},
	})
	f := r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})

	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "default branch requires 2 approving reviews; minimum is 3")
}

func TestRunCC8_1ParamOverride_DefaultStillWorks(t *testing.T) {
	controlPath := filepath.Join(repoRoot(t), cc81Path)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)
	c.Spec.Evidence[0].Fixture = "./tests/fixtures/cc8.1-pass.json"

	// No params installed → default of 1 applies → fixture (which has 2 reviewers) passes.
	r := New(policy.New(), evidence.NewFileCollector())
	f := r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v", f.Messages)
}

// --- SOC2-CC6.1 — MFA enforcement ---

const cc61Path = "controls/frameworks/soc2/cc6.1-mfa-enforcement.yaml"

func TestRunCC6_1_Pass(t *testing.T) {
	f := runCC61(t, "cc6.1-okta-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
	assert.Empty(t, f.Warnings)
}

func TestRunCC6_1_SMSOnlyFails(t *testing.T) {
	f := runCC61(t, "cc6.1-okta-sms-only.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `active user "bob@example.com" has no strong MFA factor enrolled (TOTP, push, WebAuthn, or hardware token required)`)
	// Alice has strong MFA — must NOT deny her.
	for _, m := range f.Messages {
		assert.NotContains(t, m, "alice@example.com")
	}
}

func TestRunCC6_1_SingleStrongWarns(t *testing.T) {
	f := runCC61(t, "cc6.1-okta-single-strong.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "single-strong is a warn, not a deny")
	assert.Contains(t, f.Warnings, `user "alice@example.com" has only one strong MFA factor (two recommended for device-loss redundancy)`)
	// Carol has 2 factors (push + sms): one strong, one weak. Should warn about weak alongside strong.
	assert.Contains(t, f.Warnings, `user "carol@example.com" still has weak factors (SMS/call/email) enrolled alongside strong MFA — remove to prevent phishing-fallback`)
}

func runCC61(t *testing.T, fixture string) apiv1.Finding {
	t.Helper()
	controlPath := filepath.Join(repoRoot(t), cc61Path)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)
	c.Spec.Evidence[0].Fixture = "./tests/fixtures/" + fixture
	r := New(policy.New(), evidence.NewFileCollector())
	return r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
}

// --- SOC2-CC7.1 — Vulnerability management via Trivy ---

const cc71Path = "controls/frameworks/soc2/cc7.1-vulnerability-management.yaml"

func TestRunCC7_1_Pass(t *testing.T) {
	f := runCC71(t, "cc7.1-trivy-pass.json", nil)
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCC7_1_CriticalFails(t *testing.T) {
	f := runCC71(t, "cc7.1-trivy-critical.json", nil)
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "2 CRITICAL vulnerabilities present (threshold: 0) — see warnings for fix paths")
	// Two warnings: one for the fixable, one for the un-fixable.
	assert.Contains(t, f.Warnings, "[CRITICAL] CVE-2024-99001 in github.com/example/auth-lib@1.2.3 — upgrade to 1.2.4")
	assert.Contains(t, f.Warnings, "[CRITICAL] CVE-2024-99002 in github.com/example/crypto-lib has no fix available yet — document exception or apply workaround")
}

func TestRunCC7_1_HighFixableFailsAtDefaultThreshold(t *testing.T) {
	f := runCC71(t, "cc7.1-trivy-high-fixable.json", nil)
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "2 HIGH vulnerabilities present (threshold: 0)")
}

func TestRunCC7_1_HighFixablePassesWithRelaxedThreshold(t *testing.T) {
	// Override max_high to 5 — the 2 highs in the fixture should now pass.
	params := map[string]map[string]any{
		"SOC2-CC7.1": {"max_high": 5},
	}
	f := runCC71(t, "cc7.1-trivy-high-fixable.json", params)
	assert.Equal(t, apiv1.StatusPass, f.Status, "with max_high=5, fixture's 2 highs should pass; messages=%v", f.Messages)
	// Warnings should still fire so engineers see what to fix.
	assert.Contains(t, f.Warnings, "[HIGH] CVE-2024-77001 in github.com/example/parser@0.4.0 — upgrade to 0.5.0")
}

func runCC71(t *testing.T, fixture string, params map[string]map[string]any) apiv1.Finding {
	t.Helper()
	controlPath := filepath.Join(repoRoot(t), cc71Path)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)
	c.Spec.Evidence[0].Fixture = "./tests/fixtures/" + fixture
	r := New(policy.New(), evidence.NewFileCollector()).SetParams(params)
	return r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
}

// --- SOC2-CC6.3 — Offboarding ---

const cc63Path = "controls/frameworks/soc2/cc6.3-offboarding.yaml"

func TestRunCC6_3_Pass(t *testing.T) {
	f := runSingleEv(t, cc63Path, "cc6.3-okta-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCC6_3_ResidualFactorFails(t *testing.T) {
	f := runSingleEv(t, cc63Path, "cc6.3-okta-residual-factor.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `DEPROVISIONED user "former-engineer@example.com" still has an ACTIVE token:software:totp factor — remove enrollment`)
	assert.Contains(t, f.Messages, `SUSPENDED user "on-leave@example.com" still has an ACTIVE push factor — remove enrollment`)
}

// --- SOC2-CC9.2 — Risk register ---

const cc92Path = "controls/frameworks/soc2/cc9.2-risk-register.yaml"

func TestRunCC9_2_Pass(t *testing.T) {
	f := runSingleEv(t, cc92Path, "cc9.2-register-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCC9_2_EmptyFails(t *testing.T) {
	f := runSingleEv(t, cc92Path, "cc9.2-register-empty.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "risk register is empty — at least one identified risk required for SOC 2 CC9.2 evidence")
}

func TestRunCC9_2_StaleAndMalformedFails(t *testing.T) {
	f := runSingleEv(t, cc92Path, "cc9.2-register-stale-open.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `risk register entry "docs/risk-register/old-risk.md" has not been reviewed in over 90 days`)
	assert.Contains(t, f.Messages, `risk register entry "docs/risk-register/recent-but-malformed.md" has invalid severity "moderate"`)
	assert.Contains(t, f.Messages, `risk register entry "docs/risk-register/recent-but-malformed.md" has invalid mitigation_status "in-progress" (must be open|mitigated|accepted|transferred)`)
	assert.Contains(t, f.Warnings, `risk register entry "docs/risk-register/old-risk.md" is high severity and still open — schedule treatment`)
}

// runSingleEv is the helper for single-evidence controls.
func runSingleEv(t *testing.T, controlRelPath, fixture string) apiv1.Finding {
	t.Helper()
	controlPath := filepath.Join(repoRoot(t), controlRelPath)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)
	c.Spec.Evidence[0].Fixture = "./tests/fixtures/" + fixture
	r := New(policy.New(), evidence.NewFileCollector())
	return r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
}

func runFixture(t *testing.T, fixture string) apiv1.Finding {
	t.Helper()
	controlPath := filepath.Join(repoRoot(t), cc81Path)
	c, err := controls.LoadFile(controlPath)
	require.NoError(t, err)

	c.Spec.Evidence[0].Fixture = "./tests/fixtures/" + fixture

	r := New(policy.New(), evidence.NewFileCollector())
	return r.Run(context.Background(), controls.Loaded{Control: c, Path: controlPath})
}
