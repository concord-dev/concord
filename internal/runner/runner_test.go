package runner

import (
	"context"
	"path/filepath"
	"strings"
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

// --- SOC2-CC1.4 — GitHub org security baseline ---

const cc14Path = "controls/frameworks/soc2/cc1.4-github-org-security-baseline.yaml"

func TestRunCC1_4_Pass(t *testing.T) {
	f := runSingleEv(t, cc14Path, "cc1.4-org-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
	assert.Empty(t, f.Warnings, "all hardened settings → no warnings")
}

func TestRunCC1_4_No2FAFails(t *testing.T) {
	f := runSingleEv(t, cc14Path, "cc1.4-org-no-2fa.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "GitHub org does not require two-factor authentication for members")
	assert.Contains(t, f.Messages, "GitHub org default repository permission is 'write' (members can push to every repo by default — consider 'read' with explicit grants)")
	assert.Contains(t, f.Warnings, "secret scanning is NOT enabled by default on new repositories")
}

// --- SOC2-CC6.2 — Periodic access reviews ---

const cc62Path = "controls/frameworks/soc2/cc6.2-access-reviews.yaml"

func TestRunCC6_2_Pass(t *testing.T) {
	f := runSingleEv(t, cc62Path, "cc6.2-reviews-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCC6_2_StaleFails(t *testing.T) {
	f := runSingleEv(t, cc62Path, "cc6.2-reviews-stale.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	// Exact day count depends on test date — match on substring.
	found := false
	for _, m := range f.Messages {
		if strings.Contains(m, "most recent access-review") && strings.Contains(m, "schedule the next review cycle") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected freshness deny; got %v", f.Messages)
}

// --- SOC2-CC7.2 — Incident response runbook ---

const cc72Path = "controls/frameworks/soc2/cc7.2-incident-response.yaml"

func TestRunCC7_2_Pass(t *testing.T) {
	f := runSingleEv(t, cc72Path, "cc7.2-runbook-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCC7_2_StaleFails(t *testing.T) {
	f := runSingleEv(t, cc72Path, "cc7.2-runbook-stale.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `IR runbook "docs/incident-response/main.md" has not been reviewed in over 365 days`)
}

func TestRunCC7_2_MissingOwnerFails(t *testing.T) {
	f := runSingleEv(t, cc72Path, "cc7.2-runbook-missing-owner.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `IR runbook "docs/incident-response/main.md" is missing required field "on_call_owner"`)
}

// --- SOC2-CC2.1 — Required policies published ---

const cc21Path = "controls/frameworks/soc2/cc2.1-policy-communication.yaml"

func TestRunCC2_1_Pass(t *testing.T) {
	f := runSingleEv(t, cc21Path, "cc2.1-policies-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCC2_1_MissingPoliciesFails(t *testing.T) {
	f := runSingleEv(t, cc21Path, "cc2.1-policies-missing.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, `required policy "acceptable-use" is missing from docs/policies/`)
	assert.Contains(t, f.Messages, `required policy "access-control" is missing from docs/policies/`)
	assert.Contains(t, f.Messages, `policy "docs/policies/data-protection.md" is missing required field "approved_by"`)
}

// --- SOC2-CC3.1 — Risk assessment process ---

const cc31Path = "controls/frameworks/soc2/cc3.1-risk-assessment-process.yaml"

func TestRunCC3_1_Pass(t *testing.T) {
	f := runSingleEv(t, cc31Path, "cc3.1-process-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCC3_1_MissingProcessFails(t *testing.T) {
	f := runSingleEv(t, cc31Path, "cc3.1-process-empty.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "no risk-assessment process documented at docs/policies/risk-assessment-process.md")
}

// --- SOC2-CC4.1 — Monitoring strategy ---

const cc41Path = "controls/frameworks/soc2/cc4.1-monitoring-strategy.yaml"

func TestRunCC4_1_Pass(t *testing.T) {
	f := runSingleEv(t, cc41Path, "cc4.1-monitoring-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCC4_1_EmptyFails(t *testing.T) {
	f := runSingleEv(t, cc41Path, "cc4.1-monitoring-empty.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "no monitoring strategy doc found under docs/monitoring/")
}

// --- SOC2-CC5.1 — Control activities register ---

const cc51Path = "controls/frameworks/soc2/cc5.1-control-activities-register.yaml"

func TestRunCC5_1_Pass(t *testing.T) {
	f := runSingleEv(t, cc51Path, "cc5.1-register-pass.json")
	assert.Equal(t, apiv1.StatusPass, f.Status, "messages=%v warnings=%v", f.Messages, f.Warnings)
}

func TestRunCC5_1_TooFewEntriesFails(t *testing.T) {
	f := runSingleEv(t, cc51Path, "cc5.1-register-too-few.json")
	assert.Equal(t, apiv1.StatusFail, f.Status)
	assert.Contains(t, f.Messages, "control-activities register has 2 entries; minimum is 5")
	assert.Contains(t, f.Warnings, `control register entry "docs/control-activities/branch-protection.md" is ad_hoc — consider formalizing for audit`)
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
