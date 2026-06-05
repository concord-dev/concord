package concord.gdpr.prowler

import rego.v1

# Generic reducer for Prowler-backed controls.
#
# Expects evidence.prowler with the shape produced by
# internal/evidence/prowler — a summary object with .findings, where
# each finding has .check_id, .status, .severity, .compliance.
#
# A control passes when every relevant finding has status == "PASS".
# "Relevant" here is "any finding the upstream Prowler scan returned"
# — the YAML's params.compliance / params.services / params.checks
# narrow the scan; this policy then trusts the resulting set.

deny contains msg if {
    not input.prowler
    msg := "no Prowler evidence collected (is the binary installed and credentials configured?)"
}

deny contains msg if {
    input.prowler.finding_count == 0
    msg := "Prowler returned zero findings — controls cannot be evaluated"
}

deny contains msg if {
    some f in input.prowler.findings
    f.status == "FAIL"
    msg := sprintf(
        "%s: %s (resource=%s, severity=%s, remediation=%s)",
        [f.check_id, f.title, f.resource_arn, f.severity, f.remediation],
    )
}

warn contains msg if {
    some f in input.prowler.findings
    f.status == "MANUAL"
    msg := sprintf("manual review required: %s on %s", [f.check_id, f.resource_arn])
}
