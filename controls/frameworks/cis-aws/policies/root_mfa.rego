package concord.cis_aws.root_mfa

import rego.v1

# CIS AWS 1.5 — root account MFA enabled.

deny contains msg if {
    not input.iam_summary
    msg := "no IAM account summary collected"
}

deny contains msg if {
    input.iam_summary.summary.AccountMFAEnabled == 0
    msg := "root account MFA is not enabled — enable an MFA device on the root user immediately"
}

warn contains msg if {
    input.iam_summary.summary.AccountMFAEnabled == 1
    not input.iam_summary.summary.AccountSigningCertificatesPresent == 0
    msg := "root account still has signing certificates configured (remove unless required)"
}
