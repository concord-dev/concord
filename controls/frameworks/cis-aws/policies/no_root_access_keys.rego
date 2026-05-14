package concord.cis_aws.no_root_access_keys

import rego.v1

# CIS AWS 1.4 — root account holds no active access keys.
# Input: input.iam_summary.summary is the IAM account summary map.

deny contains msg if {
    not input.iam_summary
    msg := "no IAM account summary collected"
}

deny contains msg if {
    count := input.iam_summary.summary.AccountAccessKeysPresent
    count > 0
    msg := sprintf("root account has %d active access key(s); rotate to IAM user keys and delete the root keys immediately", [count])
}

warn contains msg if {
    input.iam_summary.summary.AccountMFAEnabled == 0
    msg := "root account MFA is not enabled (covered separately by CIS-AWS-1.5 once implemented)"
}

warn contains msg if {
    devices := input.iam_summary.summary.MFADevicesInUse
    users := input.iam_summary.summary.Users
    devices < users
    msg := sprintf("only %d of %d IAM users have MFA devices configured", [devices, users])
}
