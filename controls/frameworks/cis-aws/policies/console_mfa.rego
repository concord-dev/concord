package concord.cis_aws.console_mfa

import rego.v1

# CIS AWS 1.10 — every IAM user with a console password has MFA enabled.
# Input: input.credentials.users is the parsed credential report.
# Root MFA is handled separately by CIS-AWS-1.5.

deny contains msg if {
    not input.credentials
    msg := "no IAM credential report collected"
}

deny contains msg if {
    some u in input.credentials.users
    u.user != "<root_account>"
    u.password_enabled == true
    u.mfa_active == false
    msg := sprintf("user %q has a console password but no MFA device — enroll an MFA factor or disable console login", [u.user])
}
