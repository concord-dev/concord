package concord.cis_aws.unused_credentials

import rego.v1

# CIS AWS 4.1 — IAM credentials unused for max_unused_days are deactivated.
# Input: input.credentials.users is the parsed credential report.

default max_unused_days := 90

max_unused_days := x if {
    x := input._concord.params.max_unused_days
}

deny contains msg if {
    not input.credentials
    msg := "no IAM credential report collected"
}

deny contains msg if {
    some u in input.credentials.users
    u.password_enabled == true
    u.password_last_used_days_ago > max_unused_days
    msg := sprintf("user %q password active but unused for %d days (limit %d) — disable console login", [u.user, u.password_last_used_days_ago, max_unused_days])
}

deny contains msg if {
    some u in input.credentials.users
    some key in u.access_keys
    key.active == true
    key.last_used_days_ago > max_unused_days
    msg := sprintf("user %q access key #%s active but unused for %d days (limit %d) — deactivate the key", [u.user, key.key_num, key.last_used_days_ago, max_unused_days])
}

# Active keys that have never been used are equally suspect (likely
# created-and-forgotten). last_used_days_ago == -1 marks "never used".
deny contains msg if {
    some u in input.credentials.users
    some key in u.access_keys
    key.active == true
    key.last_used_days_ago == -1
    key.last_used_date == ""
    msg := sprintf("user %q access key #%s is active but has never been used — delete it", [u.user, key.key_num])
}

warn contains msg if {
    some u in input.credentials.users
    u.password_enabled == true
    u.mfa_active == false
    u.user != "<root_account>"
    msg := sprintf("user %q has console login enabled without MFA — covered by CIS-AWS-1.10 if implemented", [u.user])
}
