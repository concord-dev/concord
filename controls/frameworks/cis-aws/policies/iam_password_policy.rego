package concord.cis_aws.iam_password_policy

import rego.v1

# CIS AWS 1.16 — IAM password policy enforces length, complexity,
# rotation, and reuse-prevention minimums.
# Input: input.password_policy is the iam_password_policy evidence.

# Defaults track the CIS v2 benchmark. They can be tightened via concord.yaml
# spec.controls.params (e.g. min_length: 16 for higher-trust environments).

default min_length := 14

min_length := x if {
    x := input._concord.params.min_length
}

default max_age_days := 90

max_age_days := x if {
    x := input._concord.params.max_age_days
}

default reuse_prevention := 24

reuse_prevention := x if {
    x := input._concord.params.reuse_prevention
}

deny contains msg if {
    not input.password_policy
    msg := "no IAM password policy evidence collected"
}

deny contains msg if {
    input.password_policy.configured == false
    msg := "no IAM account password policy is configured (CIS-AWS-1.16 requires one)"
}

deny contains msg if {
    p := input.password_policy.policy
    p.minimum_password_length < min_length
    msg := sprintf("minimum_password_length is %d, must be >= %d", [p.minimum_password_length, min_length])
}

deny contains msg if {
    p := input.password_policy.policy
    p.require_symbols == false
    msg := "require_symbols is false (CIS-AWS-1.16 requires symbols)"
}

deny contains msg if {
    p := input.password_policy.policy
    p.require_numbers == false
    msg := "require_numbers is false (CIS-AWS-1.16 requires digits)"
}

deny contains msg if {
    p := input.password_policy.policy
    p.require_uppercase_characters == false
    msg := "require_uppercase_characters is false (CIS-AWS-1.16 requires uppercase)"
}

deny contains msg if {
    p := input.password_policy.policy
    p.require_lowercase_characters == false
    msg := "require_lowercase_characters is false (CIS-AWS-1.16 requires lowercase)"
}

deny contains msg if {
    p := input.password_policy.policy
    p.expire_passwords == false
    msg := sprintf("expire_passwords is false; max_password_age must be set to <= %d days", [max_age_days])
}

deny contains msg if {
    p := input.password_policy.policy
    p.expire_passwords == true
    p.max_password_age > max_age_days
    msg := sprintf("max_password_age is %d, must be <= %d days", [p.max_password_age, max_age_days])
}

deny contains msg if {
    p := input.password_policy.policy
    p.password_reuse_prevention < reuse_prevention
    msg := sprintf("password_reuse_prevention is %d, must remember >= %d previous passwords", [p.password_reuse_prevention, reuse_prevention])
}

warn contains msg if {
    p := input.password_policy.policy
    p.allow_users_to_change_password == false
    msg := "users cannot change their own passwords — required for rotation hygiene"
}
