package concord.soc2.cc6_1

import rego.v1

# SOC 2 CC6.1 — strong MFA on every active identity-provider user.
# Input: input.okta_users.users[] each with .status, .factors[], .has_strong_mfa.

weak_factor_types := {"sms", "call", "email", "security_question"}

deny contains msg if {
    not input.okta_users
    msg := "no Okta evidence collected"
}

deny contains msg if {
    some user in input.okta_users.users
    user.status == "ACTIVE"
    not user.has_strong_mfa
    msg := sprintf("active user %q has no strong MFA factor enrolled (TOTP, push, WebAuthn, or hardware token required)", [user.email])
}

# Warn when an active user has ONE strong factor — two recommended for
# redundancy so users don't get locked out after device loss.
warn contains msg if {
    some user in input.okta_users.users
    user.status == "ACTIVE"
    user.has_strong_mfa
    count_strong_factors(user) == 1
    msg := sprintf("user %q has only one strong MFA factor (two recommended for device-loss redundancy)", [user.email])
}

# Warn when an active user has weak factors alongside strong ones — these
# should be removed to prevent phishing-fallback.
warn contains msg if {
    some user in input.okta_users.users
    user.status == "ACTIVE"
    user.has_strong_mfa
    has_weak_factor(user)
    msg := sprintf("user %q still has weak factors (SMS/call/email) enrolled alongside strong MFA — remove to prevent phishing-fallback", [user.email])
}

count_strong_factors(user) := n if {
    strong := [f |
        some f in user.factors
        f.status == "ACTIVE"
        not f.type in weak_factor_types
    ]
    n := count(strong)
}

has_weak_factor(user) if {
    some f in user.factors
    f.status == "ACTIVE"
    f.type in weak_factor_types
}
