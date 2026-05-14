package concord.soc2.cc6_3

import rego.v1

# SOC 2 CC6.3 — offboarded users retain no active MFA factors.

deny contains msg if {
    not input.okta_users
    msg := "no Okta offboarding evidence collected"
}

# Any deactivated user with an ACTIVE factor is a residual-access leak.
deny contains msg if {
    some user in input.okta_users.users
    deactivated_status(user.status)
    some factor in user.factors
    factor.status == "ACTIVE"
    msg := sprintf("%s user %q still has an ACTIVE %s factor — remove enrollment", [user.status, user.email, factor.type])
}

# Warn when a DEPROVISIONED user has any inactive factor too — these
# should typically be purged after offboarding even when inert.
warn contains msg if {
    some user in input.okta_users.users
    user.status == "DEPROVISIONED"
    some factor in user.factors
    factor.status != "ACTIVE"
    msg := sprintf("deprovisioned user %q retains a non-active %s factor in record (recommend purge)", [user.email, factor.type])
}

deactivated_status(s) if s == "SUSPENDED"
deactivated_status(s) if s == "DEPROVISIONED"
