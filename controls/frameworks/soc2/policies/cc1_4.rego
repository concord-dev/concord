package concord.soc2.cc1_4

import rego.v1

# SOC 2 CC1.4 — GitHub org security baseline.

deny contains msg if {
    not input.org_security
    msg := "no GitHub organization policy evidence collected"
}

deny contains msg if {
    input.org_security.policy.two_factor_requirement_enabled == false
    msg := "GitHub org does not require two-factor authentication for members"
}

deny contains msg if {
    input.org_security.policy.default_repository_permission == "admin"
    msg := "GitHub org default repository permission is 'admin' (members get admin rights on every repo by default)"
}

deny contains msg if {
    input.org_security.policy.default_repository_permission == "write"
    msg := "GitHub org default repository permission is 'write' (members can push to every repo by default — consider 'read' with explicit grants)"
}

warn contains msg if {
    input.org_security.policy.secret_scanning_enabled_for_new_repositories == false
    msg := "secret scanning is NOT enabled by default on new repositories"
}

warn contains msg if {
    input.org_security.policy.secret_scanning_push_protection_enabled_for_new_repositories == false
    msg := "secret-scanning push protection is NOT enabled by default on new repositories"
}

warn contains msg if {
    input.org_security.policy.dependabot_alerts_enabled_for_new_repositories == false
    msg := "Dependabot alerts are NOT enabled by default on new repositories"
}

warn contains msg if {
    input.org_security.policy.web_commit_signoff_required == false
    msg := "DCO sign-off is not required for web commits (recommended for OSS / contributor identity)"
}
