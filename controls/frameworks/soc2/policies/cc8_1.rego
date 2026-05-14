package concord.soc2.cc8_1

import rego.v1

# SOC 2 CC8.1 — change management on the default branch.
# Input shape: input.branch_protection is the normalized GitHub branch
# protection response: { repo, branch, protected, protection: {...} }.

# Configurable: minimum approving reviews required on the default branch.
# Override per-repo via concord.yaml: controls.params.SOC2-CC8.1.min_reviewers
min_reviewers := n if {
    n := input._concord.params.min_reviewers
} else := 1

deny contains msg if {
    not input.branch_protection
    msg := "no branch protection evidence collected"
}

deny contains msg if {
    input.branch_protection
    not input.branch_protection.protected
    msg := sprintf("default branch %q is not protected", [input.branch_protection.branch])
}

deny contains msg if {
    input.branch_protection.protected == true
    not input.branch_protection.protection.required_pull_request_reviews
    msg := sprintf("default branch %q does not require pull-request reviews", [input.branch_protection.branch])
}

deny contains msg if {
    input.branch_protection.protected == true
    reviews := input.branch_protection.protection.required_pull_request_reviews.required_approving_review_count
    reviews < min_reviewers
    msg := sprintf("default branch requires %d approving reviews; minimum is %d", [reviews, min_reviewers])
}

deny contains msg if {
    input.branch_protection.protected == true
    not input.branch_protection.protection.required_status_checks
    msg := "default branch does not require status checks"
}

deny contains msg if {
    input.branch_protection.protected == true
    input.branch_protection.protection.allow_force_pushes.enabled == true
    msg := "default branch allows force pushes"
}

deny contains msg if {
    input.branch_protection.protected == true
    input.branch_protection.protection.allow_deletions.enabled == true
    msg := "default branch allows deletions"
}

deny contains msg if {
    input.branch_protection.protected == true
    input.branch_protection.protection.enforce_admins.enabled == false
    msg := "branch protection does not apply to administrators (enforce_admins is off)"
}

warn contains msg if {
    input.branch_protection.protected == true
    not input.branch_protection.protection.required_pull_request_reviews.require_code_owner_reviews
    msg := "CODEOWNERS review is not required (recommended for high-stakes repos)"
}

warn contains msg if {
    input.branch_protection.protected == true
    not input.branch_protection.protection.required_linear_history.enabled
    msg := "linear history is not enforced (recommended)"
}
