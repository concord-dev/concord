package concord.soc2.cc2_1

import rego.v1

# SOC 2 CC2.1 — required policies are published, approved, current.

max_age_days := n if {
    n := input._concord.params.max_age_days
} else := 365

nanos_per_day := 86400000000000

required_policies := {"information-security", "acceptable-use", "data-protection", "access-control"}

required_fields := ["policy_name", "approved_by", "approved_at", "last_reviewed_at"]

deny contains msg if {
    not input.policies
    msg := "no policy evidence collected"
}

deny contains msg if {
    some name in required_policies
    not has_policy(name)
    msg := sprintf("required policy %q is missing from docs/policies/", [name])
}

deny contains msg if {
    some doc in input.policies.docs
    some field in required_fields
    not has_value(doc, field)
    msg := sprintf("policy %q is missing required field %q", [doc.path, field])
}

deny contains msg if {
    some doc in input.policies.docs
    doc.last_reviewed_at
    reviewed_ns := time.parse_rfc3339_ns(doc.last_reviewed_at)
    cutoff_ns := time.now_ns() - (max_age_days * nanos_per_day)
    reviewed_ns < cutoff_ns
    msg := sprintf("policy %q has not been reviewed in over %d days", [doc.path, max_age_days])
}

# Recommend a version field for change-tracking discipline.
warn contains msg if {
    some doc in input.policies.docs
    not has_value(doc, "version")
    msg := sprintf("policy %q has no version field (recommended for change history)", [doc.path])
}

has_policy(name) if {
    some doc in input.policies.docs
    doc.policy_name == name
}

has_value(doc, key) if {
    v := doc[key]
    v != ""
}
