package concord.soc2.cc6_2

import rego.v1

# SOC 2 CC6.2 — periodic access reviews documented and current.

max_age_days := n if {
    n := input._concord.params.max_age_days
} else := 90

nanos_per_day := 86400000000000

required_fields := ["title", "reviewer", "scope", "reviewed_at"]

deny contains msg if {
    not input.access_reviews
    msg := "no access-review evidence collected"
}

deny contains msg if {
    count(input.access_reviews.docs) == 0
    msg := "no access-review documents found under docs/access-reviews/"
}

deny contains msg if {
    some doc in input.access_reviews.docs
    some field in required_fields
    not has_value(doc, field)
    msg := sprintf("access-review %q is missing required field %q", [doc.path, field])
}

# The MOST RECENT review must be within max_age_days. Older entries are fine as historical record.
deny contains msg if {
    count(input.access_reviews.docs) > 0
    most_recent_age_days > max_age_days
    msg := sprintf("most recent access-review is %d days old (max %d) — schedule the next review cycle", [most_recent_age_days, max_age_days])
}

# Compute the freshest review's age in days.
most_recent_age_days := days if {
    timestamps := [t |
        some doc in input.access_reviews.docs
        doc.reviewed_at
        t := time.parse_rfc3339_ns(doc.reviewed_at)
    ]
    count(timestamps) > 0
    latest := max(timestamps)
    days := (time.now_ns() - latest) / nanos_per_day
}

warn contains msg if {
    some doc in input.access_reviews.docs
    not has_value(doc, "summary")
    msg := sprintf("access-review %q has no summary section (recommended)", [doc.path])
}

has_value(doc, key) if {
    v := doc[key]
    v != ""
}
