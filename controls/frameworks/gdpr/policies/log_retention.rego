package concord.gdpr.log_retention

import rego.v1

# Verifies CloudWatch / Cloud Logging / Azure Monitor log groups have
# a retention policy attached. GDPR Art. 5(1)(c) — data minimisation —
# requires keeping personal data for no longer than necessary.
#
# Evidence: steampipe rows from queries like
#   SELECT name, retention_in_days FROM aws_cloudwatch_log_group
# or its GCP / Azure equivalents.
#
# A row passes when retention_in_days is set AND <= max_days. The
# control YAML supplies max_days; default is 90.

default max_days := 90

deny contains msg if {
    not input.log_groups
    msg := "no log_groups evidence collected"
}

deny contains msg if {
    some g in input.log_groups.rows
    not g.retention_in_days
    msg := sprintf("log group %q has no retention policy (would retain forever)", [g.name])
}

deny contains msg if {
    some g in input.log_groups.rows
    g.retention_in_days > max_days
    msg := sprintf(
        "log group %q retains for %d days; GDPR data-minimisation budget is %d",
        [g.name, g.retention_in_days, max_days],
    )
}
