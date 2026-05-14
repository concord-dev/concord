package concord.cis_aws.cloudtrail_multi_region

import rego.v1

# CIS AWS 3.1 — at least one multi-region CloudTrail trail is actively
# logging with log-file validation enabled.

deny contains msg if {
    not input.cloudtrail
    msg := "no CloudTrail evidence collected"
}

deny contains msg if {
    count(input.cloudtrail.trails) == 0
    msg := "no CloudTrail trails exist in this account"
}

deny contains msg if {
    count(qualifying_trails) == 0
    msg := "no CloudTrail trail satisfies multi-region + logging + file-validation simultaneously"
}

# A trail qualifies if it covers every region, is currently logging,
# and has log-file integrity validation on.
qualifying_trails contains trail if {
    some trail in input.cloudtrail.trails
    trail.is_multi_region == true
    trail.is_logging == true
    trail.log_file_validation_enabled == true
}

warn contains msg if {
    some trail in input.cloudtrail.trails
    trail.is_multi_region == true
    trail.is_logging == false
    msg := sprintf("trail %q is multi-region but logging is currently stopped", [trail.name])
}

warn contains msg if {
    some trail in input.cloudtrail.trails
    trail.is_multi_region == true
    trail.is_logging == true
    trail.log_file_validation_enabled == false
    msg := sprintf("trail %q logs every region but log-file validation is off", [trail.name])
}
