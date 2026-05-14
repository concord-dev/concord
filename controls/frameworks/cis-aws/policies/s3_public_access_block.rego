package concord.cis_aws.s3_public_access_block

import rego.v1

# CIS AWS 2.1.5 — every S3 bucket has Public Access Block fully on.
# Input: input.s3_pab is the normalized collector output:
#   { fetched_at, buckets: [ { name, public_access_block: { configured, block_public_acls, ... } } ] }

required_flags := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]

deny contains msg if {
    not input.s3_pab
    msg := "no S3 public-access-block evidence collected"
}

deny contains msg if {
    some bucket in input.s3_pab.buckets
    not bucket.public_access_block.configured
    msg := sprintf("bucket %q has no Public Access Block configuration at all", [bucket.name])
}

deny contains msg if {
    some bucket in input.s3_pab.buckets
    bucket.public_access_block.configured
    some flag in required_flags
    bucket.public_access_block[flag] == false
    msg := sprintf("bucket %q has Public Access Block flag %q disabled", [bucket.name, flag])
}
