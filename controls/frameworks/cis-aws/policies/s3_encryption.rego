package concord.cis_aws.s3_encryption

import rego.v1

# CIS AWS Foundations 2.1.1 — S3 default encryption.
# Input: input.s3_buckets is the normalized response from the AWS collector:
#   { fetched_at, buckets: [ { name, creation_date, encryption: { configured, rules: [...] } } ] }

deny contains msg if {
    not input.s3_buckets
    msg := "no S3 evidence collected (AWS collector misconfigured or no credentials)"
}

deny contains msg if {
    some bucket in input.s3_buckets.buckets
    not is_encrypted(bucket)
    msg := sprintf("bucket %q has no server-side encryption configured", [bucket.name])
}

warn contains msg if {
    some bucket in input.s3_buckets.buckets
    is_encrypted(bucket)
    some rule in bucket.encryption.rules
    rule.sse_algorithm == "AES256"
    msg := sprintf("bucket %q uses AES256 (consider aws:kms for stronger key management)", [bucket.name])
}

warn contains msg if {
    some bucket in input.s3_buckets.buckets
    is_encrypted(bucket)
    some rule in bucket.encryption.rules
    rule.sse_algorithm == "aws:kms"
    not rule.bucket_key_enabled
    msg := sprintf("bucket %q uses KMS without bucket-key enabled (consider enabling to lower KMS costs)", [bucket.name])
}

is_encrypted(bucket) if {
    bucket.encryption.configured == true
}
