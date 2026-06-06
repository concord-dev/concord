package concord.lib.attestation

import rego.v1

fresh(att, max_days) if {
	now_ns := time.now_ns()
	reviewed_ns := time.parse_rfc3339_ns(att.last_review_at)
	max_ns := max_days * 24 * 3600 * 1000000000
	(now_ns - reviewed_ns) <= max_ns
}

signed_by(att, allowed_signers) if {
	some signer in att.signers
	some allowed in allowed_signers
	signer == allowed
}

not_expired(att) if {
	att.expires_at == ""
}

not_expired(att) if {
	att.expires_at != ""
	expires_ns := time.parse_rfc3339_ns(att.expires_at)
	expires_ns > time.now_ns()
}

attests(att, field) if {
	some f in att.attested_fields
	f == field
}
