package concord.lib.evidence

import rego.v1

present(payload, key) if payload[key]

is_stale(item, max_age_seconds) if {
	now_ns := time.now_ns()
	fetched_ns := time.parse_rfc3339_ns(item.fetched_at)
	(now_ns - fetched_ns) > (max_age_seconds * 1000000000)
}

freshness_message(key, max_age_seconds) := msg if {
	msg := sprintf("%s evidence is stale (older than %d seconds)", [key, max_age_seconds])
}
