package concord.test.perres

import rego.v1

# One verdict per resource in input.users, exercising the runner's fan-out.
resource_findings contains v if {
	some u in input.users
	not u.ok
	v := {"resource": u.id, "status": "fail", "messages": [sprintf("%s failed", [u.id])]}
}

resource_findings contains v if {
	some u in input.users
	u.ok
	v := {"resource": u.id, "status": "pass", "messages": []}
}
