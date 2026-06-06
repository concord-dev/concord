package concord.lib.collection

import rego.v1

all_compliant(items) if {
	count(items) > 0
	count([x | some x in items; x.compliant]) == count(items)
}

none_compliant(items) if {
	count([x | some x in items; x.compliant]) == 0
}

any_compliant(items) if {
	count([x | some x in items; x.compliant]) > 0
}

count_compliant(items) := n if {
	n := count([x | some x in items; x.compliant])
}

count_non_compliant(items) := n if {
	n := count([x | some x in items; not x.compliant])
}

non_compliant_ids(items) := ids if {
	ids := [x.id | some x in items; not x.compliant]
}

items_where_field_equals(items, field, value) := matched if {
	matched := [x | some x in items; x[field] == value]
}
