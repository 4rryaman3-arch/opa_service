# Generic interpreter for customer-defined rules (engine "securden.custom.v1").
#
# Customer rules are NEVER Rego. The API validates a strict JSON definition
# (allowlisted evidence fields and operators) and compiles it into the fixed
# structure consumed here:
#
#   input.rule = {
#     "rule_id", "rule_version", "subject_field", "tolerance",
#     "scope":     null | <group>,
#     "violation": <group>
#   }
#   <group>      = {"mode": "all"|"any", "conditions": [<cond>], "groups": [<leaf group>]}
#   <leaf group> = {"mode": "all"|"any", "conditions": [<cond>], "groups": []}
#   <cond>       = {"id", "field", "type", "op", "value"}
#
# Rego forbids recursion, so nesting is fixed at two levels (root group ->
# leaf groups), which the API schema enforces.
package securden.custom.v1

import data.securden.lib

value(rec, c) := lib.ts(rec[c.field]) if {
	c.type == "datetime"
	rec[c.field] != null
}

value(rec, c) := rec[c.field] if {
	c.type != "datetime"
	rec[c.field] != null
}

member(v, values) if v in values

holds(rec, c) if {
	c.op == "eq"
	value(rec, c) == c.value
}

holds(rec, c) if {
	c.op == "ne"
	value(rec, c) != c.value
}

holds(rec, c) if {
	c.op == "gt"
	value(rec, c) > c.value
}

holds(rec, c) if {
	c.op == "gte"
	value(rec, c) >= c.value
}

holds(rec, c) if {
	c.op == "lt"
	value(rec, c) < c.value
}

holds(rec, c) if {
	c.op == "lte"
	value(rec, c) <= c.value
}

holds(rec, c) if {
	c.op == "in"
	member(value(rec, c), c.value)
}

holds(rec, c) if {
	c.op == "not_in"
	v := value(rec, c)
	not member(v, c.value)
}

holds(rec, c) if {
	c.op == "is_null"
	rec[c.field] == null
}

holds(rec, c) if {
	c.op == "not_null"
	rec[c.field] != null
}

holds(rec, c) if {
	c.op == "older_than_days"
	lib.as_of_ns - value(rec, c) > c.value * lib.ns_per_day
}

holds(rec, c) if {
	c.op == "within_last_days"
	age := lib.as_of_ns - value(rec, c)
	age >= 0
	age <= c.value * lib.ns_per_day
}

holds(rec, c) if {
	c.op == "contains"
	member(c.value, value(rec, c))
}

leaf_group_holds(rec, g) if {
	g.mode == "all"
	every c in g.conditions {
		holds(rec, c)
	}
}

leaf_group_holds(rec, g) if {
	g.mode == "any"
	some c in g.conditions
	holds(rec, c)
}

group_holds(rec, g) if {
	g.mode == "all"
	every c in g.conditions {
		holds(rec, c)
	}
	every sg in g.groups {
		leaf_group_holds(rec, sg)
	}
}

group_holds(rec, g) if {
	g.mode == "any"
	some c in g.conditions
	holds(rec, c)
}

group_holds(rec, g) if {
	g.mode == "any"
	some sg in g.groups
	leaf_group_holds(rec, sg)
}

custom_in_scope(_) if input.rule.scope == null

custom_in_scope(rec) if {
	input.rule.scope != null
	group_holds(rec, input.rule.scope)
}

evaluated := [rec | some rec in lib.scoped_records; custom_in_scope(rec)]

# Explanation: ids of the conditions that made the violation true. Conditions
# inside a nested group are reported only when that whole group held.
matched_conditions(rec) := {c.id | some c in input.rule.violation.conditions; holds(rec, c)} | {c.id |
	some g in input.rule.violation.groups
	leaf_group_holds(rec, g)
	some c in g.conditions
	holds(rec, c)
}

subject(rec) := rec[input.rule.subject_field]

violations contains {"record_id": rec.record_id, "subject_id": subject(rec), "reasons": matched_conditions(rec)} if {
	some rec in evaluated
	group_holds(rec, input.rule.violation)
	count(lib.exception_ids_for(subject(rec))) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": subject(rec), "reasons": matched_conditions(rec), "exception_ids": ids} if {
	some rec in evaluated
	group_holds(rec, input.rule.violation)
	ids := lib.exception_ids_for(subject(rec))
	count(ids) > 0
}

metrics := {
	"records_in_scope": count(evaluated),
	"records_matching_violation": count([1 | some rec in evaluated; group_holds(rec, input.rule.violation)]),
	"tolerance": input.rule.tolerance,
}

decision := lib.decision(
	input.rule.rule_id, input.rule.rule_version,
	violations, excepted, set(), count(evaluated), input.rule.tolerance, metrics,
)
