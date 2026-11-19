package securden.custom.v1_period_test

# Optional period_field / required_fields of the fixed custom-rule interpreter (generated rules).
# Synthetic records only.
import data.securden.custom.v1

rule := {
	"rule_id": "PAM-GEN-000000000000", "rule_version": "1.0", "subject_field": "event_id", "tolerance": 0,
	"scope": {"mode": "all", "conditions": [], "groups": []},
	"violation": {"mode": "all", "conditions": [
		{"id": "c1", "field": "ticket_reference", "type": "string", "op": "is_null"},
	], "groups": []},
	"period_field": "activated_at",
}

rec(id, at, ticket) := {"record_id": id, "event_id": id, "activated_at": at, "ticket_reference": ticket,
	"scope_tags": []}

inp(records, r) := {
	"rule": r,
	"reporting_period": {"start": "2026-06-01T00:00:00.000000Z", "end": "2026-06-30T00:00:00.000000Z"},
	"params": {"scope_tags": []},
	"evidence": {"evidence_type": "break_glass_event", "records": records, "completeness": {
		"expected_record_count": count(records), "received_record_count": count(records),
		"source_complete": true, "collection_errors": 0}},
	"exceptions": [],
}

test_records_outside_the_period_are_not_in_scope if {
	d := v1.decision with input as inp([rec("a", "2026-05-01T00:00:00.000000Z", null)], rule)
	d.status == "NOT_APPLICABLE"
}

test_records_inside_the_period_are_judged if {
	d := v1.decision with input as inp([rec("a", "2026-06-10T00:00:00.000000Z", null)], rule)
	d.status == "FAIL"
}

test_missing_required_field_is_insufficient_evidence if {
	r := object.union(rule, {"required_fields": ["ticket_reference"], "violation": {"mode": "all", "conditions": [
		{"id": "c1", "field": "ticket_reference", "type": "string", "op": "eq", "value": "never"},
	], "groups": []}})
	d := v1.decision with input as inp([rec("a", "2026-06-10T00:00:00.000000Z", null)], r)
	d.status == "INSUFFICIENT_EVIDENCE"
}

test_without_period_field_every_record_counts if {
	r := object.remove(rule, ["period_field"])
	d := v1.decision with input as inp([rec("a", "2026-05-01T00:00:00.000000Z", null)], r)
	d.status == "FAIL"
}
