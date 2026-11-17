# PAM-DORMANT-001 v1.0 - dormant privileged accounts
package securden.rules.pam_dormant_001.v1_0

import data.securden.lib

rule_id := "PAM-DORMANT-001"

rule_version := "1.0"

threshold_ns := input.params.dormant_after_days * lib.ns_per_day

evaluated := [rec | some rec in lib.scoped_records; rec.privileged; rec.enabled]

last_activity_ns(rec) := lib.ts(rec.last_used_at) if {
	rec.last_used_at != null
} else := lib.ts(rec.created_at)

inactive_ns(rec) := lib.as_of_ns - last_activity_ns(rec)

failed("DORMANT_SINCE_LAST_USE", rec) if {
	rec.last_used_at != null
	inactive_ns(rec) > threshold_ns
}

failed("NEVER_USED_SINCE_CREATION", rec) if {
	rec.last_used_at == null
	inactive_ns(rec) > threshold_ns
}

reasons(rec) := {r |
	some r in ["DORMANT_SINCE_LAST_USE", "NEVER_USED_SINCE_CREATION"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.account_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.account_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.account_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.account_id)
	count(ids) > 0
}

metrics := {
	"max_inactive_days": lib.max_or_null([floor(inactive_ns(rec) / lib.ns_per_day) | some rec in evaluated]),
	"dormant_after_days": input.params.dormant_after_days,
	"enabled_privileged_accounts": count(evaluated),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, set(), count(evaluated), 0, metrics)
