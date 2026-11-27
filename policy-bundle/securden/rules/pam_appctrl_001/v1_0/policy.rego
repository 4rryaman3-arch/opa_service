# PAM-APPCTRL-001 v1.0 - application control policy enforcement
#
# Configuration snapshot: every policy must be enforced in ALLOWLIST or BLOCKLIST mode. MONITOR only observes.
package securden.rules.pam_appctrl_001.v1_0

import data.securden.lib

rule_id := "PAM-APPCTRL-001"

rule_version := "1.0"

evaluated := [rec | some rec in lib.scoped_records]

current(rec) if lib.in_period(rec.captured_at)

failed("POLICY_NOT_ENFORCED", rec) if not rec.enforced

failed("MONITOR_ONLY", rec) if rec.mode == "MONITOR"

# every field this rule uses is mandatory in the evidence schema
unknown(r, _) if r == "never"

reasons(rec) := {r |
	some r in ["POLICY_NOT_ENFORCED", "MONITOR_ONLY"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in evaluated; current(rec); r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.policy_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.policy_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.policy_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.policy_id)
	count(ids) > 0
}

unknown_reasons(rec) := {r |
	some r in ["NOTHING_UNKNOWN"]
	unknown(r, rec)
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.policy_id, "reasons": r} if {
	some rec in evaluated
	current(rec)
	count(reasons(rec)) == 0
	r := unknown_reasons(rec)
	count(r) > 0
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.policy_id, "reasons": {"SNAPSHOT_OUTSIDE_PERIOD"}} if {
	some rec in evaluated
	not current(rec)
}

# Nothing supplied is missing evidence, not "not applicable".
undetermined contains {"record_id": null, "subject_id": null, "reasons": {"NO_APPLICATION_CONTROL_POLICY_SUPPLIED"}} if {
	count(evaluated) == 0
}

metrics := {
	"assessment_basis": "CONFIGURATION_SNAPSHOT",
	"records_evaluated": count(evaluated),
	"enforced_allowlists": count([1 | some rec in evaluated; rec.enforced; rec.mode == "ALLOWLIST"]),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
