# PAM-UNAUTH-001 v1.0 - unauthorized privileged access
package securden.rules.pam_unauth_001.v1_0

import data.securden.lib

rule_id := "PAM-UNAUTH-001"

rule_version := "1.0"

evaluated := [rec | some rec in lib.scoped_records; lib.in_period(rec.accessed_at)]

determinable := [rec | some rec in evaluated; rec.entitlement_status != "UNKNOWN"]

failed("NOT_AUTHORIZED", rec) if rec.entitlement_status == "NOT_AUTHORIZED"

failed("ENTITLEMENT_REVOKED", rec) if rec.entitlement_status == "REVOKED"

failed("OUTSIDE_ENTITLEMENT_WINDOW", rec) if {
	rec.entitlement_status == "AUTHORIZED"
	rec.entitlement_valid_from != null
	lib.ts(rec.accessed_at) < lib.ts(rec.entitlement_valid_from)
}

failed("OUTSIDE_ENTITLEMENT_WINDOW", rec) if {
	rec.entitlement_status == "AUTHORIZED"
	rec.entitlement_valid_to != null
	lib.ts(rec.accessed_at) > lib.ts(rec.entitlement_valid_to)
}

reasons(rec) := {r |
	some r in ["NOT_AUTHORIZED", "ENTITLEMENT_REVOKED", "OUTSIDE_ENTITLEMENT_WINDOW"]
	failed(r, rec)
}

# Each record's reasons are computed exactly once.
failing := [[rec, r] | some rec in determinable; r := reasons(rec); count(r) > 0]

violations contains {"record_id": rec.record_id, "subject_id": rec.access_id, "reasons": r} if {
	some [rec, r] in failing
	count(lib.exception_ids_for(rec.access_id)) == 0
}

excepted contains {"record_id": rec.record_id, "subject_id": rec.access_id, "reasons": r, "exception_ids": ids} if {
	some [rec, r] in failing
	ids := lib.exception_ids_for(rec.access_id)
	count(ids) > 0
}

undetermined contains {"record_id": rec.record_id, "subject_id": rec.access_id, "reasons": {"ENTITLEMENT_STATUS_UNKNOWN"}} if {
	some rec in evaluated
	rec.entitlement_status == "UNKNOWN"
}

metrics := {
	"access_events_evaluated": count(evaluated),
	"unauthorized_access_events": count(failing),
	"entitlement_unknown_events": count(evaluated) - count(determinable),
}

decision := lib.decision(rule_id, rule_version, violations, excepted, undetermined, count(evaluated), 0, metrics)
