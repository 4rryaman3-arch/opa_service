# Shared, deterministic helpers for all Securden control tests.
#
# Determinism rules:
#   * The reference time for every age/threshold calculation is
#     input.reporting_period.end ("as_of"), never the wall clock.
#   * All timestamps arrive as UTC RFC 3339 strings (normalised by the API).
#   * Sets are used for violations so OPA serialises them in sorted order.
package securden.lib

ns_per_second := 1000000000

ns_per_minute := 60 * ns_per_second

ns_per_hour := 60 * ns_per_minute

ns_per_day := 24 * ns_per_hour

ts(s) := time.parse_rfc3339_ns(s)

as_of_ns := ts(input.reporting_period.end)

period_start_ns := ts(input.reporting_period.start)

in_period(s) if {
	s != null
	t := ts(s)
	t >= period_start_ns
	t <= as_of_ns
}

max_or_null(values) := max(values) if {
	count(values) > 0
} else := null

min_or_null(values) := min(values) if {
	count(values) > 0
} else := null

# ---------------------------------------------------------------- scope

in_scope(_) if count(input.params.scope_tags) == 0

in_scope(rec) if {
	some tag in rec.scope_tags
	tag in input.params.scope_tags
}

# Fast path: no scope tags configured -> every record is in scope.
scoped_records := input.evidence.records if {
	count(input.params.scope_tags) == 0
} else := [rec | some rec in input.evidence.records; in_scope(rec)]

# ---------------------------------------------------------------- approved exceptions
# An exception suppresses a violation only when it targets this rule and
# subject, and is valid at the as_of instant: approved_at <= as_of < expires_at.

exception_ids_for(subject) := {e.exception_id |
	some e in input.exceptions
	e.rule_id == input.rule.rule_id
	subject in e.subject_ids
	ts(e.approved_at) <= as_of_ns
	as_of_ns < ts(e.expires_at)
}

# ---------------------------------------------------------------- completeness

completeness_gaps contains "SOURCE_REPORTED_INCOMPLETE" if {
	not input.evidence.completeness.source_complete
}

completeness_gaps contains "COLLECTION_ERRORS_REPORTED" if {
	input.evidence.completeness.collection_errors > 0
}

completeness_gaps contains "RECORD_COUNT_BELOW_EXPECTED" if {
	expected := input.evidence.completeness.expected_record_count
	expected != null
	input.evidence.completeness.received_record_count < expected
}

completeness := {
	"complete": count(completeness_gaps) == 0,
	"gaps": completeness_gaps,
	"expected_record_count": input.evidence.completeness.expected_record_count,
	"received_record_count": input.evidence.completeness.received_record_count,
}

# ---------------------------------------------------------------- status
# Precedence (documented in README):
#   FAIL                  - more violations than the tolerance (a confirmed
#                           violation is a finding even if evidence is incomplete)
#   INSUFFICIENT_EVIDENCE - incomplete evidence, or undeterminable records
#   NOT_APPLICABLE        - complete evidence but nothing in scope
#   PASS                  - otherwise

status_of(violation_count, tolerance, undetermined_count, in_scope_count) := "FAIL" if {
	violation_count > tolerance
} else := "INSUFFICIENT_EVIDENCE" if {
	count(completeness_gaps) > 0
} else := "INSUFFICIENT_EVIDENCE" if {
	undetermined_count > 0
} else := "NOT_APPLICABLE" if {
	in_scope_count == 0
} else := "PASS"

summaries := {
	"FAIL": "One or more in-scope records violate the control test.",
	"INSUFFICIENT_EVIDENCE": "The supplied evidence is incomplete or contains records whose compliance cannot be determined.",
	"NOT_APPLICABLE": "Evidence is complete but no records fall within the control test's scope.",
	"PASS": "All in-scope records satisfy the control test for the reporting period.",
}

# Builds the decision document. Only defined when the request targets the
# exact rule/version implemented by the calling package, so a routing error
# yields an undefined decision (an explicit API error), never a PASS.
decision(rule_id, rule_version, violations, excepted, undetermined, in_scope_count, tolerance, metrics) := d if {
	input.rule.rule_id == rule_id
	input.rule.rule_version == rule_version
	s := status_of(count(violations), tolerance, count(undetermined), in_scope_count)
	d := {
		"rule_id": rule_id,
		"rule_version": rule_version,
		"bundle_version": data.securden.bundle.version,
		"status": s,
		"summary": summaries[s],
		"metrics": metrics,
		"violations": violations,
		"violation_count": count(violations),
		"tolerance": tolerance,
		"excepted": excepted,
		"undetermined": undetermined,
		"in_scope_record_count": in_scope_count,
		"evaluated_record_count": count(input.evidence.records),
		"completeness": completeness,
		"as_of": input.reporting_period.end,
	}
}
