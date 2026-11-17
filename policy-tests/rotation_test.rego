package securden.rules.pam_rotation_001_test

import data.securden.rules.pam_rotation_001.v1_0
import data.securden.rules.pam_rotation_001.v1_1

inp(version, records) := {
	"rule": {"rule_id": "PAM-ROTATION-001", "rule_version": version},
	"reporting_period": {"start": "2026-10-01T00:00:00Z", "end": "2026-10-31T00:00:00Z"},
	"params": {"max_rotation_age_days": 90, "scope_tags": []},
	"evidence": {
		"evidence_type": "credential_rotation",
		"records": records,
		"completeness": {"expected_record_count": count(records), "received_record_count": count(records), "source_complete": true, "collection_errors": 0},
	},
	"exceptions": [],
}

rec(id, rotated, status) := {"record_id": id, "scope_tags": [], "account_id": id, "privileged": true, "last_rotated_at": rotated, "last_rotation_status": status}

test_boundary_exactly_90_days_passes if {
	# 2026-08-02T00:00:00Z is exactly 90 days before 2026-10-31T00:00:00Z
	d := v1_1.decision with input as inp("1.1", [rec("a", "2026-08-02T00:00:00Z", "SUCCESS")])
	d.status == "PASS"
	d.metrics.password_age_days == 90
}

test_one_second_over_fails if {
	d := v1_1.decision with input as inp("1.1", [rec("a", "2026-08-01T23:59:59Z", "SUCCESS")])
	d.status == "FAIL"
}

test_failed_attempt_only_counts_in_v1_1 if {
	records := [rec("a", "2026-10-20T00:00:00Z", "FAILED")]
	d0 := v1_0.decision with input as inp("1.0", records)
	d1 := v1_1.decision with input as inp("1.1", records)
	d0.status == "PASS"
	d1.status == "FAIL"
}

test_version_routing_guard if {
	not v1_0.decision with input as inp("1.1", [])
}
