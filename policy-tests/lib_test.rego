package securden.lib_test

import data.securden.lib

base_input := {
	"rule": {"rule_id": "PAM-ROTATION-001", "rule_version": "1.1"},
	"reporting_period": {"start": "2026-10-01T00:00:00Z", "end": "2026-10-31T00:00:00Z"},
	"params": {"max_rotation_age_days": 90, "scope_tags": []},
	"evidence": {
		"evidence_type": "credential_rotation",
		"records": [],
		"completeness": {"expected_record_count": 0, "received_record_count": 0, "source_complete": true, "collection_errors": 0},
	},
	"exceptions": [],
}

test_status_precedence if {
	lib.status_of(1, 0, 5, 0) == "FAIL" with input as base_input
	lib.status_of(0, 0, 1, 3) == "INSUFFICIENT_EVIDENCE" with input as base_input
	lib.status_of(0, 0, 0, 0) == "NOT_APPLICABLE" with input as base_input
	lib.status_of(0, 0, 0, 3) == "PASS" with input as base_input
	lib.status_of(2, 2, 0, 3) == "PASS" with input as base_input # within tolerance
}

test_incomplete_evidence_is_insufficient if {
	inp := json.patch(base_input, [{"op": "replace", "path": "/evidence/completeness/source_complete", "value": false}])
	lib.status_of(0, 0, 0, 3) == "INSUFFICIENT_EVIDENCE" with input as inp
}

test_exception_validity_window if {
	inp := json.patch(base_input, [{"op": "replace", "path": "/exceptions", "value": [
		{"exception_id": "ok", "rule_id": "PAM-ROTATION-001", "subject_ids": ["a"], "approved_at": "2026-09-01T00:00:00Z", "expires_at": "2026-12-01T00:00:00Z"},
		{"exception_id": "expired", "rule_id": "PAM-ROTATION-001", "subject_ids": ["a"], "approved_at": "2026-09-01T00:00:00Z", "expires_at": "2026-10-31T00:00:00Z"},
		{"exception_id": "future", "rule_id": "PAM-ROTATION-001", "subject_ids": ["a"], "approved_at": "2026-11-01T00:00:00Z", "expires_at": "2026-12-01T00:00:00Z"},
		{"exception_id": "other-rule", "rule_id": "PAM-DORMANT-001", "subject_ids": ["a"], "approved_at": "2026-09-01T00:00:00Z", "expires_at": "2026-12-01T00:00:00Z"},
	]}])
	lib.exception_ids_for("a") == {"ok"} with input as inp
	lib.exception_ids_for("b") == set() with input as inp
}

test_decision_undefined_for_wrong_rule if {
	inp := json.patch(base_input, [{"op": "replace", "path": "/rule/rule_id", "value": "PAM-OTHER-001"}])
	not data.securden.rules.pam_rotation_001.v1_1.decision with input as inp
}
