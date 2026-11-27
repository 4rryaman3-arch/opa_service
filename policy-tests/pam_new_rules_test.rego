package securden.rules.pam_new_rules_test

import data.securden.rules.pam_appctrl_001.v1_0 as appctrl
import data.securden.rules.pam_audcfg_001.v1_0 as audcfg
import data.securden.rules.pam_audevent_001.v1_0 as audevent
import data.securden.rules.pam_bkpcfg_001.v1_0 as bkpcfg
import data.securden.rules.pam_endelev_001.v1_0 as endelev
import data.securden.rules.pam_locadm_001.v1_0 as locadm
import data.securden.rules.pam_pwdcfg_001.v1_0 as pwdcfg

period := {"start": "2026-10-01T00:00:00Z", "end": "2026-10-31T00:00:00Z"}

in_t := "2026-10-30T00:00:00Z"

out_t := "2026-09-01T00:00:00Z"

inp(rule, params, records) := {
	"rule": {"rule_id": rule, "rule_version": "1.0"},
	"reporting_period": period,
	"params": object.union(params, {"scope_tags": []}),
	"evidence": {"records": records, "completeness": {"expected_record_count": count(records), "received_record_count": count(records), "source_complete": true, "collection_errors": 0}},
	"exceptions": [],
}

base := {"record_id": "r1", "scope_tags": [], "captured_at": in_t}

why(d) := {r | some v in d.violations; some r in v.reasons}

unk(d) := {r | some v in d.undetermined; some r in v.reasons}

# ---- password policy
pw(o) := object.union(object.union(base, {"policy_id": "p", "applies_to_privileged": true, "min_length": 14, "complexity_required": true, "enforced_on_reset": true, "rotation_period_days": null, "history_count": null}), o)

pwd(recs, p) := d if d := pwdcfg.decision with input as inp("PAM-PWDCFG-001", object.union({"min_length": 14, "require_complexity": true}, p), recs)

test_pwd if {
	pwd([pw({})], {}).status == "PASS"
	why(pwd([pw({"min_length": 13})], {})) == {"MIN_LENGTH_BELOW_REQUIRED"}
	why(pwd([pw({"complexity_required": false})], {})) == {"COMPLEXITY_NOT_REQUIRED"}
	pwd([pw({"complexity_required": false})], {"require_complexity": false}).status == "PASS"
	unk(pwd([pw({"captured_at": out_t})], {})) == {"SNAPSHOT_OUTSIDE_PERIOD"}
	unk(pwd([pw({"applies_to_privileged": false, "min_length": 1})], {})) == {"NO_PRIVILEGED_PASSWORD_POLICY_SUPPLIED"}
}

# ---- audit forwarding
af(o) := object.union(object.union(base, {"destination_id": "d", "protocol": "SYSLOG", "enabled": true, "last_delivery_at": "2026-10-29T00:00:00Z"}), o)

afd(recs) := d if d := audcfg.decision with input as inp("PAM-AUDCFG-001", {}, recs)

test_audcfg if {
	afd([af({})]).status == "PASS"
	why(afd([af({"enabled": false})])) == {"FORWARDING_DISABLED"}
	afd([af({}), af({"record_id": "r2", "destination_id": "d2", "enabled": false})]).status == "PASS"
	unk(afd([af({"last_delivery_at": null})])) == {"DELIVERY_NOT_RECORDED"}
	unk(afd([af({"last_delivery_at": "2026-10-30T12:00:00Z"})])) == {"DELIVERY_AFTER_SNAPSHOT"}
	unk(afd([])) == {"NO_FORWARDING_DESTINATION_SUPPLIED"}
	unk(afd([af({"captured_at": out_t})])) == {"SNAPSHOT_OUTSIDE_PERIOD"}
}

# ---- backup
bk(o) := object.union(object.union(base, {"backup_id": "b", "scheduled": true, "encrypted": true, "last_backup_at": "2026-10-29T00:00:00Z", "last_backup_status": "SUCCESS"}), o)

bkd(recs) := d if d := bkpcfg.decision with input as inp("PAM-BKPCFG-001", {"max_backup_age_hours": 24}, recs)

test_backup if {
	bkd([bk({})]).status == "PASS"
	why(bkd([bk({"last_backup_at": "2026-10-28T23:59:59Z"})])) == {"LAST_BACKUP_TOO_OLD"}
	why(bkd([bk({"scheduled": false, "encrypted": false, "last_backup_status": "FAILED"})])) == {"BACKUP_NOT_SCHEDULED", "BACKUP_NOT_ENCRYPTED", "LAST_BACKUP_FAILED"}
	unk(bkd([bk({"last_backup_at": null})])) == {"LAST_BACKUP_UNKNOWN"}
	unk(bkd([bk({"last_backup_status": null})])) == {"LAST_BACKUP_UNKNOWN"}
	unk(bkd([bk({"last_backup_at": "2026-10-30T01:00:00Z"})])) == {"BACKUP_AFTER_SNAPSHOT"}
	bkd([bk({"encrypted": false, "last_backup_at": null})]).status == "FAIL"
	unk(bkd([])) == {"NO_BACKUP_CONFIGURATION_SUPPLIED"}
}

# ---- endpoint elevation
el(o) := object.union({"record_id": "r1", "scope_tags": [], "elevation_id": "e", "user_id": "u", "device_id": "d", "requested_at": in_t, "approval_status": "APPROVED", "application_id": "a", "approver_id": "m", "approved_at": in_t, "elevation_expires_at": null, "revoked_at": null}, o)

eld(recs) := d if d := endelev.decision with input as inp("PAM-ENDELEV-001", {}, recs)

test_elevation if {
	eld([el({})]).status == "PASS"
	why(eld([el({"approver_id": "u"})])) == {"SELF_APPROVED"}
	unk(eld([el({"approver_id": null})])) == {"APPROVER_UNKNOWN"}
	unk(eld([el({"approval_status": "AUTO_APPROVED", "approver_id": null, "application_id": null})])) == {"APPLICATION_UNKNOWN"}
	eld([el({"approval_status": "AUTO_APPROVED", "approver_id": null})]).status == "PASS"
	eld([el({"approval_status": "DENIED", "approver_id": "u"})]).status == "NOT_APPLICABLE"
	eld([el({"requested_at": out_t, "approver_id": "u"})]).status == "NOT_APPLICABLE"
}

# ---- local administrators
la(o) := object.union(object.union(base, {"device_id": "d", "account_id": "a", "approved_member": true}), o)

lad(recs) := d if d := locadm.decision with input as inp("PAM-LOCADM-001", {}, recs)

test_locadm if {
	lad([la({})]).status == "PASS"
	why(lad([la({"approved_member": false})])) == {"UNAPPROVED_LOCAL_ADMINISTRATOR"}
	unk(lad([la({"captured_at": out_t})])) == {"SNAPSHOT_OUTSIDE_PERIOD"}
	unk(lad([])) == {"NO_LOCAL_ADMIN_MEMBERSHIP_SUPPLIED"}
}

# ---- application control
ac(o) := object.union(object.union(base, {"policy_id": "p", "mode": "ALLOWLIST", "enforced": true}), o)

acd(recs) := d if d := appctrl.decision with input as inp("PAM-APPCTRL-001", {}, recs)

test_appctrl if {
	acd([ac({})]).status == "PASS"
	acd([ac({"mode": "BLOCKLIST"})]).status == "PASS"
	why(acd([ac({"mode": "MONITOR"})])) == {"MONITOR_ONLY"}
	why(acd([ac({"enforced": false})])) == {"POLICY_NOT_ENFORCED"}
	unk(acd([])) == {"NO_APPLICATION_CONTROL_POLICY_SUPPLIED"}
}

# ---- audit events
ev(o) := object.union({"record_id": "r1", "scope_tags": [], "event_id": "e", "occurred_at": in_t, "event_type": "LOGIN", "location_id": null, "source_id": null, "outcome": "SUCCESS", "actor_id": null, "target_id": null}, o)

evd(recs) := d if d := audevent.decision with input as inp("PAM-AUDEVENT-001", {}, recs)

test_audevent if {
	evd([ev({})]).status == "PASS"
	why(evd([ev({"event_type": null})])) == {"EVENT_TYPE_MISSING"}
	why(evd([ev({"outcome": null})])) == {"OUTCOME_MISSING"}
	unk(evd([ev({"occurred_at": out_t, "outcome": null})])) == {"NO_AUDIT_EVENTS_SUPPLIED"}
}

# ---- shared behaviour
test_exception_suppresses_violation if {
	i := object.union(inp("PAM-LOCADM-001", {}, [la({"approved_member": false})]), {"exceptions": [{"exception_id": "x", "rule_id": "PAM-LOCADM-001", "subject_ids": ["r1"], "approved_at": "2026-10-01T00:00:00Z", "expires_at": "2026-12-01T00:00:00Z"}]})
	d := locadm.decision with input as i
	d.status == "PASS"
	count(d.excepted) == 1
}

test_incomplete_evidence_never_passes if {
	i := json.patch(inp("PAM-APPCTRL-001", {}, [ac({})]), [{"op": "replace", "path": "/evidence/completeness/source_complete", "value": false}])
	d := appctrl.decision with input as i
	d.status == "INSUFFICIENT_EVIDENCE"
}

test_routing_guard if {
	not pwdcfg.decision with input as inp("PAM-LOCADM-001", {"min_length": 14, "require_complexity": true}, [])
}
