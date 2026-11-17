"""Organization policy contexts (CUSTOMER_POLICY): control catalog, scoped versioned
policy, collector handshake, and deterministic binding into evaluation plans.
Synthetic fixtures only; no real regulation or organization."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.models.common import format_utc
from regintel import catalog, extraction, policy_controls as pc, registry
from regintel.admin_api import PREFIX as ADMIN, create_admin_app
from regintel.orgscope import HEADER
from ..conftest import BUNDLE, OPA_TOKEN
from . import support as s

CATALOG = "/api/v1/catalog"
SCOPE_A, SCOPE_B = "pa" * 16, "pb" * 16
FW = "SYN-EU-ACT"
Q_ROT90 = "Operators shall rotate the credentials of privileged accounts at least every 90 days."
Q_ROT = "Operators shall regularly change the passwords of privileged accounts."
Q_MFA = "Operators shall use multi-factor authentication for every privileged access."
Q_IDLE = "Operators shall lock idle privileged sessions."
Q_REVIEW = "Operators shall review privileged access rights periodically."
ACT = f"""<html><body>
<h1>SYNTHETIC TEST FIXTURE - Synthetic Access Security Act (not a real regulation)</h1>
<h2>Article 7 Privileged credentials</h2>
<p>{Q_ROT90}</p>
<p>{Q_ROT}</p>
<h2>Article 8 Authentication and sessions</h2>
<p>{Q_MFA}</p>
<p>{Q_IDLE}</p>
<h2>Article 9 Reviews</h2>
<p>{Q_REVIEW}</p>
{s.FILLER}
</body></html>"""

NOW = datetime.now(timezone.utc).replace(microsecond=0)
P_END = NOW - timedelta(hours=1)
P_START = P_END - timedelta(days=30)
PERIOD = {"start": format_utc(P_START), "end": format_utc(P_END)}
ROT90_MAPPING = {"assessment": "AUTOMATED", "rule_id": "PAM-ROTATION-001", "rule_version_min": "1.1",
                 "coverage": "PARTIAL", "parameters": {"max_rotation_age_days": 90},
                 "override_constraints": {"max_rotation_age_days": {"min": 1, "max": 90}},
                 "rationale": "Synthetic fixture: the passage states 90 days.",
                 "limitations": "Synthetic fixture: accounts managed in Securden only."}
ORG = [{"type": "ORGANIZATION"}]


def credentials(tmp_path: Path):
    entries, headers = [], {}
    for name, tenants, scopes in [
        ("deploy", ["acme"], ["catalog:read", "catalog:operate", "catalog:review", "catalog:publish", "evaluate",
                              "rules:read"]),
        ("reader", ["acme"], ["catalog:read"]),
        ("intruder", ["acme"], ["catalog:read", "catalog:operate"]),
        ("other", ["tenant-b"], ["catalog:read", "catalog:operate"]),
    ]:
        secret = "synthetic-test-secret-" + name
        headers[name] = {"Authorization": f"Bearer {name}.{secret}"}
        entries.append({"key_id": name, "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
                        "scopes": scopes, "tenants": tenants, "enabled": True})
    path = tmp_path / "clients.json"
    path.write_text(json.dumps({"clients": entries}))
    return path, headers


class Env:
    def __init__(self, admin, public, db, ids, headers):
        self.admin, self.public, self.db, self.ids, self.headers = admin, public, db, ids, headers

    def h(self, scope=SCOPE_A, who="deploy"):
        return {**self.headers[who], **({HEADER: scope} if scope else {})}

    def save(self, key, controls, *, scope=SCOPE_A, who="deploy", tenant="acme", start=P_START - timedelta(days=1),
             end=None, title="Synthetic privileged access policy", context_id=None, supersedes=None):
        body = {"tenant_id": tenant, "request_key": key, "title": title,
                "policy_reference": {"title": "Synthetic PAM standard (fixture)", "identifier": "SYN-PAM-STD-1",
                                     "section": "4.2"},
                "effective_from": format_utc(start), "controls": controls}
        if end is not None:
            body["effective_to"] = format_utc(end)
        if context_id is None:
            return self.admin.post(ADMIN + "/policy-contexts", json=body, headers=self.h(scope, who))
        return self.admin.post(ADMIN + f"/policy-contexts/{context_id}/versions",
                               json={**body, "supersedes_version": supersedes}, headers=self.h(scope, who))

    def saved(self, key, controls, **kw):
        r = self.save(key, controls, **kw)
        assert r.status_code == 201, r.text
        return r.json()["policy_version"]

    def handshake(self, evidence, *, scope=SCOPE_A):
        r = self.admin.put(ADMIN + "/collector-capabilities", headers=self.h(scope), json={
            "tenant_id": "acme", "collector": {"name": "synthetic-django-bridge", "version": "1.0.0"},
            "evidence": [{"evidence_type": t, "schema_version": v} for t, v in evidence.items()]})
        assert r.status_code == 200, r.text
        return r.json()

    def plan(self, version_ids=(), *, scope=SCOPE_A, who="deploy", resolutions=None, period=PERIOD, **extra):
        body = {"tenant_id": "acme", **extra}
        if version_ids:
            body.update(policy_version_ids=list(version_ids), reporting_period=period)
        if resolutions is not None:
            body["target_resolutions"] = resolutions
        return self.public.post(f"{CATALOG}/evaluation-templates/{FW}/plan", json=body, headers=self.h(scope, who))

    def ok_plan(self, *a, **kw):
        r = self.plan(*a, **kw)
        assert r.status_code == 200, r.text
        return r.json()

    def gaps(self, plan, key):
        req = next(r for r in plan["requirements"] if r["requirement_id"] == self.ids[key])
        return req["policy_resolution"]["gaps"]


def control(cid, params, targets=ORG, version="1.0"):
    return {"control_id": cid, "control_version": version, "parameters": params, "targets": targets}


def rotation(days, targets=ORG):
    return control("PC-CRED-ROTATION", {"max_rotation_age_days": days}, targets)


MFA_AT_ACCESS = control("PC-MFA-AT-ACCESS", {"accepted_methods": ["fido2", "totp"]})


def build(tmp_path, opa_url="http://127.0.0.1:9"):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db)
    s.sync(db, {f"https://{s.DOMAIN}/act/en": ACT}, tmp_path)
    vid = db.scalar("SELECT MAX(id) FROM regulatory_document_version")
    catalog.review_document_version(db, vid, reviewer="bob", decision="APPROVED", published_on="2024-01-15",
                                    effective_from="2025-01-01")
    registry.verify_framework(db, FW, reviewer="bob", evidence_version_id=vid, lifecycle="IN_FORCE",
                              published_on="2024-01-15", effective_from="2025-01-01")
    ids = {}
    for key, quote, thresholds in (("rot90", Q_ROT90, [{"value_text": "90 days", "meaning": "interval"}]),
                                   ("rot", Q_ROT, None), ("mfa", Q_MFA, None), ("idle", Q_IDLE, None),
                                   ("review", Q_REVIEW, None)):
        section = db.scalar("SELECT id FROM document_section WHERE version_id=? AND text LIKE ?", (vid, f"%{quote}%"))
        ids[key] = extraction.add_manual_requirement(db, section_id=section, quote=quote, thresholds=thresholds,
                                                     pam_domains=["access_control"], obligation_type="MANDATORY",
                                                     actor="alice")
        catalog.review(db, "requirement", ids[key], reviewer="bob", decision="APPROVED")
    catalog.publish_catalog(db, "bob")
    path, headers = credentials(tmp_path)
    common = dict(api_clients_file=path, catalog_db_path=Path(db.path), policy_bundle_dir=BUNDLE)
    admin = create_admin_app(Settings(**common, catalog_jobs_db_path=tmp_path / "jobs.db",
                                      catalog_upload_dir=tmp_path / "uploads"), start_worker=False)
    public = create_app(Settings(**common, opa_url=opa_url, opa_token=OPA_TOKEN, db_path=tmp_path / "opm.db",
                                 log_level="WARNING", trust_proxy_headers=False, opa_connect_timeout_seconds=0.5))
    return admin, public, db, ids, headers


def publish_regulatory_rotation(env):
    h = env.headers["deploy"]
    r = env.admin.post(ADMIN + "/mappings", json={"requirement_id": env.ids["rot90"], **ROT90_MAPPING}, headers=h)
    assert r.status_code == 201, r.text
    mid = r.json()["mapping"]["id"]
    assert env.admin.post(ADMIN + f"/reviews/mapping/{mid}", headers=h,
                          json={"decision": "APPROVED", "comment": "Synthetic fixture review."}).status_code == 200
    assert env.admin.post(ADMIN + "/publish", headers=h).status_code == 200


@pytest.fixture
def env(tmp_path):
    admin, public, db, ids, headers = build(tmp_path)
    with TestClient(admin) as a, TestClient(public) as p:
        yield Env(a, p, db, ids, headers)
    db.close()


# ---------------------------------------------------------------- A. control catalog


def test_control_catalog_is_versioned_schema_driven_and_honest_about_assessability(env):
    r = env.public.get(CATALOG + "/policy-controls", headers=env.h(None))
    assert r.status_code == 200, r.text
    body = r.json()
    items = {c["control_id"]: c for c in body["items"]}
    assert body["control_catalog_version"] == pc.CONTROL_CATALOG_VERSION
    assert body["schema_subset"]["dialect"] == pc.SCHEMA_DIALECT
    # every existing predefined rule category has a control, plus the new distinct ones
    bound = {b["rule_id"] for c in items.values() for b in c["bindings"]}
    assert {"PAM-ROTATION-001", "PAM-SESSREC-001", "PAM-APPROVAL-001", "PAM-DORMANT-001", "PAM-AUTHFAIL-001",
            "PAM-UNAUTH-001", "PAM-BREAKGLASS-001", "PAM-EXCEPTION-001", "PAM-REVIEW-001", "PAM-AUDITCOMP-001"} <= bound
    assert {"PC-MFA-CONFIGURATION", "PC-MFA-AT-ACCESS", "PC-SESSION-IDLE-LIMIT", "PC-SESSION-DURATION-LIMIT"} <= set(items)
    # configuration versus event history, and failed-logon monitoring is not MFA
    assert items["PC-MFA-CONFIGURATION"]["assessment_mode"] == "CONFIGURATION_SNAPSHOT"
    assert items["PC-MFA-AT-ACCESS"]["assessment_mode"] == "EVENT_HISTORY"
    assert items["PC-SESSION-IDLE-LIMIT"]["assessment_mode"] == "CONFIGURATION_SNAPSHOT"
    assert items["PC-SESSION-DURATION-LIMIT"]["assessment_mode"] == "EVENT_HISTORY"
    assert items["PC-MFA-CONFIGURATION"]["bindings"][0]["rule_id"] != items["PC-MFA-AT-ACCESS"]["bindings"][0]["rule_id"]
    assert "PAM-AUTHFAIL-001" not in {b["rule_id"] for c in ("PC-MFA-CONFIGURATION", "PC-MFA-AT-ACCESS")
                                      for b in items[c]["bindings"]}
    assert "not MFA" in " ".join(items["PC-AUTH-FAILURE-MONITORING"]["implementation"]["limitations"])
    for c in items.values():
        assert c["definition_digest"].startswith("sha256:") and c["ui"]["order"] == list(c["ui"]["parameters"])
        assert c["parameter_schema"]["additionalProperties"] is False
        for b in c["bindings"]:
            assert b["evidence_schema_version"] == "1.0" and b["evidence_schema"]["type"] == "object"
    assert items["PC-PASSWORD-POLICY"]["implementation"]["status"] == "NOT_IMPLEMENTED"
    assert items["PC-PASSWORD-POLICY"]["bindings"] == []
    assert items["PC-CRED-ROTATION"]["assessability"]["end_to_end_assessable"] is None  # no organization given
    # for an organization without a handshake only the legacy bridge evidence counts: new controls are not advertised
    scoped = {c["control_id"]: c["assessability"] for c in env.public.get(
        CATALOG + "/policy-controls", params={"tenant_id": "acme", "include_evidence_schema": False},
        headers=env.h()).json()["items"]}
    assert scoped["PC-CRED-ROTATION"]["end_to_end_assessable"] is True
    for cid in ("PC-MFA-AT-ACCESS", "PC-MFA-CONFIGURATION", "PC-SESSION-IDLE-LIMIT", "PC-SESSION-DURATION-LIMIT",
                "PC-ACCESS-REVIEW"):
        assert scoped[cid] == {**scoped[cid], "end_to_end_assessable": False, "reason": "COLLECTOR_MISSING"}
    assert scoped["PC-PASSWORD-POLICY"]["reason"] == "NO_EXECUTABLE_RULE"
    # the handshake confirms compatible evidence; an incompatible version is not accepted
    env.handshake({"privileged_access_authentication": "1.0", "privileged_session": "2.0"})
    after = {c["control_id"]: c["assessability"] for c in env.public.get(
        CATALOG + "/policy-controls", params={"tenant_id": "acme"}, headers=env.h()).json()["items"]}
    assert after["PC-MFA-AT-ACCESS"]["end_to_end_assessable"] is True
    assert after["PC-SESSION-DURATION-LIMIT"]["reason"] == "EVIDENCE_SCHEMA_INCOMPATIBLE"
    assert after["PC-CRED-ROTATION"]["reason"] == "COLLECTOR_MISSING"  # the handshake replaces the legacy default


def test_schema_subset_validation_is_strict():
    assert pc.schema_problems({"type": "integer", "default": 5})
    assert pc.schema_problems({"type": "string", "format": "email"})
    assert pc.schema_problems({"oneOf": [{"type": "integer"}]})
    assert pc.schema_problems({"type": "object", "properties": {"a": {"type": "integer"}}, "required": [],
                               "additionalProperties": False})  # optional properties would invite defaults
    assert pc.schema_problems({"type": "object", "properties": {"a": {"type": "integer"}}, "required": ["a"]})
    assert pc.schema_problems({"type": "string", "pattern": "unanchored"})
    assert not pc.schema_problems(pc.get("PC-SEGREGATION-OF-DUTIES", "1.0")["parameter_schema"])
    schema = pc.get("PC-SEGREGATION-OF-DUTIES", "1.0")["parameter_schema"]
    good = {"conflicting_role_pairs": [{"first_role": "Requester", "second_role": "Approver"}], "enforcement": "PREVENT"}
    assert pc.value_problems(schema, good) == []
    codes = lambda v: [p["code"] for p in pc.value_problems(schema, v)]  # noqa: E731
    assert codes({**good, "enforcement": "MAYBE"}) == ["NOT_IN_ENUM"]
    assert codes({**good, "extra": 1}) == ["UNKNOWN_PARAMETER"]
    assert codes({"enforcement": "DETECT"}) == ["MISSING_PARAMETER"]
    assert codes({**good, "conflicting_role_pairs": [{"first_role": "x"}]}) == ["MISSING_PARAMETER"]
    assert codes({**good, "conflicting_role_pairs": [{"first_role": "bad\nname", "second_role": "y"}]}) == [
        "PATTERN_MISMATCH"]
    number = pc.get("PC-PASSWORD-POLICY", "1.0")["parameter_schema"]
    base = {"min_length": 12, "required_character_classes": 3, "min_entropy_bits": 60.5, "history_depth": 5}
    assert pc.value_problems(number, base) == []
    assert [p["code"] for p in pc.value_problems(number, {**base, "min_length": 12.0})] == ["INVALID_TYPE"]
    assert [p["code"] for p in pc.value_problems(number, {**base, "min_length": True})] == ["INVALID_TYPE"]
    assert [p["code"] for p in pc.value_problems(number, {**base, "min_entropy_bits": float("nan")})] == ["INVALID_TYPE"]
    assert [p["code"] for p in pc.value_problems(number, {**base, "min_length": 4})] == ["OUT_OF_RANGE"]


# ---------------------------------------------------------------- B. policy contexts


def test_save_validates_pins_and_is_idempotent_and_immutable(env):
    r = env.save("pol-key-0001", [rotation(30)])
    assert r.status_code == 201, r.text
    v = r.json()["policy_version"]
    assert v["version"] == 1 and v["status"] == "ACTIVE" and v["digest"].startswith("sha256:")
    assert v["provenance"]["origin"] == "CUSTOMER_POLICY" and v["provenance"]["declared_by"] == "deploy"
    assert v["controls"][0]["control_definition_digest"] == pc.get("PC-CRED-ROTATION", "1.0")["definition_digest"]
    assert v["controls"][0]["assessment_blockers"] == []  # legacy rotation evidence is collected
    # same key + same body replays; same key + different body is a conflict
    again = env.save("pol-key-0001", [rotation(30)])
    assert again.status_code == 200 and again.json()["policy_version"]["policy_version_id"] == v["policy_version_id"]
    clash = env.save("pol-key-0001", [rotation(31)])
    assert clash.status_code == 409 and clash.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    # schema validation: every problem reported, nothing defaulted
    bad = env.save("pol-key-0002", [control("PC-CRED-ROTATION", {}),
                                     control("PC-CRED-ROTATION", {"max_rotation_age_days": "30"}, [{"type": "USER",
                                                                                                    "id": "u1"}]),
                                     control("PC-SESSION-IDLE-LIMIT", {"max_idle_minutes": 15, "grace": 1}),
                                     control("PC-NOPE", {}), control("PC-CRED-ROTATION", {"max_rotation_age_days": 3},
                                                                     version="9.9")])
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "INVALID_POLICY_CONTEXT"
    codes = sorted({p["code"] for p in bad.json()["error"]["details"]["problems"]})
    assert codes == ["INVALID_TYPE", "MISSING_PARAMETER", "UNKNOWN_CONTROL", "UNKNOWN_PARAMETER",
                     "UNSUPPORTED_TARGET_TYPE"]
    extra = env.admin.post(ADMIN + "/policy-contexts", headers=env.h(), json={
        "tenant_id": "acme", "request_key": "pol-key-0003", "title": "x", "policy_reference": {"title": "x"},
        "effective_from": PERIOD["start"], "controls": [rotation(30)], "approved": True})
    assert extra.status_code == 422  # unknown fields (e.g. a self-approval flag) are rejected
    dup = env.save("pol-key-0004", [rotation(30), rotation(40)])
    assert dup.status_code == 422 and "DUPLICATE_CONTROL_TARGET" in dup.text
    org_id = env.save("pol-key-0005", [rotation(30, [{"type": "ORGANIZATION", "id": "x"}])])
    assert org_id.status_code == 422
    # writes need catalog:operate
    denied = env.save("pol-key-0006", [rotation(30)], who="reader")
    assert denied.status_code == 403
    # immutable and preserved at the storage layer
    with pytest.raises(sqlite3.DatabaseError):
        env.db.x("UPDATE policy_context_version SET title='changed' WHERE id=?", (v["policy_version_id"],))
    with pytest.raises(sqlite3.DatabaseError):
        env.db.x("DELETE FROM policy_context_version WHERE id=?", (v["policy_version_id"],))


def test_versions_supersede_deterministically_and_history_is_kept(env):
    v1 = env.saved("pol-ver-0001", [rotation(30)], start=P_START - timedelta(days=60))
    cid = v1["policy_context_id"]
    stale = env.save("pol-ver-0002", [rotation(20)], context_id=cid, supersedes=7)
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "VERSION_CONFLICT"
    mid = P_START + timedelta(days=10)
    v2 = env.saved("pol-ver-0003", [rotation(20)], context_id=cid, supersedes=1, start=mid)
    assert v2["version"] == 2 and v2["policy_context_id"] == cid
    detail = env.public.get(f"{CATALOG}/policy-contexts/{cid}/versions/1", params={"tenant_id": "acme"},
                            headers=env.h()).json()["policy_version"]
    assert detail["supersession"]["superseded_intervals"] == [
        {"by_version": 2, "by_policy_version_id": v2["policy_version_id"], "start": format_utc(mid), "end": None}]
    assert detail["supersession"]["in_force_intervals"] == [{"start": v1["effective_from"], "end": format_utc(mid)}]
    listed = env.public.get(CATALOG + "/policy-contexts", params={"tenant_id": "acme"}, headers=env.h()).json()
    assert [x["version"] for x in listed["items"][0]["versions"]] == [1, 2]
    # selecting v1 alone leaves the superseded part uncovered; selecting both covers the period with two segments
    alone = env.ok_plan([v1["policy_version_id"]])
    gap = next(g for g in env.gaps(alone, "rot") if g["code"] == "POLICY_CONTEXT_REQUIRED")
    assert gap["status"] == "PARTIALLY_RESOLVED" and "POLICY_CONTEXT_NOT_EFFECTIVE" in gap["policy_codes"]
    assert gap["uncovered_intervals"] == [{"start": format_utc(mid), "end": PERIOD["end"]}]
    both = env.ok_plan([v1["policy_version_id"], v2["policy_version_id"]])
    gap = next(g for g in env.gaps(both, "rot") if g["code"] == "POLICY_CONTEXT_REQUIRED")
    assert gap["status"] == "RESOLVED_BY_POLICY" and gap["uncovered_intervals"] == []
    segs = sorted((e["reporting_period"]["start"], e["parameters"]["max_rotation_age_days"])
                  for e in both["policy_context"]["executions"])
    assert segs == [(PERIOD["start"], 30), (format_utc(mid), 20)]
    assert all(e["evaluate_request"]["policy_settings"]["effective_from"] <= e["reporting_period"]["start"]
               for e in both["policy_context"]["executions"])


def test_effective_dates_must_cover_the_reporting_period(env):
    late = env.saved("pol-eff-0001", [rotation(30)], start=P_START + timedelta(days=5))
    gap = next(g for g in env.gaps(env.ok_plan([late["policy_version_id"]]), "rot")
               if g["code"] == "POLICY_CONTEXT_REQUIRED")
    assert gap["status"] == "PARTIALLY_RESOLVED"
    assert gap["uncovered_intervals"] == [{"start": PERIOD["start"], "end": format_utc(P_START + timedelta(days=5))}]
    ended = env.saved("pol-eff-0002", [rotation(30)], start=P_START - timedelta(days=90),
                      end=P_START - timedelta(days=1))
    plan = env.ok_plan([ended["policy_version_id"]])
    binding = plan["policy_context"]["bindings"][0]
    assert "POLICY_CONTEXT_NOT_EFFECTIVE" in binding["blocker_codes"] and plan["policy_context"]["executions"] == []
    assert next(g for g in env.gaps(plan, "rot") if g["code"] == "POLICY_CONTEXT_REQUIRED")["status"] == "BLOCKED"


def test_tenant_and_scope_isolation(env):
    v = env.saved("pol-iso-0001", [rotation(30)])
    cid = v["policy_context_id"]
    url = f"{CATALOG}/policy-contexts/{cid}/versions/1"
    assert env.public.get(url, params={"tenant_id": "acme"}, headers=env.h(SCOPE_B)).status_code == 404
    assert env.public.get(CATALOG + "/policy-contexts", params={"tenant_id": "acme"},
                          headers=env.h(SCOPE_B)).json()["items"] == []
    no_scope = env.public.get(url, params={"tenant_id": "acme"}, headers=env.h(None))
    assert no_scope.status_code == 422 and no_scope.json()["error"]["code"] == "SCOPE_REQUIRED"
    other_tenant = env.public.get(url, params={"tenant_id": "acme"}, headers=env.h("pc" * 16, "other"))
    assert other_tenant.status_code == 403 and other_tenant.json()["error"]["code"] == "TENANT_FORBIDDEN"
    stolen = env.save("pol-iso-0002", [rotation(30)], who="intruder")  # scope A is bound to 'deploy'
    assert stolen.status_code == 403 and stolen.json()["error"]["code"] == "SCOPE_FORBIDDEN"
    foreign_version = env.save("pol-iso-0003", [rotation(10)], scope=SCOPE_B, context_id=cid, supersedes=1)
    assert foreign_version.status_code == 404 and foreign_version.json()["error"]["code"] == "UNKNOWN_POLICY_CONTEXT"
    cross = env.plan([v["policy_version_id"]], scope=SCOPE_B)
    assert cross.status_code == 404 and cross.json()["error"]["code"] == "UNKNOWN_POLICY_VERSION"
    unscoped = env.plan([v["policy_version_id"]], scope=None)
    assert unscoped.status_code == 422 and unscoped.json()["error"]["code"] == "SCOPE_REQUIRED"
    no_period = env.public.post(f"{CATALOG}/evaluation-templates/{FW}/plan", headers=env.h(),
                                json={"tenant_id": "acme", "policy_version_ids": [v["policy_version_id"]]})
    assert no_period.json()["error"]["code"] == "REPORTING_PERIOD_REQUIRED"


# ---------------------------------------------------------------- C. plans


def test_policy_resolves_only_its_gap_and_never_replaces_regulatory_thresholds(env):
    publish_regulatory_rotation(env)
    before = env.public.get(f"{CATALOG}/evaluation-templates/{FW}/plan", params={"tenant_id": "acme"},
                            headers=env.h()).json()
    v = env.saved("pol-reg-0001", [rotation(30), control("PC-PASSWORD-POLICY", {
        "min_length": 16, "required_character_classes": 3, "min_entropy_bits": 70.0, "history_depth": 12})])
    # old clients: unchanged plan, unchanged digest, no policy fields
    old = env.public.get(f"{CATALOG}/evaluation-templates/{FW}/plan", params={"tenant_id": "acme"},
                         headers=env.h()).json()
    assert old["plan_digest"] == before["plan_digest"] and "policy_context" not in old
    assert all("policy_resolution" not in r for r in old["requirements"])
    plan = env.ok_plan([v["policy_version_id"]])
    assert plan["plan_digest"] != before["plan_digest"]
    # regulatory part is untouched: same executions, 90 days stays 90 days
    assert plan["executions"] == old["executions"]
    assert {k: v for k, v in plan["digest_input"].items() if k != "policy_context"} == old["digest_input"]
    assert [e["parameters"] for e in plan["executions"]] == [{"max_rotation_age_days": 90}]
    rot90 = next(r for r in plan["requirements"] if r["requirement_id"] == env.ids["rot90"])
    assert rot90["policy_resolution"]["policy_execution_ids"] == []
    assert [g["code"] for g in rot90["policy_resolution"]["gaps"]] == ["PARTIAL_COVERAGE"]
    # the unstated interval is resolved by the company value, labelled CUSTOMER_POLICY
    gap = next(g for g in env.gaps(plan, "rot") if g["code"] == "POLICY_CONTEXT_REQUIRED")
    assert gap["status"] == "RESOLVED_BY_POLICY" and gap["target_coverage"] == "ORGANIZATION"
    [execution] = plan["policy_context"]["executions"]
    assert execution["provenance"] == "CUSTOMER_POLICY" and execution["parameters"] == {"max_rotation_age_days": 30}
    assert execution["requirement_ids"] == [env.ids["rot"]]
    assert execution["evaluate_request"]["policy_settings"]["policy_version"] == v["policy_version_id"]
    # other gaps stay distinct and open
    assert {g["code"]: g["status"] for g in env.gaps(plan, "review")} == {"COLLECTOR_MISSING": "OPEN"}
    assert {g["code"]: g["status"] for g in env.gaps(plan, "mfa")} == {"COLLECTOR_MISSING": "OPEN"}
    # documented-only control: saved, blocked, never executed
    pw = next(b for b in plan["policy_context"]["bindings"] if b["control_id"] == "PC-PASSWORD-POLICY")
    assert pw["blocker_codes"] == ["NO_EXECUTABLE_RULE"] and pw["execution_ids"] == []
    # the regulatory row itself is unchanged
    row = env.db.one("SELECT thresholds, status FROM regulatory_requirement WHERE id=?", (env.ids["rot90"],))
    assert row["thresholds"][0]["value_text"] == "90 days" and row["status"] == "APPROVED"


def test_missing_collector_keeps_the_gap_until_the_handshake(env):
    v = env.saved("pol-col-0001", [MFA_AT_ACCESS])
    plan = env.ok_plan([v["policy_version_id"]])
    [gap] = env.gaps(plan, "mfa")
    assert gap["code"] == "COLLECTOR_MISSING" and gap["status"] == "OPEN" and gap["policy_codes"] == ["COLLECTOR_MISSING"]
    assert plan["policy_context"]["bindings"][0]["blocker_codes"] == ["COLLECTOR_MISSING"]
    env.handshake({"privileged_access_authentication": "1.0"})
    plan = env.ok_plan([v["policy_version_id"]])
    gap, residual = env.gaps(plan, "mfa")
    assert (gap["code"], gap["status"]) == ("POLICY_CONTEXT_REQUIRED", "RESOLVED_BY_POLICY")
    # the rule tests MFA at access only: the rest of the passage stays visible as partial coverage
    assert (residual["code"], residual["status"], residual["rule_id"]) == ("PARTIAL_COVERAGE", "OPEN", "PAM-MFAACC-001")
    req = next(r for r in plan["requirements"] if r["requirement_id"] == env.ids["mfa"])
    assert req["policy_resolution"]["summary"] == "PARTIALLY_RESOLVED"
    assert plan["policy_context"]["executions"][0]["parameters"] == {"accepted_methods": ["fido2", "totp"]}
    env.handshake({"privileged_access_authentication": "9.0"})
    plan = env.ok_plan([v["policy_version_id"]])
    assert "EVIDENCE_SCHEMA_INCOMPATIBLE" in plan["policy_context"]["bindings"][0]["blocker_codes"]
    bad = env.admin.put(ADMIN + "/collector-capabilities", headers=env.h(), json={
        "tenant_id": "acme", "collector": {"name": "x", "version": "1"},
        "evidence": [{"evidence_type": "made_up_type", "schema_version": "1.0"}]})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "UNKNOWN_EVIDENCE_TYPE"


def test_configuration_snapshot_never_resolves_an_event_requirement(env):
    env.handshake({"mfa_configuration": "1.0", "privileged_access_authentication": "1.0"})
    v = env.saved("pol-cfg-0001", [control("PC-MFA-CONFIGURATION", {"accepted_methods": ["fido2"]})])
    plan = env.ok_plan([v["policy_version_id"]])
    [gap] = env.gaps(plan, "mfa")
    assert (gap["code"], gap["status"], gap["binding_ids"]) == ("POLICY_CONTEXT_REQUIRED", "OPEN", [])
    [binding] = plan["policy_context"]["bindings"]
    assert binding["assessment_mode"] == "CONFIGURATION_SNAPSHOT" and binding["unused_reason"].startswith("NO_MATCHING")
    assert plan["policy_context"]["executions"] == []


def test_conflicts_and_unresolved_scope(env):
    g1 = [{"type": "ACCOUNT_GROUP", "id": "grp-finance"}]
    a1 = [{"type": "ACCOUNT", "id": "acct-007"}]
    va = env.saved("pol-cnf-0001", [rotation(30, g1)], title="Group policy")
    vb = env.saved("pol-cnf-0002", [rotation(60, a1)], title="Account policy")
    ids = [va["policy_version_id"], vb["policy_version_id"]]

    def outcome(resolutions=None):
        plan = env.ok_plan(ids, resolutions=resolutions)
        gap = next(g for g in env.gaps(plan, "rot") if g["code"] == "POLICY_CONTEXT_REQUIRED")
        return ({c for b in plan["policy_context"]["bindings"] for c in b["blocker_codes"]}, gap["status"],
                len(plan["policy_context"]["executions"]))

    full = {"valid_from": format_utc(P_START - timedelta(days=1)), "complete": True, "target": g1[0]}
    # group vs account without membership: overlap undecidable
    assert outcome() == ({"POLICY_SCOPE_UNRESOLVED"}, "BLOCKED", 0)
    # membership known and the account is in the group: conflicting values
    assert outcome([{**full, "members": [{"type": "ACCOUNT", "id": "acct-007"}]}]) == ({"POLICY_CONFLICT"}, "BLOCKED", 0)
    # membership known, disjoint: both bindings run, but only for their targets
    disjoint = outcome([{**full, "members": [{"type": "ACCOUNT", "id": "acct-001"}]}])
    assert disjoint == (set(), "PARTIALLY_RESOLVED", 2)
    # only current membership (from mid-period): historical membership missing -> unresolved
    current_only = {**full, "valid_from": format_utc(P_START + timedelta(days=15)),
                    "members": [{"type": "ACCOUNT", "id": "acct-001"}]}
    assert outcome([current_only])[0] == {"POLICY_SCOPE_UNRESOLVED"}
    incomplete = {**full, "complete": False, "members": [{"type": "ACCOUNT", "id": "acct-001"}]}
    assert outcome([incomplete])[0] == {"POLICY_SCOPE_UNRESOLVED"}
    # organization-wide vs one account with a different value: conflict without needing membership
    vc = env.saved("pol-cnf-0003", [rotation(45)], title="Organization policy")
    plan = env.ok_plan([vb["policy_version_id"], vc["policy_version_id"]])
    assert {c for b in plan["policy_context"]["bindings"] for c in b["blocker_codes"]} == {"POLICY_CONFLICT"}
    # same value on overlapping targets is not a conflict
    vd = env.saved("pol-cnf-0004", [rotation(45, a1)], title="Same value")
    plan = env.ok_plan([vc["policy_version_id"], vd["policy_version_id"]])
    assert all(not b["blocker_codes"] for b in plan["policy_context"]["bindings"])
    bad_member = env.plan(ids, resolutions=[{**full, "members": [{"type": "USER", "id": "u1"}]}])
    assert bad_member.status_code == 422


def test_saved_plans_go_stale_when_policy_or_collector_changes(env):
    v1 = env.saved("pol-stl-0001", [rotation(30)], start=P_START - timedelta(days=60))
    plan = env.ok_plan([v1["policy_version_id"]])
    digest = plan["plan_digest"]
    assert env.ok_plan([v1["policy_version_id"]], expected_digest=digest)["plan_digest"] == digest  # deterministic
    env.saved("pol-stl-0002", [rotation(25)], context_id=v1["policy_context_id"], supersedes=1,
              start=P_START + timedelta(days=3))
    stale = env.plan([v1["policy_version_id"]], expected_digest=digest)
    assert stale.status_code == 409 and stale.json()["error"]["code"] == "PLAN_STALE"
    fresh = env.ok_plan([v1["policy_version_id"]])["plan_digest"]
    env.handshake({"credential_rotation": "1.0"})
    assert env.plan([v1["policy_version_id"]], expected_digest=fresh).status_code == 409


# ---------------------------------------------------------------- real OPA


def test_policy_executions_run_through_the_real_engine(tmp_path, opa_url):
    admin, public, db, ids, headers = build(tmp_path, opa_url)
    with TestClient(admin) as a, TestClient(public) as p:
        env = Env(a, p, db, ids, headers)
        env.handshake({"credential_rotation": "1.0", "privileged_access_authentication": "1.0"})
        v = env.saved("pol-opa-0001", [rotation(30), MFA_AT_ACCESS])
        plan = env.ok_plan([v["policy_version_id"]])
        execs = {e["rule_id"]: e for e in plan["policy_context"]["executions"]}
        end = P_END

        def run(rule_id, evidence_type, records):
            body = {"tenant_id": "acme", **execs[rule_id]["evaluate_request"],
                    "evidence": {"evidence_type": evidence_type, "records": records,
                                 "completeness": {"expected_record_count": len(records),
                                                  "received_record_count": len(records), "source_complete": True}}}
            r = p.post("/api/v1/evaluate", json=body, headers=headers["deploy"])
            assert r.status_code == 200, r.text
            return r.json()

        def rot(i, days):
            return {"record_id": f"rot-{i}", "account_id": f"acct-{i}", "privileged": True,
                    "last_rotated_at": format_utc(end - timedelta(days=days)), "last_rotation_status": "SUCCESS"}

        ok = run("PAM-ROTATION-001", "credential_rotation", [rot(1, 10)])
        assert ok["status"] == "PASS" and ok["decision_details"]["parameters"]["max_rotation_age_days"] == 30
        assert ok["decision_details"]["customer_policy_version"] == v["policy_version_id"]
        assert run("PAM-ROTATION-001", "credential_rotation", [rot(1, 40)])["status"] == "FAIL"  # 30, not 90

        def access(i, status, method):
            return {"record_id": f"acc-{i}", "access_id": f"acc-{i}", "user_id": "u", "account_id": "a",
                    "accessed_at": format_utc(end - timedelta(days=2)), "access_granted": True,
                    "mfa_status": status, "mfa_method": method}

        assert run("PAM-MFAACC-001", "privileged_access_authentication", [access(1, "VERIFIED", "fido2")])["status"] == "PASS"
        bad = run("PAM-MFAACC-001", "privileged_access_authentication",
                  [access(1, "VERIFIED", "fido2"), access(2, "NOT_PERFORMED", None), access(3, "VERIFIED", "sms")])
        assert bad["status"] == "FAIL"
        assert {x["subject_id"]: x["reasons"] for x in bad["violations"]} == {
            "acc-2": ["MFA_NOT_PERFORMED"], "acc-3": ["MFA_METHOD_NOT_ACCEPTED"]}
        # failed-logon evidence is not accepted as MFA evidence
        wrong = p.post("/api/v1/evaluate", headers=headers["deploy"], json={
            "tenant_id": "acme", **execs["PAM-MFAACC-001"]["evaluate_request"],
            "evidence": {"evidence_type": "authentication_summary", "records": [],
                         "completeness": {"received_record_count": 0, "source_complete": True}}})
        assert wrong.status_code == 422 and wrong.json()["error"]["code"] == "EVIDENCE_TYPE_MISMATCH"
    db.close()
