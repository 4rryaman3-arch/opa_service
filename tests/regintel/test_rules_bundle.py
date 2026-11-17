"""Rule definitions, threshold provenance, tested immutable bundles, rollback."""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from regintel import catalog, coverage, rules
from regintel.db import CatalogError

from .. import helpers
from ..conftest import BUNDLE, OPA_TOKEN, ROOT, _free_port, make_settings, opa_binary
from . import support as s

TESTS_DIR = ROOT / "policy-tests"


def code(exc) -> str:
    return exc.value.code


@pytest.fixture
def cat(tmp_path):
    db = s.make_db(tmp_path)
    return db, s.reviewed_requirements(db, tmp_path)


@pytest.fixture
def opa():
    binary = opa_binary()
    if not binary:
        pytest.skip("OPA binary not available (set OPM_TEST_OPA_BINARY)")
    return binary


def build(db, tmp_path, opa):
    return rules.build_bundle(db, base_dir=BUNDLE, store_dir=tmp_path / "store", tests_dir=TESTS_DIR, opa_binary=opa, actor="bob")


# ---------------------------------------------------------------- definitions & thresholds (no OPA needed)


def test_rule_definitions_are_structured_data_never_rego(cat):
    db, ids = cat
    for mutate, fragment in (
        (lambda d: d.update(rule_id="PAM-ROTATION-001"), "rule_id"),
        (lambda d: d.update(rego="package x\nallow := true"), "rego"),
        (lambda d: d["violation_when"]["all"].append({"field": "password", "op": "eq", "value": "x"}), "not allowed"),
        (lambda d: d.update(framework_mappings=[{"framework": "ISO27001:2022", "control": "8.2"}]), "framework_mappings"),
    ):
        d = s.rule_definition()
        mutate(d)
        with pytest.raises(CatalogError) as exc:
            rules.draft_rule_version(db, definition=d, pam_control_id="PAMC-CRED-ROTATION", threshold_provenance=[],
                                     tests=s.rule_tests(), actor="alice")
        assert code(exc) == "RULE_INVALID" and fragment in exc.value.message


def test_regulatory_threshold_must_appear_in_the_official_text(cat):
    db, ids = cat
    kw = dict(pam_control_id="PAMC-CRED-ROTATION", tests=s.rule_tests(), actor="alice")
    with pytest.raises(CatalogError) as exc:
        rules.draft_rule_version(db, definition=s.rule_definition(), threshold_provenance=[], **kw)
    assert code(exc) == "THRESHOLD_PROVENANCE_MISSING"
    # 30 days is not in the passage ("at least every 90 days"): it cannot be called regulatory.
    with pytest.raises(CatalogError) as exc:
        rules.draft_rule_version(db, definition=s.rule_definition(days=30), threshold_provenance=[
            {"condition": "g1.c2", "origin": "REGULATORY", "requirement_id": ids["rotation"]}], **kw)
    assert code(exc) == "THRESHOLD_NOT_IN_SOURCE"
    # "9" is a substring of "90" but not the number in the text.
    with pytest.raises(CatalogError) as exc:
        rules.draft_rule_version(db, definition=s.rule_definition(days=9), threshold_provenance=[
            {"condition": "g1.c2", "origin": "REGULATORY", "requirement_id": ids["rotation"]}], **kw)
    assert code(exc) == "THRESHOLD_NOT_IN_SOURCE"
    # The session passage states no number at all.
    with pytest.raises(CatalogError) as exc:
        rules.draft_rule_version(db, definition=s.rule_definition(), threshold_provenance=[
            {"condition": "g1.c2", "origin": "REGULATORY", "requirement_id": ids["session"]}], **kw)
    assert code(exc) == "THRESHOLD_NOT_IN_SOURCE"
    with pytest.raises(CatalogError) as exc:
        rules.draft_rule_version(db, definition=s.rule_definition(days=30), threshold_provenance=[
            {"condition": "g1.c2", "origin": "SECURDEN_DEFAULT"}], **kw)
    assert code(exc) == "THRESHOLD_PROVENANCE_INVALID"  # needs a note
    rid = rules.draft_rule_version(db, definition=s.rule_definition(days=30), threshold_provenance=[
        {"condition": "g1.c2", "origin": "SECURDEN_DEFAULT", "note": "Stricter Securden default; not a regulatory value."}], **kw)
    assert db.one("SELECT threshold_provenance FROM rule_version WHERE id=?", (rid,))["threshold_provenance"][0]["origin"] == "SECURDEN_DEFAULT"


def test_rule_needs_pass_and_fail_tests_and_independent_review(cat):
    db, ids = cat
    prov = [{"condition": "g1.c2", "origin": "REGULATORY", "requirement_id": ids["rotation"]}]
    for tests, expected in (([], "RULE_TESTS_REQUIRED"), (s.rule_tests()[:1], "RULE_TESTS_REQUIRED"),
                            ([{**s.rule_tests()[0], "records": [{"record_id": "x", "password": "hunter2"}]}, s.rule_tests()[1]], "RULE_TESTS_INVALID")):
        with pytest.raises(CatalogError) as exc:
            rules.draft_rule_version(db, definition=s.rule_definition(), pam_control_id="PAMC-CRED-ROTATION",
                                     threshold_provenance=prov, tests=tests, actor="alice")
        assert code(exc) == expected
    rid = s.draft_rule(db, ids["rotation"])
    with pytest.raises(CatalogError) as exc:
        rules.review_rule_version(db, rid, reviewer="alice", decision="APPROVED")
    assert code(exc) == "SELF_APPROVAL"
    with pytest.raises(CatalogError) as exc:
        s.draft_rule(db, ids["rotation"])
    assert code(exc) == "RULE_VERSION_EXISTS"
    rules.review_rule_version(db, rid, reviewer="bob", decision="APPROVED")
    with pytest.raises(Exception, match="immutable"):
        db.x("UPDATE rule_version SET definition='{}' WHERE id=?", (rid,))


def test_bundle_build_requires_opa(cat, tmp_path):
    db, _ = cat
    with pytest.raises(CatalogError) as exc:
        rules.build_bundle(db, base_dir=BUNDLE, store_dir=tmp_path / "store", tests_dir=None, opa_binary=None, actor="bob")
    assert code(exc) == "OPA_UNAVAILABLE"


def test_base_bundle_is_consistent():
    assert rules.check_bundle_consistency(BUNDLE) == []


def test_consistency_check_detects_catalog_rego_drift(tmp_path):
    import shutil

    target = tmp_path / "bundle"
    shutil.copytree(BUNDLE, target)
    (target / "securden" / "rules" / "pam_dormant_001" / "v1_0" / "policy.rego").unlink()
    problems = rules.check_bundle_consistency(target)
    assert problems == ["PAM-DORMANT-001 1.0: package securden.rules.pam_dormant_001.v1_0 is not in the bundle"]


# ---------------------------------------------------------------- bundles (real OPA)

pytestmark_opa = pytest.mark.opa


@pytest.mark.opa
def test_unreviewed_rules_are_never_published(cat, tmp_path, opa):
    db, ids = cat
    s.draft_rule(db, ids["rotation"])  # DRAFT, never approved
    out = build(db, tmp_path, opa)
    assert out["rule_versions"] == 0
    catalog_json = json.loads((tmp_path / "store" / "versions" / out["version"] / "securden" / "catalog" / "data.json").read_text())
    assert not [r for r in catalog_json["rules"] if r.startswith("REG-")]


@pytest.mark.opa
def test_bundle_build_tests_rules_and_is_immutable(cat, tmp_path, opa):
    db, ids = cat
    mid = catalog.create_mapping(db, requirement_id=ids["rotation"], pam_control_id="PAMC-CRED-ROTATION", strength="DIRECT",
                                 rationale="Fixture rationale long enough to pass.", limitations="Fixture limitation.", actor="alice")
    catalog.review(db, "mapping", mid, reviewer="bob", decision="APPROVED")
    catalog.publish_catalog(db, "bob")
    rules.review_rule_version(db, s.draft_rule(db, ids["rotation"]), reviewer="bob", decision="APPROVED")
    out = build(db, tmp_path, opa)
    report = out["test_report"]
    assert (report["opa_check"], report["rego_unit_tests"], report["consistency"]) == ("PASS", "PASS", "PASS")
    assert [t["passed"] for t in report["rule_tests"]] == [True, True]
    bundle_dir = tmp_path / "store" / "versions" / out["version"]
    data = json.loads((bundle_dir / "securden" / "catalog" / "data.json").read_text())
    entry = data["rules"]["REG-SYN-ROTATION-001"]["versions"]["1.0"]
    assert entry["source"] == "PUBLISHED" and entry["package"] == "securden.custom.v1"
    assert entry["framework_mappings"] == [{"framework": "SYN-EU-ACT", "control": "#2 Article 7 Privileged credentials",
                                            "title": f"interpretive mapping #{mid} via PAMC-CRED-ROTATION"}]
    assert not list(bundle_dir.rglob("*reg*.rego"))  # no Rego was generated
    assert json.loads((bundle_dir / "securden" / "bundle" / "data.json").read_text())["version"] == out["version"]
    assert rules.check_bundle_consistency(bundle_dir) == []
    with pytest.raises(Exception, match="immutable"):
        db.x("UPDATE bundle_version SET digest='0'")
    # tampering with a recorded bundle is detected at activation
    target = bundle_dir / "securden" / "catalog" / "data.json"
    os.chmod(target, 0o644)
    target.write_text(target.read_text().replace('"value": 90', '"value": 900'))
    with pytest.raises(CatalogError) as exc:
        rules.activate_bundle(db, tmp_path / "store", out["version"], actor="bob")
    assert code(exc) == "BUNDLE_TAMPERED"


@pytest.mark.opa
def test_failing_rule_tests_block_the_bundle(cat, tmp_path, opa):
    db, ids = cat
    rid = rules.draft_rule_version(
        db, definition=s.rule_definition(), pam_control_id="PAMC-CRED-ROTATION",
        threshold_provenance=[{"condition": "g1.c2", "origin": "REGULATORY", "requirement_id": ids["rotation"]}],
        tests=s.rule_tests(expect_old="PASS") + [{**s.rule_tests()[1], "name": "really fails"}], actor="alice")
    rules.review_rule_version(db, rid, reviewer="bob", decision="APPROVED")
    with pytest.raises(CatalogError) as exc:
        build(db, tmp_path, opa)
    assert code(exc) == "BUNDLE_TESTS_FAILED" and "expected PASS, got FAIL" in exc.value.message
    assert db.scalar("SELECT COUNT(*) FROM bundle_version") == 0
    assert not list((tmp_path / "store" / "versions").iterdir())  # nothing left behind


@pytest.mark.opa
def test_withdrawn_requirement_blocks_rules_that_cite_it(cat, tmp_path, opa):
    db, ids = cat
    rules.review_rule_version(db, s.draft_rule(db, ids["rotation"]), reviewer="bob", decision="APPROVED")
    catalog.publish_catalog(db, "bob")
    catalog.withdraw(db, "requirement", ids["rotation"], actor="bob", reason="Fixture: withdrawn after re-review.")
    with pytest.raises(CatalogError) as exc:
        build(db, tmp_path, opa)
    assert code(exc) == "THRESHOLD_NOT_IN_SOURCE"


def _start_opa(binary: str, bundle_dir: Path):
    port = _free_port()
    proc = subprocess.Popen(
        [binary, "run", "--server", "--addr", f"127.0.0.1:{port}", "--authentication=token", "--authorization=basic",
         "--log-level=error", "--disable-telemetry", bundle_dir.name],
        env={**os.environ, "OPA_AUTH_TOKEN": OPA_TOKEN}, cwd=str(bundle_dir.parent), stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            if httpx.get(f"{url}/health", headers={"Authorization": f"Bearer {OPA_TOKEN}"}, timeout=1).status_code == 200:
                return proc, url
        except httpx.HTTPError:
            time.sleep(0.2)
    proc.kill()
    raise RuntimeError("OPA did not start")


@pytest.mark.opa
def test_published_rule_evaluates_end_to_end_then_rolls_back(cat, tmp_path, opa, clients_file):
    """Approved definition -> tested bundle -> activation -> the *existing*
    evaluation API returns a deterministic decision -> rollback removes it."""
    db, ids = cat
    store = tmp_path / "store"
    rules.review_rule_version(db, s.draft_rule(db, ids["rotation"]), reviewer="bob", decision="APPROVED")
    v1 = build(db, tmp_path, opa)["version"]
    activated = rules.activate_bundle(db, store, v1, actor="bob")
    assert rules.active_bundle(store) == v1 and rules.resolve_bundle_dir(store, BUNDLE) == store / "versions" / v1
    assert coverage.metrics(db)["published_opa_rules"]["catalog_rules_in_active_bundle"] == 1
    changes = db.q("SELECT entity_type, change_type FROM catalog_change WHERE publication_seq=?", (activated["catalog_version"],))
    assert changes == [{"entity_type": "rule_version", "change_type": "UPSERT"}]

    start, end = helpers.recent_period()
    body = helpers.request("tenant-a", "REG-SYN-ROTATION-001", "credential_rotation", [
        helpers.rotation(1, rotated_at=end - timedelta(days=10)), helpers.rotation(2, rotated_at=end - timedelta(days=95)),
        helpers.rotation(3, rotated_at=None)])
    proc, url = _start_opa(opa, rules.resolve_bundle_dir(store, BUNDLE))
    try:
        settings = make_settings(tmp_path, clients_file, url, policy_bundle_dir=rules.resolve_bundle_dir(store, BUNDLE),
                                 catalog_db_path=Path(db.path))
        with TestClient(create_app(settings)) as client:
            assert client.get("/ready").json()["status"] == "ready"
            r = client.post("/api/v1/evaluate", json=body, headers=helpers.auth())
            assert r.status_code == 200, r.text
            result = r.json()
            assert result["status"] == "FAIL" and result["policy_bundle_version"] == v1
            assert sorted(v["subject_id"] for v in result["violations"]) == ["acct-00002", "acct-00003"]
            assert result["decision_details"]["rule_source"] == "PUBLISHED"
            assert result["decision_details"]["policy_package"] == "securden.custom.v1"
            again = client.post("/api/v1/evaluate", json=body, headers=helpers.auth()).json()
            assert again["decision_details"]["input_digest"] == result["decision_details"]["input_digest"]
            # existing predefined rules are untouched by the new bundle
            pre = client.post("/api/v1/evaluate", headers=helpers.auth(), json=helpers.request(
                "tenant-a", "PAM-ROTATION-001", "credential_rotation", [helpers.rotation(1, rotated_at=end - timedelta(days=95))]))
            assert pre.status_code == 200 and pre.json()["status"] == "FAIL" and pre.json()["decision_details"]["rule_source"] == "PREDEFINED"
            listed = client.get("/api/v1/catalog/rules", headers=helpers.auth("catalog-sync")).json()
            reg = next(i for i in listed["items"] if i["rule_id"] == "REG-SYN-ROTATION-001")
            assert listed["bundle_consistent"] and reg["versions"][0]["in_running_bundle"]
            assert reg["versions"][0]["threshold_provenance"][0]["origin"] == "REGULATORY"
        # API still on v1 while OPA is asked about a different bundle -> fail closed, never a result
        with TestClient(create_app(make_settings(tmp_path, clients_file, url, catalog_db_path=Path(db.path)))) as stale:
            assert stale.get("/ready").status_code == 503
            r = stale.post("/api/v1/evaluate", headers=helpers.auth(), json=helpers.request(
                "tenant-a", "PAM-ROTATION-001", "credential_rotation", [helpers.rotation(1, rotated_at=end)]))
            assert r.status_code == 502 and r.json()["error"]["code"] == "POLICY_VERSION_MISMATCH"
    finally:
        proc.terminate()
        proc.wait(timeout=10)

    # rollback = activate an earlier version (here: the base bundle)
    rolled = rules.activate_bundle(db, store, None, actor="bob")
    assert rolled["previous"] == v1 and rules.resolve_bundle_dir(store, BUNDLE) == BUNDLE
    assert db.q("SELECT change_type FROM catalog_change WHERE publication_seq=?", (rolled["catalog_version"],)) == [{"change_type": "WITHDRAW"}]
    assert coverage.metrics(db)["published_opa_rules"]["catalog_rules_in_active_bundle"] == 0
    assert (store / "versions" / v1).is_dir()  # history is kept
    rules.activate_bundle(db, store, v1, actor="bob")  # and can be re-activated after digest verification
    with pytest.raises(CatalogError) as exc:
        rules.activate_bundle(db, store, "2099.01.01-1-reg9999", actor="bob")
    assert code(exc) == "UNKNOWN_BUNDLE"


@pytest.mark.opa
def test_new_bundle_versions_never_overwrite_old_ones(cat, tmp_path, opa):
    db, ids = cat
    rules.review_rule_version(db, s.draft_rule(db, ids["rotation"]), reviewer="bob", decision="APPROVED")
    v1 = build(db, tmp_path, opa)
    rules.review_rule_version(db, s.draft_rule(db, ids["rotation"], version="1.1"), reviewer="bob", decision="APPROVED")
    v2 = build(db, tmp_path, opa)
    assert v1["version"] != v2["version"] and v2["rule_versions"] == 2
    store = tmp_path / "store"
    rules.verify_bundle(db, store, v1["version"])
    rules.verify_bundle(db, store, v2["version"])
    manifest = json.loads((store / "manifests" / f"{v1['version']}.json").read_text())
    assert manifest["digest"] == v1["digest"] and len(manifest["rule_versions"]) == 1
