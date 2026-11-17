"""Source-grounded mapping proposals: the real NIST proposal set file, live validation against
the stored text and canonical references, collector handshake and scope isolation, preserved
proposal runs. The fixture framework is SYNTHETIC (see test_control_catalog_mapping); its quoted
passages are verbatim NIST SP 800-53 Rev. 5 text. Nothing here drafts or publishes a mapping."""
from __future__ import annotations

import copy
import sqlite3

import pytest

from regintel import mapping_proposals as mpp
from .test_control_catalog_mapping import FW, Q, env  # noqa: F401  (fixture)
from .test_policy_contexts import ADMIN, CATALOG, SCOPE_B

NIST = "NIST-SP-800-53-R5"
# published catalog requirement id -> fixture key (same verbatim passage)
REAL = {354: "au14", 360: "ia26", 372: "ia5i", 299: "ac2i", 326: "ac7a", 304: "ac2_2", 291: "ac2a"}


def real_set():
    data = mpp.proposal_set(NIST)
    assert data is not None
    return data


def fixture_set(env, mutate=None):
    data = copy.deepcopy(real_set())
    data["framework_id"] = FW
    data["proposals"] = [{**p, "requirement_id": env.ids[REAL[p["requirement_id"]]]}
                         for p in data["proposals"] if p["requirement_id"] in REAL]
    if mutate:
        mutate(data)
    return data


@pytest.fixture
def proposals(env, monkeypatch):  # noqa: F811
    data = fixture_set(env)
    monkeypatch.setattr(mpp, "proposal_set", lambda fw: data if fw == FW else None)
    return data


def by_key(body, env, key):
    return next(i for i in body["items"] if i["requirement_id"] == env.ids[key])


def test_real_nist_proposal_set_is_grounded_and_invents_nothing():
    data = real_set()
    assert mpp.set_problems(data) == []
    assert data["status"] == "PROPOSED_UNREVIEWED" and "not cover the whole framework" in data["statement"]
    ids = [p["requirement_id"] for p in data["proposals"]]
    assert len(ids) == 41 == len(set(ids))
    props = {p["requirement_id"]: p for p in data["proposals"]}
    # every passage quoted by the fixture is the published passage the proposal is keyed to
    for rid, key in REAL.items():
        assert Q[key].startswith(props[rid]["quote_prefix"].removeprefix("i. ")), rid
    # no parameter value is ever stated: NIST leaves them organization-defined or silent
    for p in data["proposals"]:
        for prm in (p.get("candidate") or {}).get("parameters", []):
            assert prm["provenance"] in ("ORGANIZATION_DEFINED", "NOT_IN_SOURCE") and "value" not in prm
    au14 = props[354]["candidate"]
    assert (au14["rule_id"], au14["coverage"], au14["policy_control_id"]) == (
        "PAM-SESSREC-001", "PARTIAL", "PC-SESSION-RECORDING")
    assert props[354]["proposed_code"] == "POLICY_CONTEXT_REQUIRED"
    assert props[360]["candidate"]["rule_id"] == "PAM-MFAACC-001"
    assert {r["rule_id"] for r in props[360]["rejected_rules"]} == {"PAM-MFACFG-001"}
    assert "factor_on_separate_device (boolean)" in props[360]["candidate"]["required_new_evidence_fields"]
    assert props[372]["classification"] == "REJECTED" and props[372]["proposed_code"] == "NO_EXECUTABLE_RULE"
    assert {r["rule_id"] for r in props[372]["rejected_rules"]} == {"PAM-ROTATION-001"}
    assert props[372]["proposed_new_rule"]["status"] == "NOT_IMPLEMENTED"
    # look-alike rules are never candidates
    for p in data["proposals"]:
        if p.get("candidate"):
            assert p["candidate"]["rule_id"] not in ("PAM-ROTATION-001", "PAM-DORMANT-001", "PAM-MFACFG-001")


def test_proposals_validate_live_and_none_is_publishable(env, proposals):  # noqa: F811
    r = env.public.get(f"{CATALOG}/frameworks/{FW}/mapping-proposals", headers=env.h(None))
    assert r.status_code == 200, r.text
    body = r.json()
    assert all(i["proposal_status"] == "VALID" for i in body["items"] if "classification" in i)
    au14 = by_key(body, env, "au14")
    assert au14["citation"]["quote"] == Q["au14"] and au14["citation"]["canonical_id"] == "AU-14"
    assert au14["citation"]["clause"] == "a" and au14["citation"]["document_version_id"]
    assert au14["effective_code"] == "POLICY_CONTEXT_REQUIRED" and au14["candidate"]["validation_problems"] == []
    assert au14["publication"]["route"]["policy_control_id"] == "PC-SESSION-RECORDING"
    assert au14["publication"]["route"]["result_at_best"] == "PARTIALLY_RESOLVED"
    assert au14["residual_gaps"] == ["PARTIAL_COVERAGE"] and au14["publication"]["eligible"] is False
    assert {"ORGANIZATION_DEFINED_INPUTS", "PARAMETER_NOT_IN_SOURCE"} <= set(au14["publication"]["blockers"])
    ia26 = by_key(body, env, "ia26")
    assert ia26["citation"]["canonical_id"] == "IA-2(6)" and ia26["effective_code"] == "COLLECTOR_MISSING"
    assert "COLLECTOR_MISSING" in ia26["publication"]["blockers"] and ia26["publication"]["route"] is None
    ia5i = by_key(body, env, "ia5i")
    assert ia5i["rejection"]["code"] == "NO_EXECUTABLE_RULE"
    assert ia5i["rejection"]["detail_code"] == "LOOKALIKE_RULE_REJECTED"
    assert ia5i["rejection"]["rejected_rules"][0]["rule_id"] == "PAM-ROTATION-001"
    # requirement without a proposal keeps the engine's own code
    disc = next(i for i in body["items"] if i["requirement_id"] == env.ids["ac2disc"])
    assert disc["proposal_status"] == "NO_PROPOSAL"
    assert body["counts"]["eligible_for_publication"] == 0
    again = env.public.get(f"{CATALOG}/frameworks/{FW}/mapping-proposals", headers=env.h(None)).json()
    assert again["proposal_digest"] == body["proposal_digest"]  # deterministic
    assert env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping") == 0
    assert env.public.get(f"{CATALOG}/frameworks/{NIST}X/mapping-proposals", headers=env.h(None)).status_code == 404


def test_handshake_changes_codes_per_organization_only(env, proposals):  # noqa: F811
    params = {"tenant_id": "acme"}
    env.handshake({"privileged_access_authentication": "1.0", "privileged_session": "1.0"})
    mine = env.public.get(f"{CATALOG}/frameworks/{FW}/mapping-proposals", params=params, headers=env.h()).json()
    ia26 = by_key(mine, env, "ia26")
    # collector declared: MFA at access still needs the organization's accepted methods; never publishable
    assert ia26["effective_code"] == "POLICY_CONTEXT_REQUIRED" and ia26["candidate"]["collected"] is True
    assert "COLLECTOR_MISSING" not in ia26["publication"]["blockers"] and ia26["publication"]["eligible"] is False
    other = env.public.get(f"{CATALOG}/frameworks/{FW}/mapping-proposals", params=params,
                           headers=env.h(SCOPE_B)).json()
    assert by_key(other, env, "ia26")["effective_code"] == "COLLECTOR_MISSING"
    assert other["proposal_digest"] != mine["proposal_digest"]


def test_source_mismatch_invalidates_a_proposal(env, monkeypatch):  # noqa: F811
    def wrong(data):
        for p in data["proposals"]:
            if p["requirement_id"] == env.ids["au14"]:
                p["canonical_id"] = "AU-13"
            if p["requirement_id"] == env.ids["ia5i"]:
                p["quote_prefix"] = "Changing passwords every 90 days"
    data = fixture_set(env, wrong)
    monkeypatch.setattr(mpp, "proposal_set", lambda fw: data if fw == FW else None)
    body = env.public.get(f"{CATALOG}/frameworks/{FW}/mapping-proposals", headers=env.h(None)).json()
    for key in ("au14", "ia5i"):
        item = by_key(body, env, key)
        assert item["proposal_status"] == "INVALID" and "PROPOSAL_SOURCE_MISMATCH" in item["publication"]["blockers"]


def test_proposal_runs_are_preserved_and_immutable(env, proposals):  # noqa: F811
    r = env.admin.post(f"{ADMIN}/frameworks/{FW}/mapping-proposals/runs", json={"tenant_id": "acme"}, headers=env.h())
    assert r.status_code == 201, r.text
    run_id = r.json()["run_id"]
    listing = env.admin.get(f"{ADMIN}/frameworks/{FW}/mapping-proposals/runs", headers=env.h()).json()
    assert [x["id"] for x in listing["items"]] == [run_id]
    run = env.admin.get(f"{ADMIN}/mapping-proposal-runs/{run_id}", headers=env.h()).json()["run"]
    stored = {i["requirement_id"]: i for i in run["proposal_result"]["items"]}
    assert stored[env.ids["ia5i"]]["rejection"]["rejected_rules"][0]["rule_id"] == "PAM-ROTATION-001"
    assert run["proposal_set_status"] == "PROPOSED_UNREVIEWED" and run["tenant_id"] == "acme"
    # another organization cannot read a scoped run
    assert env.admin.get(f"{ADMIN}/mapping-proposal-runs/{run_id}", headers=env.h(SCOPE_B)).status_code == 404
    assert env.admin.post(f"{ADMIN}/frameworks/{FW}/mapping-proposals/runs", json={},
                          headers=env.h(None, "reader")).status_code in (401, 403)
    with pytest.raises(sqlite3.DatabaseError):
        env.db.x("UPDATE mapping_proposal_run SET proposal_digest='x' WHERE id=?", (run_id,))
    with pytest.raises(sqlite3.DatabaseError):
        env.db.x("DELETE FROM mapping_proposal_run WHERE id=?", (run_id,))
    assert env.db.scalar("SELECT COUNT(*) FROM framework_control_mapping") == 0
