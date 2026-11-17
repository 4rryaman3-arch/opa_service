"""Policy auto-v2: operative text and addressee gate automated approval; mapping
signals come from the quoted text, only for rules the PAM bridge collects, with
structured per-requirement mapping gaps. Synthetic fixtures only."""
from __future__ import annotations

import pytest

from regintel import automation, mapping_policy as mp
from . import support as s
from .test_automation import EN_URL, approved_framework, build, pipeline_llm

RECITAL_QUOTE = "Operators should rotate the credentials of privileged accounts regularly to limit misuse."
STATE_QUOTE = "Member States shall ensure that operators record every privileged session."
SUBJECT_QUOTE = "A data subject should have the right of access to personal data concerning him or her."
ACT = f"""<html><body>
<h1>SYNTHETIC TEST FIXTURE - Synthetic Access Security Act (not a real regulation)</h1>
<p>Whereas: (1) {RECITAL_QUOTE}</p>
<p>(2) {SUBJECT_QUOTE}</p>
<p>HAVE ADOPTED THIS REGULATION:</p>
<h2>Article 1 Credentials</h2>
<p>{s.ROTATION_QUOTE}</p>
<h2>Article 2 Supervision</h2>
<p>{STATE_QUOTE}</p>
</body></html>"""


def act_llm() -> s.FakeLlm:
    base = pipeline_llm().script

    def script(system, prompt):
        if system == automation.SYSTEM_REVIEW or system != automation.extraction.SYSTEM_EXTRACT:
            return base(system, prompt)
        out = []
        for quote, domains, thr in ((RECITAL_QUOTE, ["credential_lifecycle"], []),
                                    (SUBJECT_QUOTE, ["access_control"], []),
                                    (s.ROTATION_QUOTE, ["credential_lifecycle"], ["90 days"]),
                                    (STATE_QUOTE, ["session_monitoring"], [])):
            if quote in prompt:
                out.append(s.candidate(quote, domains=domains, thresholds=thr))
        return {"requirements": out}
    return s.FakeLlm(script)


def req(text, *, obligation="MANDATORY", thresholds=(), translation=None):
    return {"id": 0, "section_id": None, "original_text": text, "translation_en": translation,
            "obligation_type": obligation, "thresholds": [{"value_text": t} for t in thresholds], "pam_domains": []}


def test_recitals_and_public_body_duties_are_never_auto_approved(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    approved_framework(db)
    llm = act_llm()
    result = build(db, tmp_path, llm=llm, pages={EN_URL: ACT})

    assert result["extraction"]["drafted"] == 4
    approved = [a["requirement_id"] for a in result["review"]["approved"]]
    texts = {r["id"]: r["original_text"] for r in db.q("SELECT id, original_text FROM regulatory_requirement")}
    assert [texts[i] for i in approved] == [s.ROTATION_QUOTE]
    codes = {texts[r["requirement_id"]]: [p["code"] for p in r["problems"]] for r in result["review"]["rejected"]}
    assert codes[RECITAL_QUOTE] == [mp.NON_OPERATIVE_TEXT]  # same section as the enacting formula, but before it
    assert mp.NON_OPERATIVE_TEXT in codes[SUBJECT_QUOTE] and mp.OUTSIDE_PAM_SCOPE in codes[SUBJECT_QUOTE]
    assert codes[STATE_QUOTE] == [mp.OUTSIDE_PAM_SCOPE]
    reviewed = [p for system, p in llm.calls if system == automation.SYSTEM_REVIEW]
    assert len(reviewed) == 1 and s.ROTATION_QUOTE in reviewed[0]  # deterministic gate costs no model call
    assert result["publication"]["requirement_ids"] == approved
    db.close()


def test_section_coverage_counts_operative_sections(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)
    approved_framework(db)
    result = build(db, tmp_path, llm=act_llm(), pages={EN_URL: ACT})
    [cov] = result["section_coverage"]
    assert cov["operative"] >= 2 and cov["operative_unprocessed"] == 0
    assert cov["operative"] + cov["non_operative"] == cov["sections"]
    db.close()


def test_position_rules():
    enacting = (3, 40)
    assert not mp.section_is_operative({"ordinal": 9, "section_ref": "#9 (preamble) [part 9]", "text": ""}, None)[0]
    assert not mp.section_is_operative({"ordinal": 2, "section_ref": "#2 page 2", "text": "x"}, enacting)[0]
    assert mp.section_is_operative({"ordinal": 4, "section_ref": "#4 page 4", "text": "x"}, enacting)[0]
    assert mp.section_is_operative({"ordinal": 1, "section_ref": "Article 1", "text": "x"}, None)[0]


@pytest.mark.parametrize("text, problem", [
    ("Member States should, in their national strategies, address the needs of small enterprises.", True),
    ("Where appropriate, competent authorities shall audit operators.", True),
    ("The Commission shall adopt implementing acts.", True),
    ("A data subject should have the right of access to personal data.", True),
    ("Operators shall rotate the credentials of privileged accounts.", False),
    ("implement policies that limit logical access to what is required for approved functions only", False),
])
def test_addressee(text, problem):
    assert (mp.addressee_problem(text) is not None) is problem


def test_list_point_addressee_comes_from_the_lead_in():
    regulator = ("Harmonisation of tools The supervisory authorities shall, in consultation with the agency, develop "
                 "draft standards in order to: (a) specify the access policy; (b) develop further components of the "
                 "controls of access rights.")
    entity = ("As part of the framework referred to in Article 6, operators shall: (a) develop policies; "
              "(b) develop further components of the controls of access rights.")
    point = "develop further components of the controls of access rights"
    assert "public body" in mp.lead_in_problem(regulator, point)
    assert mp.lead_in_problem(entity, point) is None


def test_mapping_gap_codes():
    bundle = {"PAM-ROTATION-001", "PAM-DORMANT-001", "PAM-SESSREC-001", "PAM-APPROVAL-001", "PAM-REVIEW-001"}

    def codes(r, mapped=()):
        return [(g["code"], g.get("rule_id")) for g in mp.mapping_gaps(None, r, mapped_rules=list(mapped),
                                                                      bundle_rules=bundle)]
    # rotation without a stated interval: never a rule default or company policy as a legal threshold
    assert codes(req("Operators shall change passwords of privileged accounts regularly.")) == \
        [(mp.POLICY_CONTEXT_REQUIRED, "PAM-ROTATION-001")]
    # access approval: the rule exists, the bridge does not collect its evidence
    assert codes(req("limit access to what is required for legitimate and approved functions")) == \
        [(mp.COLLECTOR_MISSING, "PAM-APPROVAL-001")]
    # strong authentication AND cryptography: neither is tested by any rule
    assert [c for c, _ in codes(req("strong authentication mechanisms and protection of cryptographic keys"))] == \
        [mp.NO_EXECUTABLE_RULE, mp.NO_EXECUTABLE_RULE]
    assert codes(req("Operators shall keep an inventory of assets.")) == [(mp.MAPPING_MISSING, None)]
    mapped = codes(req(s.SESSION_QUOTE), mapped=["PAM-SESSREC-001"])
    assert mapped == [(mp.PARTIAL_COVERAGE, "PAM-SESSREC-001")]


def test_mapping_recipes_ignore_model_domains(tmp_path, monkeypatch):
    from app.engine.catalog import Catalog
    from regintel import mapping_recipes as mr
    from ..conftest import BUNDLE

    engine = Catalog.load(BUNDLE)
    db = s.make_db(tmp_path)
    located = {"status": "NO_CONTROL_HEADING_BEFORE_PASSAGE", "canonical_id": None}

    def decide(r):
        return mr.resolve(db, r, located, engine, mp.bridge_collected_rules())

    base = {**req(s.ROTATION_QUOTE, thresholds=["90 days"]), "pam_domains": []}
    got = decide(base)  # no domain needed: the text decides
    assert (got["decision"], got["rule_id"], got["parameters"]) == ("PROPOSED", "PAM-ROTATION-001",
                                                                    {"max_rotation_age_days": 90})
    assert got["rule_version"] == "1.1"  # the single ACTIVE version, never the retired 1.0
    assert got["parameter_provenance"] == [{"name": "max_rotation_age_days", "value": 90, "provenance": "SOURCE_TEXT",
                                            "source_text": "90 days"}]
    wrong = {**req("Operators shall keep records of their privileged staff training."),
             "pam_domains": ["session_monitoring"]}
    assert decide(wrong)["decision"] == "NOT_MAPPED"  # a domain label alone never maps
    assert decide(req(s.SESSION_QUOTE, obligation="RECOMMENDED"))["code"] == mr.NOT_MANDATORY
    rec = decide(req(s.SESSION_QUOTE))
    assert rec["parameters"] == {"accept_partial_recordings": False} and "every privileged session" in \
        rec["parameter_provenance"][0]["source_text"]
    # recording without "all/every/each": the strict setting is not stated, so no mapping
    loose = decide(req("Operators shall record privileged sessions where feasible."))
    assert loose["code"] == mr.PARAMETER_NOT_SOURCE_GROUNDED
    access = req("Privileged access to systems and their resources are disabled after 45 days of inactivity.",
                 thresholds=["45 days"])
    assert decide(access)["parameters"] == {"dormant_after_days": 45}
    unprivileged = req("Unprivileged access to systems is disabled after 45 days of inactivity.", thresholds=["45 days"])
    assert decide(unprivileged)["decision"] == "NOT_MAPPED"  # the rule tests privileged accounts only
    both = req("Operators shall rotate the credentials of privileged accounts every 90 days and disable privileged "
               "accounts after 45 days of inactivity.")
    assert decide(both)["code"] == mr.AMBIGUOUS_REQUIREMENT
    two_values = req("Operators shall rotate privileged credentials every 90 days, or every 30 days for root.")
    assert decide(two_values)["code"] == mr.PARAMETER_NOT_SOURCE_GROUNDED
    cut = req("Operators shall rotate privileged credentials every [Assignment: organization-defined")
    assert decide(cut)["code"] == mr.PARTIALLY_PARSED
    licence = req("This publication is available free of charge and privileged credentials examples are not "
                  "subject to copyright.")
    assert decide(licence)["code"] == mp.NON_OPERATIVE_TEXT
    monkeypatch.setenv("OPM_REGINTEL_BRIDGE_COLLECTED_RULES", "PAM-DORMANT-001")
    assert decide(base)["code"] == mp.COLLECTOR_MISSING  # rotation evidence not collected -> not mapped
    db.close()
