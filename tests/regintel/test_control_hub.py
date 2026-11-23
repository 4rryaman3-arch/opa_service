"""Hub controls, OSCAL catalog import and PDF glyph repair (design D: vetted catalog controls first).

SYNTHETIC FIXTURES ONLY: the OSCAL catalog and the glyph texts below are invented test text in the published
layouts; control identifiers are used only as identifiers. No real standard text is reproduced."""
from __future__ import annotations

import json

import pytest

from app.engine.store import RuleStore
from regintel import control_hub as hub, control_ids as ci, generated_rules as gr, textproc as tp
from .test_rule_generation import by_req, gen  # noqa: F401  (fixture)
from .test_rewrite_contract import env  # noqa: F401  (fixture)


def derived(cid, clause=None, location="CONTROL_STATEMENT"):
    return {"status": "DERIVED", "canonical_id": cid, "control_id": cid.split("(")[0], "clause": clause,
            "location": location}


# ------------------------------------------------------------------------------------------- hub gate

def test_hub_allows_only_matrix_controls_and_their_evidence():
    assert hub.scope_gap(derived("AC-2", "e")) is None
    assert "privileged_access_request" in hub.evidence_types(derived("AC-2", "e"))
    assert hub.scope_gap(derived("IA-2(1)")) is None  # listed through an alias
    # an enhancement is not covered by its base control; unlisted controls get no PAM rule
    for ref in (derived("AC-3(3)"), derived("PE-4"), derived("SA-5", "a"), derived("PL-4", "b")):
        assert "is not a hub control" in hub.scope_gap(ref), ref
    assert "discussion text" in hub.scope_gap(derived("AC-2", "i", location="DISCUSSION"))
    front = {"status": "NO_CONTROL_HEADING_BEFORE_PASSAGE", "canonical_id": None, "control_headings_in_version": 300}
    assert "before the first control heading" in hub.scope_gap(front)


def test_documents_without_control_headings_are_not_governed_by_the_hub():
    for ref in ({"status": "NO_CONTROL_HEADING_BEFORE_PASSAGE", "canonical_id": None, "control_headings_in_version": 0},
                {"status": "QUOTE_NOT_LOCATED", "canonical_id": None}, {}, None):
        assert hub.scope_gap(ref) is None and not hub.governed(ref)
        assert hub.mapping_gap(ref, "access_authorization") is None


def test_a_hub_rule_on_other_evidence_is_withdrawn():
    assert hub.mapping_gap(derived("AC-2", "i"), "access_authorization") is None
    assert "covered by credential_rotation" in hub.mapping_gap(derived("IA-5"), "access_authorization")


def test_off_hub_passage_never_reaches_the_model():
    class NoModel:
        def __getattr__(self, name):
            raise AssertionError("the model must not be called")

    raw, proposal, gap, called, analysis = gr._proposal_for(
        None, NoModel(), {"id": 1}, derived("PE-4"), {}, scope="s", proposal_key="k")  # type: ignore[arg-type]
    assert (raw, proposal, called, analysis) == (None, None, False, None)
    assert gap["gap_code"] == "OUTSIDE_PAM_SCOPE" and gap["hub"] == hub.HUB_VERSION


def test_a_job_withdraws_its_generated_rule_once_the_hub_rejects_the_passage(gen, monkeypatch):  # noqa: F811
    env, ids, run, _submit, _model, _digest, store_path = gen
    first = by_req(run("hub-run-1"))[ids["ticket"]]
    assert first["outcome"] == gr.GENERATED_RULE_ACTIVATED, first
    rule_id, mapping_id = first["rule_id"], first["mapping_id"]

    ticket = env.db.one("SELECT original_text FROM regulatory_requirement WHERE id=?", (ids["ticket"],))
    monkeypatch.setattr(hub, "scope_gap", lambda ref, _real=hub.scope_gap: (
        "control-hub-v1: test - not a hub control") if ref is not None and ref.get("_ticket") else _real(ref))
    real_annotate = ci.annotate

    def annotate(db, reqs, **kw):
        out = real_annotate(db, reqs, **kw)
        for r in reqs:
            if r.get("original_text") == ticket["original_text"]:
                out[r["id"]] = {**out[r["id"]], "_ticket": True}
        return out

    monkeypatch.setattr(ci, "annotate", annotate)
    second = by_req(run("hub-run-2"))[ids["ticket"]]
    assert second["gap_code"] == "OUTSIDE_PAM_SCOPE" and second["withdrawn_mapping_ids"] == [mapping_id], second
    assert env.db.scalar("SELECT status FROM framework_control_mapping WHERE id=?", (mapping_id,)) == "WITHDRAWN"
    assert env.db.scalar("SELECT status FROM generated_rule_version WHERE rule_id=?", (rule_id,)) == "FAILED"
    store = RuleStore(store_path)
    try:
        assert store.get_custom("acme", rule_id, "1.0")["status"] == "INACTIVE"
    finally:
        store.close()


# ------------------------------------------------------------------------------------------- PDF glyphs

def test_ligature_glyphs_are_repaired_from_the_documents_own_vocabulary():
    pages = ["Identify each organization and its configuration. Software settings.",
             "Idenfy the organizaon conﬁguraon. Soware Sengs. Qzxq stays."]
    out = tp.repair_glyphs(pages)
    assert out[1] == "Identify the organization configuration. Software Settings. Qzxq stays."
    assert tp.repair_glyphs(["plain text only"]) == ["plain text only"]


def test_a_glyph_read_the_same_way_everywhere_fills_words_the_document_never_spells_plainly():
    known = " ".join(["action"] * 3)
    pages = [known, " ".join(["acon"] * 25) + " execuve"]
    assert tp.repair_glyphs(pages)[1].endswith("executive")


# ------------------------------------------------------------------------------------------- OSCAL import

def _param(pid, label):
    return {"id": pid, "label": label}


OSCAL = {"catalog": {"uuid": "00000000-0000-4000-8000-000000000000", "metadata": {"title": "SYNTHETIC TEST CATALOG"},
                     "groups": [{"id": "ac", "title": "Access Control", "controls": [
    {"id": "ac-2", "title": "Account Management", "props": [{"name": "label", "value": "AC-2"},
                                                            {"name": "label", "class": "zero-padded", "value": "AC-02"}],
     "params": [_param("ac-02_odp.01", "personnel or roles")],
     "parts": [{"name": "statement", "parts": [
         {"name": "item", "props": [{"name": "label", "value": "a."}], "prose": "Define the synthetic account types;"},
         {"name": "item", "props": [{"name": "label", "value": "e."}],
          "prose": "Require approvals by {{ insert: param, ac-02_odp.01 }} for synthetic requests."}]},
               {"name": "guidance", "prose": "Synthetic discussion that is not a requirement."}],
     "controls": [{"id": "ac-2.3", "title": "Disable Accounts",
                   "props": [{"name": "label", "value": "AC-2(3)"}],
                   "params": [{"id": "ac-02.03_odp", "select": {"how-many": "one-or-more",
                                                                "choice": ["expire", "disable"]}}],
                   "parts": [{"name": "statement", "prose": "Synthetic: {{ insert: param, ac-02.03_odp }} accounts."}]},
                  {"id": "ac-2.99", "title": "Gone", "props": [{"name": "label", "value": "AC-2(99)"},
                                                               {"name": "status", "value": "withdrawn"}]}]},
]}]}}


def test_oscal_catalog_is_rendered_in_the_official_layout_and_control_ids_are_derived():
    parsed = tp.parse_document(json.dumps(OSCAL).encode(), "json")
    assert parsed.complete and len(parsed.sections) == 1
    s = parsed.sections[0]
    assert s.section_ref == "#1 AC-2 ACCOUNT MANAGEMENT"
    assert "Require approvals by [Assignment: organization-defined personnel or roles]" in s.text
    assert "[Selection (one or more): expire; disable]" in s.text
    assert "Synthetic discussion" not in s.text and "GONE" not in s.text
    text = ci._norm(s.text)
    base = [(m.group(1), m.group(2), m.group(3)) for m in ci._BASE.finditer(text)]
    assert base == [("AC", "2", "ACCOUNT MANAGEMENT")]
    enh = [(m.group(1), m.group(3)) for m in ci._ENH.finditer(text)]
    assert enh == [("3", "DISABLE ACCOUNTS")]


@pytest.mark.parametrize("content", [b"{}", b"not json", json.dumps({"catalog": {"groups": []}}).encode()])
def test_json_that_is_not_an_oscal_catalog_is_not_parsed(content):
    parsed = tp.parse_document(content, "json")
    assert not parsed.complete and not parsed.sections and parsed.incomplete_reason
