"""Source-grounded mapping proposals (one reviewed-or-not proposal set per framework).

A proposal set (``regintel/data/mapping_proposals/<framework>.json``) records, per published
requirement, either a CANDIDATE rule (rule/version, parameters and their provenance, evidence
type and schema, technical coverage, residual limitations) or a structured REJECTED reason.
This module validates every proposal against the stored source text, the derived canonical
control reference, the loaded policy bundle, the policy-control catalog and the caller's
collector handshake. It never creates, approves or publishes a mapping.

Publication eligibility (regulatory AUTOMATED mapping) needs ALL of:
  * the proposal matches the requirement's exact text and canonical reference;
  * the rule version is ACTIVE in the running bundle with the stated evidence type;
  * every rule parameter has provenance SOURCE_TEXT with a value stated in the passage;
  * the passage has no organization-defined inputs;
  * the evidence is collected (handshake);
  * the proposal set has been reviewed (status REVIEWED); review and publication then go
    through the normal draft -> review -> publish workflow.
Anything else is reported with its blockers; a CUSTOMER_POLICY route is named where a
policy control can resolve a POLICY_CONTEXT_REQUIRED gap.
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from . import mapping_policy as mp, policy_controls as pc
from .db import CatalogDb, digest_of

DATA = Path(__file__).with_name("data") / "mapping_proposals"
PROVENANCE = ("SOURCE_TEXT", "ORGANIZATION_DEFINED", "NOT_IN_SOURCE")
REJECTION_CODES = (mp.MAPPING_MISSING, mp.COLLECTOR_MISSING, mp.NO_EXECUTABLE_RULE, mp.POLICY_CONTEXT_REQUIRED,
                   mp.OUTSIDE_PAM_SCOPE, mp.PARTIAL_COVERAGE)
DETAIL_CODES = ("PROCEDURAL_OBLIGATION", "NO_RULE_FOR_BEHAVIOUR", "LOOKALIKE_RULE_REJECTED", "PRODUCT_CAPABILITY",
                "PARTIAL_COVERAGE", "MOBILE_DEVICE_MANAGEMENT", "DATA_STORE_AUDITING", "REGISTRATION_PROCESS")
BLOCKERS = ("PROPOSAL_UNREVIEWED", "PROPOSAL_SOURCE_MISMATCH", "CANDIDATE_INVALID", "ORGANIZATION_DEFINED_INPUTS",
            "PARAMETER_NOT_IN_SOURCE", "COLLECTOR_MISSING", "REJECTED")


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip().replace("- ", "-")


_MARKER = re.compile(r"^(?:[a-z]\.|\([a-z0-9]{1,3}\))\s+")


def _unmarked(text: str) -> str:
    """Normalized text without a leading clause marker ("i. ", "(a) "), which extraction may or may
    not keep; the canonical clause itself is compared separately."""
    return _MARKER.sub("", _norm(text), count=1)


@lru_cache(maxsize=8)
def _load(framework_id: str) -> dict[str, Any] | None:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", framework_id):
        return None
    path = DATA / f"{framework_id}.json"
    if not path.is_file():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    problems = set_problems(data)
    if problems:
        raise ValueError(f"invalid proposal set {path.name}: {problems}")
    return data


def proposal_set(framework_id: str) -> dict[str, Any] | None:
    return _load(framework_id)


def set_problems(data: dict[str, Any]) -> list[str]:
    """Static checks of a proposal set file (codes, provenance, one proposal per requirement)."""
    out: list[str] = []
    seen: set[int] = set()
    for p in data.get("proposals", []):
        rid = p.get("requirement_id")
        if rid in seen:
            out.append(f"{rid}: duplicate proposal")
        seen.add(rid)
        if p.get("classification") not in ("CANDIDATE", "REJECTED"):
            out.append(f"{rid}: classification")
        if p.get("proposed_code") not in REJECTION_CODES:
            out.append(f"{rid}: proposed_code {p.get('proposed_code')}")
        if p.get("detail_code") not in DETAIL_CODES:
            out.append(f"{rid}: detail_code {p.get('detail_code')}")
        if not p.get("quote_prefix") or not p.get("canonical_id"):
            out.append(f"{rid}: source grounding (quote_prefix, canonical_id) missing")
        cand = p.get("candidate")
        if (p.get("classification") == "CANDIDATE") != bool(cand):
            out.append(f"{rid}: a CANDIDATE needs exactly one candidate")
        for prm in (cand or {}).get("parameters", []):
            if prm.get("provenance") not in PROVENANCE:
                out.append(f"{rid}: parameter {prm.get('name')} provenance")
            if prm.get("provenance") == "SOURCE_TEXT" and "value" not in prm:
                out.append(f"{rid}: SOURCE_TEXT parameter {prm.get('name')} needs a value")
    return out


def _candidate_problems(cand: dict[str, Any], engine: Any) -> list[str]:
    problems: list[str] = []
    spec = (getattr(engine, "rules", {}) or {}).get(cand["rule_id"], {}).get(cand["rule_version"])
    if spec is None:
        return [f"{cand['rule_id']} {cand['rule_version']} is not in the running policy bundle"]
    if spec.status != "ACTIVE":
        problems.append(f"{cand['rule_id']} {cand['rule_version']} is {spec.status}")
    if spec.evidence_type != cand["evidence_type"]:
        problems.append(f"evidence type is {spec.evidence_type}, not {cand['evidence_type']}")
    stated = {p["name"] for p in cand.get("parameters", [])}
    if stated != set(spec.parameters):
        problems.append(f"parameters must be exactly {sorted(spec.parameters)} (stated {sorted(stated)})")
    ctl = cand.get("policy_control_id")
    if ctl:
        pins = [c for (cid, _), c in pc.CONTROLS.items() if cid == ctl
                and any(b["rule_id"] == cand["rule_id"] and b["rule_version"] == cand["rule_version"]
                        for b in c["bindings"]) and cand["rule_id"] in c.get("addresses_gap_rules", [])]
        if not pins:
            problems.append(f"policy control {ctl} does not pin {cand['rule_id']} {cand['rule_version']}")
    return problems


def evaluate(db: CatalogDb, engine: Any, framework_id: str, items: list[dict[str, Any]],
             collected: tuple[str, ...] | list[str]) -> dict[str, Any]:
    """Validate the framework's proposal set against the published requirements in ``items``
    (output of ``automation.requirement_mapping_gaps``). Deterministic for the same inputs."""
    data = proposal_set(framework_id)
    by_req = {p["requirement_id"]: p for p in (data or {}).get("proposals", [])}
    reviewed = (data or {}).get("status") == "REVIEWED"
    out: list[dict[str, Any]] = []
    for it in items:
        rid = it["requirement_id"]
        row = db.one("SELECT original_text, translation_en, document_version_id, section_ref FROM regulatory_requirement "
                     "WHERE id=?", (rid,)) or {}
        text = _norm(row.get("translation_en") or row.get("original_text") or "")
        ref = it.get("canonical_reference") or {}
        citation = {"framework_id": framework_id, "requirement_id": rid, "document_version_id": row.get("document_version_id"),
                    "section_ref": row.get("section_ref"), "canonical_id": ref.get("canonical_id"),
                    "clause": ref.get("clause"), "location": ref.get("location"), "quote": text}
        engine_codes = [g["code"] for g in it["gaps"]]
        p = by_req.get(rid)
        if p is None:
            out.append({"requirement_id": rid, "citation": citation, "proposal_status": "NO_PROPOSAL",
                        "engine_gap_codes": engine_codes, "effective_code": engine_codes[0] if engine_codes else None,
                        "publication": {"eligible": False, "blockers": ["NO_PROPOSAL"], "route": None}})
            continue
        source_problems = []
        if p["canonical_id"] != ref.get("canonical_id") or (p.get("clause") or None) != (ref.get("clause") or None):
            source_problems.append(f"canonical reference is {ref.get('canonical_id')} {ref.get('clause') or ''}".strip())
        if not _unmarked(text).startswith(_unmarked(p["quote_prefix"])):
            source_problems.append("quote_prefix does not match the stored requirement text")
        entry: dict[str, Any] = {
            "requirement_id": rid, "citation": citation, "proposal_status": "INVALID" if source_problems else "VALID",
            "source_problems": source_problems, "classification": p["classification"],
            "proposed_code": p["proposed_code"], "detail_code": p["detail_code"], "rationale": p.get("rationale"),
            "engine_gap_codes": engine_codes, "rejected_rules": p.get("rejected_rules", []),
            "organization_defined": mp.organization_defined(text),
        }
        blockers: list[str] = [] if reviewed else ["PROPOSAL_UNREVIEWED"]
        if source_problems:
            blockers.append("PROPOSAL_SOURCE_MISMATCH")
        route = None
        cand = p.get("candidate")
        if cand:
            problems = _candidate_problems(cand, engine)
            live = next((g for g in it["gaps"] if g.get("rule_id") == cand["rule_id"]), None)
            live_code = live["code"] if live else None
            if cand["rule_id"] not in collected:
                live_code = mp.COLLECTOR_MISSING
            entry["candidate"] = {**cand, "validation_problems": problems, "collected": cand["rule_id"] in collected,
                                  "technical_coverage": cand["coverage"], "limitations": p.get("limitations")}
            entry["effective_code"] = live_code or p["proposed_code"]
            if problems:
                blockers.append("CANDIDATE_INVALID")
            if entry["organization_defined"] or cand.get("organization_defined_inputs"):
                blockers.append("ORGANIZATION_DEFINED_INPUTS")
            if any(x["provenance"] != "SOURCE_TEXT" for x in cand.get("parameters", [])):
                blockers.append("PARAMETER_NOT_IN_SOURCE")
            if cand["rule_id"] not in collected:
                blockers.append("COLLECTOR_MISSING")
            elif cand.get("policy_control_id") and not problems:
                route = {"provenance": "CUSTOMER_POLICY", "policy_control_id": cand["policy_control_id"],
                         "resolves": mp.POLICY_CONTEXT_REQUIRED, "result_at_best": "PARTIALLY_RESOLVED"}
            entry["residual_gaps"] = [mp.PARTIAL_COVERAGE] if cand["coverage"] == "PARTIAL" else []
        else:
            entry["rejection"] = {"code": p["proposed_code"], "detail_code": p["detail_code"],
                                  "reason": p.get("rationale"), "rejected_rules": p.get("rejected_rules", [])}
            entry["effective_code"] = p["proposed_code"]
            if "proposed_new_rule" in p:
                entry["proposed_new_rule"] = p["proposed_new_rule"]
            blockers.append("REJECTED")
        entry["publication"] = {"eligible": not blockers, "blockers": blockers, "route": route}
        out.append(entry)
    counts: dict[str, int] = {}
    for e in out:
        counts[e["effective_code"] or "NONE"] = counts.get(e["effective_code"] or "NONE", 0) + 1
    meta = {k: (data or {}).get(k) for k in ("proposal_set_id", "status", "prepared_by", "source", "statement")}
    body = {"framework_id": framework_id, "proposal_set": meta, "policy_bundle_version": getattr(engine, "bundle_version", None),
            "collected_rules": sorted(collected), "items": out,
            "counts": {"requirements": len(out), "candidates": sum(1 for e in out if e.get("candidate")),
                       "rejected": sum(1 for e in out if e.get("rejection")),
                       "eligible_for_publication": sum(1 for e in out if e["publication"]["eligible"]),
                       "by_effective_code": dict(sorted(counts.items()))},
            "blocker_codes": list(BLOCKERS) + ["NO_PROPOSAL"]}
    body["proposal_digest"] = digest_of(body)
    return body
