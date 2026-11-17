"""Automated requirements pipeline: one durable job from configured sources to
published requirements, with no human review action during normal processing.

This is an explicit engine capability, not a bypass of review:

  * It runs only for credentials holding the ``catalog:automate`` scope.
  * Every decision it makes is recorded with ``decision_origin='AUTOMATED'``,
    the engine actor, the automation policy version and - where a model review
    was involved - the persisted review attempt. Automated decisions are never
    presented as human review.
  * Candidates pass TWO gates: a second, independent model review of the
    candidate against its actual source section, and the same deterministic
    code checks the human review path enforces (verbatim grounding, source
    attribution, threshold support, duplicates, date consistency). A model
    verdict alone approves nothing.
  * It publishes only requirements the automated pipeline itself approved for
    the requested framework - never unrelated pending content.
  * The manual review endpoints and lifecycle are unchanged and keep working.

Policy ``auto-v1`` (``POLICY_VERSION``):

  * Framework approval is an input, not automated: the framework must already
    be review-approved.
  * Source eligibility for automated verification: the adapter fetches over
    the network (``file_drop`` is excluded - file provenance cannot be
    machine-verified) and every domain on the source's fetch allowlist is a
    registered official domain of its authority, or a subdomain of one. The
    fetcher independently enforces HTTPS + that allowlist on every hop.
  * Document eligibility for automated completeness review: the retrieved
    version parsed as complete with at least one section. Incomplete versions
    become explicit blockers for the existing human resolution path.
"""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import catalog, control_ids, coverage, extraction
from . import mapping_policy, mapping_recipes
from . import plan as planning
from .db import CatalogDb, CatalogError, canonical, now_iso
from .llm import LocalLlm
from .screening import SCREENING_MODES, SCREENING_VERSION
from .screening import screen_for_source
from .sources.registry import is_verified, sync_source, verify_source

AUTOMATION_SCOPE = "catalog:automate"
# auto-v2: operative-text and addressee checks before approval; mapping signals from the quoted text only,
# restricted to bridge-collected rules, with structured per-requirement mapping gaps
# auto-v3: deterministic mapping recipes (regintel.mapping_recipes, incl. NIST SP 800-53 canonical controls):
# exactly one ACTIVE rule version, every parameter stated in the passage, collected evidence, no conflicting
# mapping, licensing/provenance statements and partially parsed passages excluded, full decision record
POLICY_VERSION = "auto-v3"


def pipeline_options(languages: list[str] | None, screening: str | None) -> tuple[list[str] | None, str]:
    """Resolve per-job options, falling back to the operator settings in the environment
    (``OPM_REGINTEL_AUTOMATION_LANGUAGES=en,de``; ``OPM_REGINTEL_AUTOMATION_SCREENING=pam-keyword-screen-v1``)."""
    import os
    if languages is None:
        configured = os.environ.get("OPM_REGINTEL_AUTOMATION_LANGUAGES", "").strip()
        languages = [c.strip().lower() for c in configured.split(",") if c.strip()] or None
    if screening is None:
        screening = os.environ.get("OPM_REGINTEL_AUTOMATION_SCREENING", "").strip() or "none"
    if screening not in SCREENING_MODES:
        raise CatalogError("INVALID_SCREENING", f"screening must be one of {list(SCREENING_MODES)}")
    return languages, screening
REVIEW_PROMPT_VERSION = "review-v1"
TRANSLATION_REVIEW_PROMPT_VERSION = "translation-review-v1"

STATEMENT = (
    "Decisions marked decision_origin=AUTOMATED were made by the engine's automation policy "
    f"({POLICY_VERSION}): a model review plus deterministic code checks. They are not human review, and no "
    "person reviewed the original-language text. Publication makes requirements readable; template readiness "
    "still requires reviewed, published rule mappings."
)

SYSTEM_REVIEW = (
    "You are a second, independent reviewer of ONE proposed regulatory requirement extracted from a section of an "
    "official text. You receive the section text and the proposal. Check strictly:\n"
    "quote_supported: the quoted passage appears in the section and itself concerns user or administrator access, "
    "accounts, identities, credentials/passwords/keys, authentication, privileged sessions, access logging or "
    "monitoring, access reviews, emergency access, or segregation of duties.\n"
    "obligation_type_correct: the stated obligation type matches the binding force of the passage's own wording "
    "(shall/must-type = MANDATORY, should-type = RECOMMENDED, may-type = PERMISSIVE).\n"
    "thresholds_grounded: every reported threshold value appears literally inside the quoted passage.\n"
    "domains_relevant: the stated PAM domains are subjects the passage itself mentions.\n"
    "Answer verdict APPROVE only when every check passes. When in doubt, REJECT: a wrong rejection can be corrected "
    "by a human reviewer, a wrong approval cannot. Give short factual reasons."
)
SYSTEM_TRANSLATION_REVIEW = (
    "You review an English working translation of a regulatory passage against its original. Check that the "
    "translation is faithful and complete: same obligations, same scope, every number, date, duration and defined "
    "term preserved exactly, nothing added, omitted or interpreted. Answer verdict APPROVE only when all of that "
    "holds; otherwise REJECT. When in doubt, REJECT. Give short factual reasons."
)


class _Checks(BaseModel):
    model_config = ConfigDict(extra="forbid")
    quote_supported: bool
    obligation_type_correct: bool
    thresholds_grounded: bool
    domains_relevant: bool


class _Review(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["APPROVE", "REJECT"]
    reasons: list[str] = Field(default_factory=list, max_length=10)
    checks: _Checks


class _TranslationReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    verdict: Literal["APPROVE", "REJECT"]
    reasons: list[str] = Field(default_factory=list, max_length=10)


REVIEW_SCHEMA = _Review.model_json_schema()
TRANSLATION_REVIEW_SCHEMA = _TranslationReview.model_json_schema()


def engine_actor(key_id: str) -> str:
    """Service identity that signs automated decisions: distinguishable from
    both human key ids and model identities (llm:*)."""
    return f"engine:{key_id}"


# ------------------------------------------------------------------ policy checks


def _domain_within(host: str, official: set[str]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in (o.lower().rstrip(".") for o in official))


def source_eligibility(db: CatalogDb, source: dict[str, Any]) -> tuple[bool, str]:
    """Policy auto-v1: can this PROPOSED source be verified automatically?"""
    if source["adapter_type"] == "file_drop":
        return False, ("file_drop provenance (that uploaded files came from an authorized repository) "
                       "cannot be machine-verified; a human must verify this source")
    authority = db.one("SELECT * FROM regulatory_authority WHERE id=?", (source["authority_id"],))
    official = set((authority or {}).get("official_domains") or [])
    if not official:
        return False, f"authority '{source['authority_id']}' has no registered official domains"
    allowed = list((source["config"] or {}).get("allowed_domains") or [])
    if not allowed:
        return False, "the source declares no fetch domains"
    outside = sorted(d for d in allowed if not _domain_within(d, official))
    if outside:
        return False, (f"fetch domains {outside} are not registered official domains of "
                       f"authority '{source['authority_id']}'")
    return True, (f"every fetch domain ({sorted(allowed)}) is a registered official domain of authority "
                  f"'{source['authority_id']}' or a subdomain of one; the fetcher additionally enforces HTTPS and "
                  "this allowlist on every request. Machine check of domain restriction, not a human attestation.")


_NUMBER = re.compile(r"\d+(?:[.,]\d+)*")


def _translation_numbers_ok(original: str, translation: str) -> list[str]:
    """Deterministic check: every number in the translation must exist in the
    original (a translation must not introduce values). Returns the offenders."""
    def tokens(text: str) -> set[str]:
        return {m.group().replace(",", "").replace(".", "") for m in _NUMBER.finditer(text)}
    return sorted(tokens(translation) - tokens(original))


def _code_checks(db: CatalogDb, req: dict[str, Any]) -> list[dict[str, str]]:
    """Deterministic rejections beyond what catalog._check_requirement enforces."""
    problems: list[dict[str, str]] = []
    dup = db.one(
        "SELECT id FROM regulatory_requirement WHERE framework_id=? AND id<>? AND status IN ('APPROVED','SUPERSEDED') "
        "AND original_text=?", (req["framework_id"], req["id"], req["original_text"]))
    if dup:
        problems.append({"code": "DUPLICATE_REQUIREMENT",
                         "message": f"an approved requirement ({dup['id']}) already records this exact passage"})
    if req["effective_from"] and req["effective_to"] and req["effective_from"] > req["effective_to"]:
        problems.append({"code": "INCONSISTENT_DATES",
                         "message": f"effective_from {req['effective_from']} is after effective_to {req['effective_to']}"})
    return problems


# ------------------------------------------------------------------ pipeline


def _action(action: str, method: str, path: str, scope: str, description: str, ids: list[Any]) -> dict[str, Any]:
    return {"action": action, "method": method, "path": path, "required_scope": scope,
            "description": description, "count": len(ids), "ids": ids[:100], "truncated": len(ids) > 100}


def _review_candidate(db: CatalogDb, llm: LocalLlm, req: dict[str, Any], section_text: str,
                      job_id: str | None) -> tuple[int, _Review | None, list[str]]:
    """Second-pass model review of one draft. Returns (attempt_id, review, problems)."""
    proposal = canonical({"quote": req["original_text"], "obligation_type": req["obligation_type"],
                          "pam_domains": req["pam_domains"], "thresholds": req["thresholds"]})
    started = now_iso()
    output = extraction._model_output(
        llm, SYSTEM_REVIEW,
        f"Document language: {req['original_language']}\n\nSECTION:\n{section_text}\n\nPROPOSAL:\n{proposal}",
        REVIEW_SCHEMA)
    review: _Review | None = None
    problems: list[str] = []
    validation_errors: list[dict[str, Any]] = []
    if output["error"] is not None:
        status, problems = "LLM_ERROR", [f"model review failed: {output['error']}"]
    elif output["parsed"] is None:
        status, problems = "MALFORMED_OUTPUT", [f"model review output was not JSON: {output['parse_error']}"]
    else:
        try:
            review = _Review.model_validate(output["parsed"])
            status = "SUCCEEDED"
        except ValidationError as exc:
            status = "VALIDATION_FAILED"
            validation_errors = [{"path": ".".join(str(p) for p in e["loc"]) or "$", "message": e["msg"][:200],
                                  "code": "SCHEMA"} for e in exc.errors(include_input=False)]
            problems = ["model review output did not match the review schema"]
    attempt_id = extraction._record_attempt(
        db, version_id=req["document_version_id"], section_id=req["section_id"], kind="REVIEW",
        requirement_id=req["id"], llm=llm, prompt_version=REVIEW_PROMPT_VERSION, started_at=started,
        status=status, output=output, validated=review.model_dump() if review else None,
        validation_errors=validation_errors, job_id=job_id)
    return attempt_id, review, problems


def _review_translation(db: CatalogDb, llm: LocalLlm, req: dict[str, Any],
                        job_id: str | None) -> tuple[int, bool, list[str]]:
    """Model + code review of the working translation. Returns (attempt_id, approved, problems)."""
    started = now_iso()
    output = extraction._model_output(
        llm, SYSTEM_TRANSLATION_REVIEW,
        f"Original language: {req['original_language']}\n\nORIGINAL:\n{req['original_text']}\n\n"
        f"TRANSLATION:\n{req['translation_en']}", TRANSLATION_REVIEW_SCHEMA)
    review: _TranslationReview | None = None
    problems: list[str] = []
    validation_errors: list[dict[str, Any]] = []
    if output["error"] is not None:
        status, problems = "LLM_ERROR", [f"translation review failed: {output['error']}"]
    elif output["parsed"] is None:
        status, problems = "MALFORMED_OUTPUT", [f"translation review output was not JSON: {output['parse_error']}"]
    else:
        try:
            review = _TranslationReview.model_validate(output["parsed"])
            status = "SUCCEEDED"
            if review.verdict != "APPROVE":
                problems = [f"translation review verdict REJECT: {'; '.join(review.reasons) or 'no reason given'}"]
        except ValidationError as exc:
            status = "VALIDATION_FAILED"
            validation_errors = [{"path": ".".join(str(p) for p in e["loc"]) or "$", "message": e["msg"][:200],
                                  "code": "SCHEMA"} for e in exc.errors(include_input=False)]
            problems = ["translation review output did not match the review schema"]
    invented = _translation_numbers_ok(req["original_text"], req["translation_en"] or "")
    if invented:
        problems.append(f"translation contains numbers not present in the original: {invented}")
    attempt_id = extraction._record_attempt(
        db, version_id=req["document_version_id"], section_id=req["section_id"], kind="TRANSLATION_REVIEW",
        requirement_id=req["id"], llm=llm, prompt_version=TRANSLATION_REVIEW_PROMPT_VERSION, started_at=started,
        status=status, output=output, validated=review.model_dump() if review else None,
        validation_errors=validation_errors, job_id=job_id)
    return attempt_id, not problems, problems


# ------------------------------------------------------------------ mapping preparation

def mapping_decision(db: CatalogDb, engine: Any, req: dict[str, Any], *,
                     collected: tuple[str, ...] | list[str] | None = None,
                     _cache: dict[int, Any] | None = None, _indexes: dict[int, Any] | None = None) -> dict[str, Any]:
    """The deterministic recipe decision (mapping_recipes.resolve) for one requirement."""
    ref = control_ids.annotate(db, [req], _cache=_indexes if _indexes is not None else {})[req["id"]] \
        if req.get("section_id") else {"status": "NO_SOURCE_SECTION"}
    return mapping_recipes.resolve(db, req, ref, engine,
                                   mapping_policy.bridge_collected_rules() if collected is None else collected,
                                   _cache=_cache)


def prepare_mappings(db: CatalogDb, engine: Any, requirement_ids: list[int], *, actor: str,
                     collected: tuple[str, ...] | list[str] | None = None) -> dict[str, Any]:
    """Draft and review (AUTOMATED) mappings for approved requirements whose deterministic recipe
    decision is PROPOSED (see ``mapping_recipes``); publication is the caller's step. Every other
    requirement gets a structured NOT_MAPPED decision and stays visible in ``mapping_gaps``.
    Idempotent: an identical live mapping is reported as existing, a different one is a conflict."""
    out: dict[str, Any] = {"prepared": [], "unmapped": [], "errors": [], "mapping_gaps": [], "decisions": [],
                           "policy_version": POLICY_VERSION, "recipe_set_version": mapping_recipes.RECIPE_SET_VERSION}
    me = engine_actor(actor)
    if engine is None:
        out["errors"].append("RULE_CATALOG_UNAVAILABLE: the policy bundle is not readable; no mappings were prepared")
        return out
    collected = mapping_policy.bridge_collected_rules() if collected is None else tuple(collected)
    out["recipes"] = mapping_recipes.recipe_catalog(engine, collected)
    cache: dict[int, Any] = {}
    indexes: dict[int, Any] = {}
    for rid in sorted(set(requirement_ids)):
        req = db.one("SELECT * FROM regulatory_requirement WHERE id=?", (rid,))
        if req is None or req["status"] != "APPROVED":
            continue
        d = mapping_decision(db, engine, req, collected=collected, _cache=cache, _indexes=indexes)
        public = {k: v for k, v in d.items() if k not in ("rationale", "limitations", "override_constraints")}
        if d["decision"] == "NOT_MAPPED":
            out["unmapped"].append(rid)
            out["decisions"].append(public)
            continue
        if d["decision"] == "EXISTING":
            row = db.one("SELECT status FROM framework_control_mapping WHERE id=?", (d["mapping_id"],))
            out["prepared"].append({"requirement_id": rid, "mapping_id": d["mapping_id"], "rule_id": d["rule_id"],
                                    "existing": True, "status": row["status"]})
            out["decisions"].append(public)
            continue
        try:
            mid = catalog.create_mapping(
                db, requirement_id=rid, assessment="AUTOMATED", rule_id=d["rule_id"],
                rule_version_min=d["rule_version"], rule_version_max=d["rule_version"], coverage=d["coverage"],
                parameters=d["parameters"], override_constraints=d["override_constraints"],
                evidence_type=d["evidence_type"], rationale=d["rationale"], limitations=d["limitations"],
                actor=me, engine_rules=engine.rules)
        except CatalogError as exc:
            out["errors"].append(f"requirement {rid}: {exc.code}: {exc.message}")
            out["unmapped"].append(rid)
            out["decisions"].append({**public, "decision": "NOT_MAPPED", "code": mapping_recipes.VALIDATION_FAILED,
                                     "message": f"{exc.code}: {exc.message}"})
            continue
        record = {"automated": True, "policy_version": POLICY_VERSION,
                  "recipe_set_version": mapping_recipes.RECIPE_SET_VERSION, "recipe_id": d["recipe_id"],
                  "source_requirement": {"requirement_id": rid, "framework_id": req["framework_id"],
                                         "section_ref": req["section_ref"],
                                         "document_version_id": req["document_version_id"],
                                         "canonical_id": (d["canonical_reference"] or {}).get("canonical_id"),
                                         "clause": (d["canonical_reference"] or {}).get("clause")},
                  "rule_id": d["rule_id"], "rule_version": d["rule_version"], "evidence_type": d["evidence_type"],
                  "parameters": d["parameters"], "parameter_provenance": d["parameter_provenance"],
                  "coverage": d["coverage"], "limitations": d["limitations"]}
        try:
            catalog.review(db, "mapping", mid, reviewer=me, decision="APPROVED",
                           comment=f"AUTOMATED mapping approval ({POLICY_VERSION}, recipe {d['recipe_id']}): exactly one "
                                   "rule version resolved, every parameter stated in the passage, evidence collected, "
                                   "no conflicting mapping, coverage/rationale/limitations validated.",
                           attestations=record, origin="AUTOMATED", policy_version=POLICY_VERSION)
        except CatalogError as exc:
            out["errors"].append(f"mapping {mid}: {exc.code}: {exc.message}")
            continue
        out["prepared"].append({"requirement_id": rid, "mapping_id": mid, "rule_id": d["rule_id"],
                                "rule_version": d["rule_version"], "recipe_id": d["recipe_id"],
                                "parameters": d["parameters"], "parameter_provenance": d["parameter_provenance"],
                                "coverage": d["coverage"], "decision_origin": "AUTOMATED",
                                "policy_version": POLICY_VERSION})
        out["decisions"].append({**public, "mapping_id": mid})
    out["mapping_gaps"] = requirement_mapping_gaps(db, engine, requirement_ids, collected=collected, _cache=cache)
    return out


def section_coverage(db: CatalogDb, version_id: int) -> dict[str, Any]:
    """Which operative sections of a version were actually extracted (completed attempt,
    current prompt). Recitals are counted separately; they impose no duties."""
    enacting = mapping_policy.enacting_position(db, version_id)
    out: dict[str, Any] = {"version_id": version_id, "sections": 0, "non_operative": 0, "operative": 0,
                           "operative_extracted": 0, "operative_unprocessed": 0, "unprocessed_refs": []}
    for s in db.q("SELECT * FROM document_section WHERE version_id=? ORDER BY ordinal", (version_id,)):
        out["sections"] += 1
        if not mapping_policy.section_is_operative(s, enacting)[0]:
            out["non_operative"] += 1
            continue
        out["operative"] += 1
        if extraction.section_already_extracted(db, version_id, s["id"]):
            out["operative_extracted"] += 1
        else:
            out["operative_unprocessed"] += 1
            if len(out["unprocessed_refs"]) < 200:
                out["unprocessed_refs"].append(s["section_ref"])
    out["unprocessed_refs_truncated"] = out["operative_unprocessed"] > len(out["unprocessed_refs"])
    return out


def requirement_mapping_gaps(db: CatalogDb, engine: Any, requirement_ids: list[int], *,
                             collected: tuple[str, ...] | None = None,
                             _cache: dict[int, Any] | None = None, scope: str | None = None) -> list[dict[str, Any]]:
    """Per requirement: approved executable mappings and the structured reasons
    (``mapping_policy.GAP_CODES``) for whatever is not covered."""
    cache = {} if _cache is None else _cache
    bundle = set(engine.rules) if engine is not None else set()
    out = []
    indexes: dict[int, Any] = {}
    for rid in sorted(set(requirement_ids)):
        req = db.one("SELECT * FROM regulatory_requirement WHERE id=?", (rid,))
        if req is None or req["status"] != "APPROVED":
            continue
        canonical = control_ids.annotate(db, [req], _cache=indexes)[rid]
        mapped = sorted({r["rule_id"] for r in db.q(
            "SELECT d.rule_id FROM framework_control_mapping m JOIN opa_rule_definition d ON d.pam_control_id="
            "m.pam_control_id WHERE m.requirement_id=? AND m.status='APPROVED' AND " + mapping_recipes.VISIBLE,
            (rid, req["organization_scope"], scope))})
        gaps = mapping_policy.mapping_gaps(db, req, mapped_rules=mapped, bundle_rules=bundle, collected=collected,
                                           _cache=cache)
        item = {"requirement_id": rid, "framework_id": req["framework_id"], "section_ref": req["section_ref"],
                "canonical_reference": canonical, "executable_rules": mapped, "gaps": gaps,
                "status": "PARTIAL_COVERAGE" if mapped else "UNMAPPED"}
        if engine is not None:  # why automation did / did not bind a rule (mapping_recipes decision)
            d = mapping_recipes.resolve(db, req, canonical, engine,
                                        mapping_policy.bridge_collected_rules() if collected is None else collected,
                                        _cache=cache, scope=scope)
            item["auto_mapping"] = {k: d.get(k) for k in ("decision", "code", "message", "recipe_id", "rule_id",
                                                           "rule_version", "mapping_id") if d.get(k) is not None}
        from . import llm_mapping
        llm = llm_mapping.latest_decision(db, rid, scope)
        if llm is not None:  # the LLM-assisted decision for this organization (llm_mapping)
            item["llm_mapping"] = llm
        out.append(item)
    return out


def build_framework(db: CatalogDb, *, actor: str, framework_id: str, llm: LocalLlm, blob_dir: Any,
                    engine: Any = None, version_ids: list[int] | None = None, translate: bool = True,
                    as_of: str | None = None, job_id: str | None = None, transport: Any = None,
                    progress: Any = None, org_scope: str | None = None, languages: list[str] | None = None,
                    screening: str | None = None) -> dict[str, Any]:
    """Run the automated pipeline for one framework. Every stage is idempotent:
    re-running drafts no duplicate requirements, records no duplicate decisions
    and never repeats a publication; sections with a completed extraction
    attempt are not sent to the model again.

    ``languages`` limits the document versions processed (e.g. ``["en"]``) and
    ``screening`` (``pam-keyword-screen-v1``) sends only PAM-relevant sections to
    the model. Unset values fall back to the operator settings
    ``OPM_REGINTEL_AUTOMATION_LANGUAGES`` / ``OPM_REGINTEL_AUTOMATION_SCREENING``."""
    me = engine_actor(actor)
    when = planning.parse_date(None) if as_of is None else str(as_of)
    languages, screening = pipeline_options(languages, screening)

    def report(stage: str, **info: Any) -> None:
        if progress is not None:
            progress(stage, **info)

    fw = db.one("SELECT * FROM regulatory_framework WHERE id=?", (framework_id,))
    if fw is None:
        raise CatalogError("UNKNOWN_FRAMEWORK", f"framework '{framework_id}' is not registered")
    result: dict[str, Any] = {
        "framework_id": framework_id, "policy_version": POLICY_VERSION, "actor": me, "as_of": when,
        "stages": [], "blockers": [], "next_actions": [], "warnings": [], "llm_errors": 0,
        "child_job_ids": [],  # stages run inline on the single worker; there are no child jobs
        "options": {"languages": languages, "screening": screening},
        "statement": STATEMENT,
    }

    def stage_done(name: str, **info: Any) -> None:
        result["stages"].append({"stage": name, **info})
        report(name, **info)

    fw_review = planning.review_status(db, fw)
    if fw_review != "APPROVED":
        result.update(status="FAILED", outcome="FRAMEWORK_NOT_APPROVED",
                      error=f"FRAMEWORK_NOT_APPROVED: framework review status is {fw_review}")
        result["blockers"].append({
            "code": "FRAMEWORK_NOT_APPROVED",
            "message": f"Framework '{framework_id}' review status is {fw_review}. Framework identity approval is an "
                       "input to the automated pipeline, not automated by it.",
            "supply": {"verify_framework": {"method": "POST", "path": f"/frameworks/{framework_id}/verify",
                                            "required_scope": "catalog:review"}}})
        stage_done("resolve", framework_review=fw_review)
        return result
    stage_done("resolve", framework_review=fw_review, jurisdiction=fw["jurisdiction_code"])

    # ---- sources: use verified ones, auto-verify eligible proposed ones ----
    sources_info: dict[str, Any] = {"used": [], "auto_verified": [], "ineligible": [], "sync": [], "errors": []}
    if not version_ids:
        rows = db.q(  # official sources only: scoped (uploaded) sources are processed via explicit version_ids
            "SELECT * FROM source WHERE organization_scope IS NULL AND (authority_id=? OR id IN "
            "(SELECT DISTINCT source_id FROM regulatory_document WHERE framework_id=? AND organization_scope IS NULL)) "
            "ORDER BY id",
            (fw["authority_id"], framework_id))
        for src in rows:
            if is_verified(db, src):
                sources_info["used"].append(src["id"])
                continue
            if src["status"] == "PROPOSED":
                eligible, reason = source_eligibility(db, src)
                if eligible:
                    verify_source(db, src["id"], verifier=me, outcome="VERIFIED", evidence=reason,
                                  origin="AUTOMATED", policy_version=POLICY_VERSION)
                    sources_info["auto_verified"].append({"source_id": src["id"], "reason": reason})
                    sources_info["used"].append(src["id"])
                else:
                    sources_info["ineligible"].append({"source_id": src["id"], "status": src["status"],
                                                       "reason": reason})
            else:
                sources_info["ineligible"].append({"source_id": src["id"], "status": src["status"],
                                                   "reason": f"source status is {src['status']}"})
        if not sources_info["used"]:
            result.update(status="FAILED", outcome="SOURCE_CONFIGURATION_REQUIRED",
                          error="SOURCE_CONFIGURATION_REQUIRED: no usable source is configured for this framework")
            result["blockers"].append({
                "code": "SOURCE_CONFIGURATION_REQUIRED",
                "message": f"No verified or automatically verifiable source is configured for framework "
                           f"'{framework_id}'. The pipeline only fetches configured official sources; it never "
                           "searches the open internet.",
                "ineligible_sources": sources_info["ineligible"],
                "supply": {
                    "register_source": {"method": "POST", "path": "/sources", "required_scope": "catalog:operate",
                                        "note": "HTTPS source on the authority's registered official domains is "
                                                "auto-verifiable; file_drop requires human verification"},
                    "upload_document": {"method": "POST", "path": "/uploads", "required_scope": "catalog:operate"},
                    "verify_source": {"method": "POST", "path": "/sources/{id}/verify",
                                      "required_scope": "catalog:review"}}})
            result["sources"] = sources_info
            stage_done("sources", used=0, ineligible=len(sources_info["ineligible"]))
            return result
        stage_done("sources", used=len(sources_info["used"]), auto_verified=len(sources_info["auto_verified"]),
                   ineligible=len(sources_info["ineligible"]))

        # ---- retrieve/parse ----
        for source_id in sources_info["used"]:
            try:
                run = sync_source(db, source_id, blob_dir=blob_dir, actor=me, transport=transport)
                sources_info["sync"].append({k: run[k] for k in ("source_id", "status", "documents_seen",
                                                                 "versions_new", "versions_changed",
                                                                 "versions_unchanged", "errors", "warnings")})
                if run["status"] != "SUCCESS":
                    sources_info["errors"].extend(f"{source_id}: {e}" for e in run["errors"])
            except CatalogError as exc:
                sources_info["errors"].append(f"{source_id}: {exc.code}: {exc.message}")
        stage_done("retrieve", synced=len(sources_info["sync"]), errors=len(sources_info["errors"]))
    result["sources"] = sources_info

    # ---- document scope + automated completeness review ----
    if version_ids:
        versions = db.q(
            "SELECT v.*, d.framework_id, d.language FROM regulatory_document_version v JOIN regulatory_document d "
            f"ON d.id=v.document_id WHERE v.id IN ({','.join('?' * len(version_ids))})", list(version_ids))
        found = {v["id"] for v in versions}
        unknown = [i for i in version_ids if i not in found]
        foreign = [v["id"] for v in versions if v["framework_id"] != framework_id]
        if unknown or foreign:
            raise CatalogError("INVALID_VERSION_SELECTION",
                               f"unknown versions {unknown}, versions of another framework {foreign}")
    else:
        versions = db.q(
            "SELECT v.*, d.framework_id, d.language FROM regulatory_document_version v JOIN regulatory_document d "
            "ON d.id=v.document_id WHERE d.framework_id=? AND "
            + ("d.organization_scope IS NULL" if org_scope is None else "d.organization_scope=?")
            + " ORDER BY v.id", (framework_id, *([] if org_scope is None else [org_scope])))
    excluded = []
    if languages:
        wanted = {code.lower() for code in languages}
        excluded = [v["id"] for v in versions if (v["language"] or "").split("-")[0].lower() not in wanted]
        versions = [v for v in versions if v["id"] not in excluded]
    documents: dict[str, Any] = {"version_ids": [v["id"] for v in versions], "auto_reviewed": [],
                                 "already_reviewed": [], "incomplete": [], "unusable": [],
                                 "language_excluded": excluded}
    for v in versions:
        if v["status"] == "REVIEWED":
            documents["already_reviewed"].append(v["id"])
            continue
        if v["status"] != "AWAITING_REVIEW":
            documents["unusable"].append({"version_id": v["id"], "status": v["status"]})
            continue
        sections = db.scalar("SELECT COUNT(*) FROM document_section WHERE version_id=?", (v["id"],))
        if not v["complete"] or not sections:
            reason = v["incomplete_reason"] if not v["complete"] else "the document parsed into 0 sections"
            documents["incomplete"].append({"version_id": v["id"], "reason": reason})
            continue
        catalog.review_document_version(
            db, v["id"], reviewer=me, decision="APPROVED", origin="AUTOMATED", policy_version=POLICY_VERSION,
            comment=f"AUTOMATED completeness review ({POLICY_VERSION}): the retrieved text is complete per the "
                    f"parser and has {sections} sections; dates kept as stated by the source metadata.",
            published_on=v["published_on"], effective_from=v["effective_from"], effective_to=v["effective_to"])
        documents["auto_reviewed"].append(v["id"])
    if documents["incomplete"]:
        result["blockers"].append({
            "code": "INCOMPLETE_DOCUMENTS",
            "message": "Some retrieved versions are not complete official text and were not reviewed automatically.",
            "versions": documents["incomplete"]})
        result["next_actions"].append(_action(
            "resolve_incomplete_document", "GET", "/documents/{version_id}", "catalog:operate",
            "Inspect the incomplete version and re-upload or reconfigure the source.",
            [d["version_id"] for d in documents["incomplete"]]))
    result["documents"] = documents
    stage_done("document_review", auto_reviewed=len(documents["auto_reviewed"]),
               already_reviewed=len(documents["already_reviewed"]), incomplete=len(documents["incomplete"]))

    # ---- extraction (persists every attempt, including failures) ----
    usable = [v["id"] for v in versions if v["id"] in set(documents["auto_reviewed"] + documents["already_reviewed"])]
    extract_totals = {"sections": 0, "drafted": 0, "duplicates": 0, "llm_errors": 0, "translation_failures": 0,
                      "screened_out": 0, "already_extracted": 0, "model_calls": 0, "non_operative": 0,
                      "attempt_ids": [], "requirement_ids": [], "rejected": []}
    model_info = {"model": llm.info.model, "model_version": llm.info.version, "runtime": llm.info.runtime}
    for n, vid in enumerate(usable, 1):
        def on_section(index: int, total: int, _vid: int = vid, _n: int = n) -> None:
            if index == 1 or index % 5 == 0 or index == total:
                report("extract", framework_id=framework_id, version_id=_vid, version=f"{_n}/{len(usable)}",
                       section=f"{index}/{total}", drafted=extract_totals["drafted"],
                       done=index, total=total, unit="section")  # on_section fires after the section
        stats = extraction.extract_version(db, vid, llm, actor=me, translate=translate, job_id=job_id,
                                           screening=screening, skip_extracted=True, on_section=on_section)
        for key in ("sections", "drafted", "duplicates", "llm_errors", "translation_failures",
                    "screened_out", "already_extracted", "model_calls", "non_operative"):
            extract_totals[key] += stats[key]
        extract_totals["attempt_ids"].extend(stats["attempt_ids"])
        extract_totals["requirement_ids"].extend(stats["requirement_ids"])
        extract_totals["rejected"].extend(f"version {vid}: {r}" for r in stats["rejected"])
    result["extraction"] = {**extract_totals, **model_info}
    result["llm_errors"] += extract_totals["llm_errors"]
    result["section_coverage"] = [section_coverage(db, vid) for vid in usable]
    unprocessed = sum(c["operative_unprocessed"] for c in result["section_coverage"])
    if unprocessed:
        result["warnings"].append(
            f"{unprocessed} operative section(s) were not sent to the model (screening, language or earlier failure); "
            "see section_coverage. Published requirements do not establish coverage of those sections.")
    stage_done("extract", versions=len(usable), drafted=extract_totals["drafted"],
               duplicates=extract_totals["duplicates"], llm_errors=extract_totals["llm_errors"])

    # ---- second-pass review + automated approval ----
    scope_ids = set(documents["version_ids"])
    drafts = [r for r in db.q(
        "SELECT * FROM regulatory_requirement WHERE framework_id=? AND status='DRAFT' AND created_by LIKE 'llm:%' AND "
        + ("organization_scope IS NULL" if org_scope is None else "organization_scope=?")
        + " ORDER BY id", (framework_id, *([] if org_scope is None else [org_scope])))
        if r["document_version_id"] in scope_ids]
    review_out: dict[str, Any] = {"approved": [], "rejected": [], "attempt_ids": [], "not_screened": []}
    if screening == SCREENING_VERSION:
        # drafts from sections outside the PAM screen (e.g. from an earlier unscreened run) stay DRAFT for a human
        rows = {r["id"]: r for r in db.q(
            "SELECT s.id, s.text, d.source_id FROM document_section s JOIN regulatory_document_version v "
            "ON v.id=s.version_id JOIN regulatory_document d ON d.id=v.document_id "
            f"WHERE s.id IN ({','.join('?' * len(drafts)) or 'NULL'})", [d["section_id"] for d in drafts])}
        screens: dict[Any, Any] = {}

        def _passes(section_id: Any) -> bool:
            row = rows.get(section_id)
            if row is None:
                return False
            if row["source_id"] not in screens:
                screens[row["source_id"]] = screen_for_source(db, row["source_id"])
            return screens[row["source_id"]].passes(row["text"])

        review_out["not_screened"] = [d["id"] for d in drafts if not _passes(d["section_id"])]
        drafts = [d for d in drafts if d["id"] not in set(review_out["not_screened"])]
    applic_cache: dict[int, Any] = {}
    for i, req in enumerate(drafts, 1):
        if i == 1 or i % 5 == 0 or i == len(drafts):
            report("candidate_review", framework_id=framework_id, candidate=f"{i}/{len(drafts)}",
                   approved=len(review_out["approved"]), rejected=len(review_out["rejected"]),
                   done=i - 1, total=len(drafts), unit="candidate")  # reported before candidate i
        section = db.one("SELECT text FROM document_section WHERE id=?", (req["section_id"],))
        problems: list[dict[str, Any]] = []
        # deterministic first: recitals and duties of public bodies are never auto-approved (and cost no model call)
        not_applicable = mapping_policy.assess(db, req, _cache=applic_cache)
        if not_applicable:
            review_out["rejected"].append({"requirement_id": req["id"], "problems": not_applicable,
                                           "disposition": "LEFT_DRAFT_FOR_HUMAN_REVIEW"})
            continue
        # translation first: a non-English draft needs a reviewed working translation
        if req["translation_status"] == "UNREVIEWED":
            if not req["translation_en"] and translate:  # e.g. the generation failed on an earlier run
                t_started = now_iso()
                t_output = extraction._model_output(
                    llm, extraction.SYSTEM_TRANSLATE,
                    f"Source language: {req['original_language']}\n\nPASSAGE:\n{req['original_text']}",
                    extraction.TRANSLATION_SCHEMA)
                regenerated = extraction._validated_translation(t_output)
                review_out["attempt_ids"].append(extraction._record_translation_attempt(
                    db, version_id=req["document_version_id"], section_id=req["section_id"],
                    requirement_id=req["id"], llm=llm, started_at=t_started, output=t_output,
                    translation=regenerated, job_id=job_id))
                if regenerated:
                    with db.tx():
                        db.x("UPDATE regulatory_requirement SET translation_en=?, translation_model=?, "
                             "translation_model_version=? WHERE id=?",
                             (regenerated, llm.info.model, llm.info.version, req["id"]))
                    req = {**req, "translation_en": regenerated}
            if not req["translation_en"]:
                problems.append({"code": "TRANSLATION_UNAVAILABLE",
                                 "message": "no working translation could be generated for this passage"})
            else:
                t_attempt, t_ok, t_problems = _review_translation(db, llm, req, job_id)
                review_out["attempt_ids"].append(t_attempt)
                if t_ok:
                    catalog.review_translation(db, req["id"], reviewer=me, decision="REVIEWED",
                                               origin="AUTOMATED", policy_version=POLICY_VERSION,
                                               attempt_id=t_attempt)
                else:
                    problems.append({"code": "TRANSLATION_REJECTED", "message": "; ".join(t_problems),
                                     "attempt_id": t_attempt})
        attempt_id, review, review_problems = _review_candidate(db, llm, req, section["text"] if section else "",
                                                                job_id)
        review_out["attempt_ids"].append(attempt_id)
        if review_problems:
            problems.append({"code": "REVIEW_FAILED", "message": "; ".join(review_problems),
                             "attempt_id": attempt_id})
            result["llm_errors"] += 1
        elif review is not None and review.verdict != "APPROVE":
            problems.append({"code": "REVIEW_REJECTED",
                             "message": "; ".join(review.reasons) or "the review model rejected the candidate",
                             "attempt_id": attempt_id})
        problems.extend(_code_checks(db, req))
        if not problems:
            try:
                catalog.review(
                    db, "requirement", req["id"], reviewer=me, decision="APPROVED",
                    comment=f"AUTOMATED approval ({POLICY_VERSION}): model review APPROVE "
                            f"({model_info['model']}@{model_info['model_version'][:20]}, attempt {attempt_id}) and "
                            "deterministic checks passed (operative text, addressee, grounding, attribution, "
                            "thresholds, duplicates, dates).",
                    attestations={"automated": True, "policy_version": POLICY_VERSION,
                                  "review_attempt_id": attempt_id, **model_info,
                                  "prompt_version": REVIEW_PROMPT_VERSION},
                    origin="AUTOMATED", policy_version=POLICY_VERSION, attempt_id=attempt_id)
                review_out["approved"].append({"requirement_id": req["id"], "attempt_id": attempt_id,
                                               "decision_origin": "AUTOMATED"})
                continue
            except CatalogError as exc:
                problems.append({"code": exc.code, "message": exc.message})
        review_out["rejected"].append({"requirement_id": req["id"], "problems": problems,
                                       "disposition": "LEFT_DRAFT_FOR_HUMAN_REVIEW"})
    result["review"] = review_out
    if review_out["rejected"]:
        result["next_actions"].append(_action(
            "review_requirement", "POST", "/reviews/requirement/{id}", "catalog:review",
            "Candidates the automated policy did not approve stay DRAFT for human review.",
            [r["requirement_id"] for r in review_out["rejected"]]))
    stage_done("candidate_review", reviewed=len(drafts), approved=len(review_out["approved"]),
               rejected=len(review_out["rejected"]))

    # ---- scoped publication: only automated-approved requirements of this framework ----
    publishable = [r["id"] for r in db.q(
        "SELECT r.id FROM regulatory_requirement r WHERE r.framework_id=? AND r.status='APPROVED' "
        "AND r.published_seq IS NULL AND "
        + ("r.organization_scope IS NULL" if org_scope is None else "r.organization_scope=?")
        + " AND EXISTS (SELECT 1 FROM review_approval a WHERE a.entity_type='requirement' "
        "AND a.entity_id=CAST(r.id AS TEXT) AND a.decision='APPROVED' AND a.decision_origin='AUTOMATED') ORDER BY r.id",
        (framework_id, *([] if org_scope is None else [org_scope])))]
    publication = catalog.publish_scoped(db, me, publishable, organization_scope=org_scope) if publishable \
        else {"published": False, "catalog_version": db.catalog_version(), "requirement_ids": []}
    result["publication"] = publication
    stage_done("publish", published=len(publication["requirement_ids"]),
               catalog_version=publication["catalog_version"])

    # ---- recomputed coverage and template readiness ----
    result["coverage"] = coverage.coverage_detail(db, fw["jurisdiction_code"])
    fw_fresh = db.one("SELECT * FROM regulatory_framework WHERE id=?", (framework_id,))
    if engine is not None:
        template = planning.template_summary(planning.build_plan(db, fw_fresh, when, engine, org_scope=org_scope))
        result["readiness"] = template
        if template["readiness"] != "READY" and publication["requirement_ids"]:
            result["next_actions"].append(_action(
                "draft_mapping", "POST", "/mappings", "catalog:operate",
                "Published requirements need reviewed, published rule mappings before the template can execute.",
                publication["requirement_ids"]))
    else:
        result["readiness"] = {"unavailable_reason": "the policy bundle is not readable by this worker; "
                                                     "query GET /api/v1/catalog/evaluation-templates instead"}

    counts = {"documents_auto_reviewed": len(documents["auto_reviewed"]),
              "extracted_drafts": extract_totals["drafted"], "duplicates_skipped": extract_totals["duplicates"],
              "candidates_reviewed": len(drafts), "approved": len(review_out["approved"]),
              "rejected": len(review_out["rejected"]), "published": len(publication["requirement_ids"]),
              "llm_errors": result["llm_errors"], "incomplete_documents": len(documents["incomplete"]),
              "sections_screened_out": extract_totals["screened_out"],
              "sections_already_extracted": extract_totals["already_extracted"],
              "model_calls_extraction": extract_totals["model_calls"],
              "drafts_left_unscreened": len(review_out["not_screened"])}
    result["counts"] = counts
    if not drafts and not extract_totals["drafted"] and not publication["requirement_ids"]:
        result["warnings"].append(
            "The pipeline ran but produced nothing to publish. An empty result is not evidence of compliance or of "
            "the absence of obligations; check the extraction attempts and the rejected list.")
    partial = bool(result["llm_errors"] or review_out["rejected"] or documents["incomplete"]
                   or sources_info["errors"])
    result["status"] = "PARTIAL" if partial else "SUCCESS"
    result["outcome"] = "PUBLISHED" if publication["requirement_ids"] else "NOTHING_TO_PUBLISH"
    return result
