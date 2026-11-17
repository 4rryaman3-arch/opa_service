"""PAM requirement extraction and translation with the local LLM.

The model only *proposes*. Each proposed requirement is accepted as a DRAFT
only if it survives deterministic checks:

  * strict JSON schema (unknown fields, wrong enums -> rejected)
  * grounding: the quoted passage must occur verbatim in the section it was
    extracted from (so a passage cannot be invented or mis-attributed)
  * thresholds: every number/duration the model reports must occur literally
    inside that quote (so a regulatory threshold cannot be invented)

Document, framework, language and section reference are taken from the
database row being processed, never from model output. Drafts are invisible to
the catalog API until a human approves and publishes them.

Every model call is persisted as an ``extraction_attempt`` row - raw output
(including malformed or truncated output), parsed JSON, validated JSON,
validation errors with JSON paths, accepted draft ids and rejected candidates -
so reviewers can see exactly what the model produced. Raw output is never
labelled approved; approval exists only on the requirement rows themselves.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from . import PAM_DOMAINS
from .db import CatalogDb, CatalogError, now_iso
from .llm import LocalLlm
from .textproc import normalize

PROMPT_VERSION = "extract-v2"
TRANSLATE_PROMPT_VERSION = "translate-v1"
RAW_RESPONSE_LIMIT = 200_000  # characters of raw model output retained per attempt

SYSTEM_EXTRACT = (
    "You extract regulatory obligations relevant to privileged access management (PAM) from one section of an "
    "official regulatory text. The text may be in any language.\n"
    "WHAT TO EXTRACT: only passages that themselves speak about user or administrator access, access rights, "
    "authentication, passwords/credentials/keys, accounts and identities, session monitoring or recording, logging "
    "or monitoring of access and security events, access reviews, emergency access, or segregation of duties. "
    "Skip general governance, risk management, training, incident reporting, supply chain and business continuity "
    "passages that do not mention those subjects. If nothing qualifies, return an empty list.\n"
    "HOW TO QUOTE: copy each passage EXACTLY as written, in the original language, character for character; never "
    "translate, summarize, merge, reorder or complete text. In an enumerated list, quote each relevant item "
    "separately, without its letter or number.\n"
    "obligation_type: MANDATORY when the passage or the list it belongs to uses binding wording (shall, must, is "
    "required to, and equivalents in the document language); RECOMMENDED for should-type wording; PERMISSIVE for "
    "may-type wording; UNDETERMINED if unclear.\n"
    "pam_domains: choose only topics the passage itself mentions, at most three, from: " + ", ".join(PAM_DOMAINS) + ".\n"
    "thresholds: report a number or duration only if it appears literally in your quote; otherwise leave empty."
)
SYSTEM_TRANSLATE = (
    "You translate a passage of regulatory text into English as a working aid for a reviewer. Translate "
    "faithfully and literally; keep numbers, dates, defined terms and references unchanged; do not explain, "
    "interpret or add anything."
)


class _Threshold(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value_text: str = Field(min_length=1, max_length=80)
    meaning: str = Field(default="", max_length=200)


class _Candidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    quote: str = Field(min_length=20, max_length=4000)
    pam_domains: list[Literal[PAM_DOMAINS]] = Field(min_length=1, max_length=len(PAM_DOMAINS))  # type: ignore[valid-type]
    obligation_type: Literal["MANDATORY", "RECOMMENDED", "PERMISSIVE", "UNDETERMINED"]
    thresholds: list[_Threshold] = Field(default_factory=list, max_length=10)


class _Extraction(BaseModel):
    model_config = ConfigDict(extra="forbid")
    requirements: list[_Candidate] = Field(max_length=30)


class _Translation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    translation: str = Field(min_length=1, max_length=8000)


EXTRACTION_SCHEMA = _Extraction.model_json_schema()
TRANSLATION_SCHEMA = _Translation.model_json_schema()


def _bounded_candidate(item: Any) -> dict[str, Any]:
    """The rejected candidate as the model sent it, bounded for storage/display."""
    if not isinstance(item, dict):
        return {"value": str(item)[:500]}
    return {str(k)[:60]: (v[: 500] + "…" if isinstance(v, str) and len(v) > 500 else v)
            for k, v in list(item.items())[:20]}


def _format_rejection(r: dict[str, Any]) -> str:
    if r["code"] == "NOT_AN_OBJECT":
        return r["message"]
    if r["code"] == "SCHEMA":
        return f"[{r['index']}] schema: {r['message']}"
    return f"[{r['index']}] {r['code']}: {r['message']}"


def validate_candidates_detailed(raw: Any, section_text: str) -> tuple[list[_Candidate], list[dict[str, Any]]]:
    """Pure function: strict validation + grounding.

    Returns ``(accepted, rejections)``. Each rejection is structured:
    ``{index, code, message, errors: [{path, message}], candidate}`` where
    ``path`` is a JSON path into the model's output (``requirements[2].quote``)."""
    if not isinstance(raw, dict) or not isinstance(raw.get("requirements"), list):
        return [], [{"index": None, "code": "NOT_AN_OBJECT",
                     "message": "output is not an object with a 'requirements' list",
                     "errors": [{"path": "$", "message": "expected {\"requirements\": [...]}"}],
                     "candidate": _bounded_candidate(raw)}]
    haystack = normalize(section_text)
    accepted: list[_Candidate] = []
    rejections: list[dict[str, Any]] = []
    seen: set[str] = set()
    for i, item in enumerate(raw["requirements"][:30]):
        base = f"requirements[{i}]"

        def reject(code: str, message: str, errors: list[dict[str, str]]) -> None:
            rejections.append({"index": i, "code": code, "message": message, "errors": errors,
                               "candidate": _bounded_candidate(item)})

        try:
            cand = _Candidate.model_validate(item)
        except ValidationError as exc:
            errors = [{"path": base + ("." + ".".join(str(part) for part in e["loc"]) if e["loc"] else ""),
                       "message": e["msg"][:200]} for e in exc.errors(include_input=False)]
            reject("SCHEMA", "; ".join(e["message"] for e in errors)[:200], errors)
            continue
        quote = normalize(cand.quote)
        if quote not in haystack:
            reject("UNGROUNDED_QUOTE", "passage does not occur verbatim in the section",
                   [{"path": base + ".quote", "message": "passage does not occur verbatim in the section"}])
            continue
        bad = [t.value_text for t in cand.thresholds if normalize(t.value_text) not in quote]
        if bad:
            reject("INVENTED_THRESHOLD", f"{bad} not literally present in the quoted passage",
                   [{"path": base + ".thresholds", "message": f"{bad} not literally present in the quoted passage"}])
            continue
        if quote in seen:
            reject("DUPLICATE_IN_RESPONSE", "the same passage was proposed more than once in this response",
                   [{"path": base + ".quote", "message": "duplicate of an earlier candidate in the same response"}])
            continue
        seen.add(quote)
        accepted.append(cand.model_copy(update={"quote": quote}))
    return accepted, rejections


def validate_candidates(raw: Any, section_text: str) -> tuple[list[_Candidate], list[str]]:
    """Backward-compatible wrapper: rejection reasons as strings."""
    accepted, rejections = validate_candidates_detailed(raw, section_text)
    return accepted, [_format_rejection(r) for r in rejections]


def _model_output(llm: LocalLlm, system: str, prompt: str, schema: dict[str, Any]) -> dict[str, Any]:
    """One model call, normalized for attempt persistence. Raises nothing.

    Returns ``{raw, truncated, unavailable_reason, parsed, parse_error, error}``:
    ``raw`` is the generated text when the client exposes it; ``parsed`` is set
    when the output was valid JSON; ``error`` is set when the call itself failed."""
    out: dict[str, Any] = {"raw": None, "truncated": False, "unavailable_reason": None,
                           "parsed": None, "parse_error": None, "error": None}
    gen = getattr(llm, "generate_raw", None)
    try:
        if gen is not None:
            result = gen(system, prompt, schema)
            raw = result.content
            out["truncated"] = bool(result.truncated)
            if len(raw) > RAW_RESPONSE_LIMIT:
                raw, out["truncated"] = raw[:RAW_RESPONSE_LIMIT], True
            out["raw"] = raw
            try:
                out["parsed"] = json.loads(raw)
            except json.JSONDecodeError as exc:
                out["parse_error"] = f"invalid JSON: {exc.msg} at position {exc.pos}" + \
                                     (" (output truncated at the runtime's output limit)" if out["truncated"] else "")
        else:  # client without raw access (older integrations): parsed output only
            out["parsed"] = llm.generate_json(system, prompt, schema)
            out["unavailable_reason"] = "the model client does not expose raw output; only parsed output was returned"
    except Exception as exc:  # noqa: BLE001 - runtime/GPU/transport failure must be recorded, not raised
        out["error"] = f"{type(exc).__name__}: {exc}"[:500]
        if out["raw"] is None:
            out["unavailable_reason"] = "the model call failed before any output was returned"
    return out


def _record_attempt(db: CatalogDb, *, version_id: int, section_id: int | None, kind: str,
                    requirement_id: int | None, llm: LocalLlm, prompt_version: str, started_at: str,
                    status: str, output: dict[str, Any], validated: Any = None,
                    validation_errors: list[dict[str, Any]] | None = None,
                    accepted_ids: list[int] | None = None,
                    rejected: list[dict[str, Any]] | None = None, job_id: str | None = None) -> int:
    return db.insert(
        "extraction_attempt", job_id=job_id, version_id=version_id, section_id=section_id,
        kind=kind, requirement_id=requirement_id, model=llm.info.model, model_version=llm.info.version,
        runtime=llm.info.runtime, prompt_version=prompt_version, started_at=started_at, finished_at=now_iso(),
        status=status, raw_response=output["raw"], raw_truncated=int(bool(output["truncated"])),
        raw_unavailable_reason=output["unavailable_reason"], parsed_json=output["parsed"],
        validated_json=validated, validation_errors=validation_errors or [],
        accepted_requirement_ids=accepted_ids or [], rejected_candidates=rejected or [],
        error=output["error"] or output["parse_error"])


EXTRACTED_STATUSES = ("SUCCEEDED", "PARTIAL", "VALIDATION_FAILED")


def section_already_extracted(db: CatalogDb, version_id: int, section_id: int) -> bool:
    """True when a completed extraction attempt (current prompt) exists for this section."""
    return db.one(
        "SELECT 1 FROM extraction_attempt WHERE version_id=? AND section_id=? AND kind='EXTRACTION' AND "
        f"prompt_version=? AND status IN ({','.join('?' * len(EXTRACTED_STATUSES))})",
        (version_id, section_id, PROMPT_VERSION, *EXTRACTED_STATUSES)) is not None


def store_candidates(db: CatalogDb, v: dict[str, Any], s: dict[str, Any], accepted: list[_Candidate], *,
                     llm: LocalLlm | None, model_info: Any, provenance: dict[str, Any], actor: str,
                     translate: bool, job_id: str | None, stats: dict[str, Any]) -> list[int]:
    """Persist grounded candidates of one section as DRAFT requirements (deduplicated)."""
    accepted_ids: list[int] = []
    for cand in accepted:
        if db.one("SELECT 1 FROM regulatory_requirement WHERE document_version_id=? AND section_id=? AND original_text=?",
                  (v["id"], s["id"], cand.quote)):
            stats["duplicates"] += 1
            continue
        is_english = v["language"].split("-")[0] == "en"
        translation, t_started, t_output = None, None, None
        if translate and not is_english and llm is not None:
            t_started = now_iso()
            t_output = _model_output(llm, SYSTEM_TRANSLATE,
                                     f"Source language: {v['language']}\n\nPASSAGE:\n{cand.quote}",
                                     TRANSLATION_SCHEMA)
            translation = _validated_translation(t_output)
            if translation is None:
                stats["translation_failures"] += 1
        with db.tx():
            rid = db.insert(
                "regulatory_requirement", framework_id=v["framework_id"], document_version_id=v["id"],
                section_id=s["id"], section_ref=s["section_ref"], original_language=v["language"],
                original_text=cand.quote, obligation_type=cand.obligation_type,
                pam_domains=sorted(set(cand.pam_domains)),
                thresholds=[t.model_dump() for t in cand.thresholds], extraction=provenance,
                translation_en=translation,
                translation_model=model_info.model if translation else None,
                translation_model_version=model_info.version if translation else None,
                translation_status="NOT_REQUIRED" if is_english else "UNREVIEWED",
                effective_from=v["effective_from"], effective_to=v["effective_to"],
                created_by=f"llm:{model_info.model}", created_at=now_iso(),
                organization_scope=v["organization_scope"])  # a requirement lives in its document's namespace
            db.audit(actor, "DRAFT_EXTRACTED", "requirement", rid, model=model_info.model)
        if t_output is not None and llm is not None:
            stats["attempt_ids"].append(_record_translation_attempt(
                db, version_id=v["id"], section_id=s["id"], requirement_id=rid, llm=llm,
                started_at=t_started, output=t_output, translation=translation, job_id=job_id))
        stats["drafted"] += 1
        stats["requirement_ids"].append(rid)
        accepted_ids.append(rid)
    return accepted_ids


def load_version(db: CatalogDb, version_id: int) -> dict[str, Any]:
    v = db.one(
        "SELECT v.*, d.framework_id, d.language, d.source_id, d.organization_scope FROM regulatory_document_version v "
        "JOIN regulatory_document d ON d.id=v.document_id WHERE v.id=?", (version_id,))
    if v is None:
        raise CatalogError("UNKNOWN_DOCUMENT_VERSION", str(version_id))
    return v


def extract_version(db: CatalogDb, version_id: int, llm: LocalLlm, *, actor: str = "worker",
                    translate: bool = True, job_id: str | None = None, screening: str | None = None,
                    skip_extracted: bool = False, on_section: Any = None) -> dict[str, Any]:
    """Run extraction over the sections of one document version.

    ``screening`` (``pam-keyword-screen-v1``) sends only sections that mention PAM
    subjects, and only their matching lines, to the model; skipped sections are
    counted in ``screened_out``. ``skip_extracted`` skips sections that already
    have a completed extraction attempt (resume after interruption, or sections
    preloaded from the offline staging package)."""
    from .screening import SCREENING_VERSION, screen_for_source
    if screening not in (None, "none", SCREENING_VERSION):
        raise CatalogError("INVALID_SCREENING", f"unknown screening mode {screening!r}")
    screen = screening == SCREENING_VERSION
    v = load_version(db, version_id)
    if not v["complete"]:
        raise CatalogError("DOCUMENT_INCOMPLETE", f"version {version_id} is incomplete: {v['incomplete_reason']}")
    if v["status"] in ("REJECTED", "SUPERSEDED"):
        raise CatalogError("DOCUMENT_NOT_USABLE", f"version {version_id} is {v['status']}")
    if not v["framework_id"]:
        raise CatalogError("DOCUMENT_UNASSIGNED", "assign the document to a framework before extraction")
    screener = screen_for_source(db, v["source_id"]) if screen else None
    from . import mapping_policy
    enacting = mapping_policy.enacting_position(db, version_id) if screen else None
    stats = {"version_id": version_id, "sections": 0, "drafted": 0, "duplicates": 0, "rejected": [], "llm_errors": 0,
             "translation_failures": 0, "model": llm.info.model, "model_version": llm.info.version,
             "runtime": llm.info.runtime, "prompt_version": PROMPT_VERSION, "requirement_ids": [], "warnings": [],
             "attempt_ids": [], "screening": screener.label if screener else "none", "screened_out": 0,
             "already_extracted": 0, "model_calls": 0, "non_operative": 0}
    provenance = {"method": "LOCAL_LLM", "model": llm.info.model, "model_version": llm.info.version,
                  "runtime": llm.info.runtime, "prompt_version": PROMPT_VERSION,
                  **({"screening": screener.label} if screener else {})}
    sections = db.q("SELECT * FROM document_section WHERE version_id=? ORDER BY ordinal", (version_id,))
    for index, s in enumerate(sections, 1):
        stats["sections"] += 1
        if on_section is not None:
            on_section(index, len(sections))
        text = s["text"]
        if screener is not None:
            if not mapping_policy.section_is_operative(s, enacting)[0]:
                stats["non_operative"] += 1  # recitals impose no duties; bounded runs do not extract them
                continue
            text = screener.excerpt(s["text"])
            if not text:
                stats["screened_out"] += 1
                continue
        if skip_extracted and section_already_extracted(db, version_id, s["id"]):
            stats["already_extracted"] += 1
            continue
        stats["model_calls"] += 1
        started = now_iso()
        output = _model_output(llm, SYSTEM_EXTRACT, f"Document language: {v['language']}\n\nSECTION:\n{text}",
                               EXTRACTION_SCHEMA)
        if output["error"] is not None:
            stats["llm_errors"] += 1
            stats["rejected"].append(f"{s['section_ref']}: LLM_ERROR {output['error'].split(':', 1)[0]}")
            stats["attempt_ids"].append(_record_attempt(
                db, version_id=version_id, section_id=s["id"], kind="EXTRACTION", requirement_id=None, llm=llm,
                prompt_version=PROMPT_VERSION, started_at=started, status="LLM_ERROR", output=output, job_id=job_id))
            continue
        if output["parsed"] is None:  # raw came back but is not JSON (e.g. truncated)
            stats["llm_errors"] += 1
            stats["rejected"].append(f"{s['section_ref']}: MALFORMED_OUTPUT {output['parse_error']}")
            stats["attempt_ids"].append(_record_attempt(
                db, version_id=version_id, section_id=s["id"], kind="EXTRACTION", requirement_id=None, llm=llm,
                prompt_version=PROMPT_VERSION, started_at=started, status="MALFORMED_OUTPUT", output=output,
                job_id=job_id))
            continue
        # grounding is always checked against the full section text, also when only an excerpt was sent
        accepted, rejections = validate_candidates_detailed(output["parsed"], s["text"])
        stats["rejected"].extend(f"{s['section_ref']}: {_format_rejection(r)}" for r in rejections)
        accepted_ids = store_candidates(db, v, s, accepted, llm=llm, model_info=llm.info, provenance=provenance,
                                        actor=actor, translate=translate, job_id=job_id, stats=stats)
        if rejections and not accepted:
            status = "VALIDATION_FAILED"
        elif rejections:
            status = "PARTIAL"
        else:
            status = "SUCCEEDED"
        stats["attempt_ids"].append(_record_attempt(
            db, version_id=version_id, section_id=s["id"], kind="EXTRACTION", requirement_id=None, llm=llm,
            prompt_version=PROMPT_VERSION, started_at=started, status=status, output=output,
            validated={"requirements": [c.model_dump() for c in accepted]},
            validation_errors=[{"index": r["index"], **e, "code": r["code"]} for r in rejections for e in r["errors"]],
            accepted_ids=accepted_ids, rejected=rejections, job_id=job_id))
    if stats["sections"] == 0:
        stats["warnings"].append("The document version has no parsed sections; nothing was extracted.")
    elif stats["model_calls"] == 0:
        stats["warnings"].append(
            f"No section was sent to the model ({stats['screened_out']} screened out, {stats['non_operative']} "
            f"recitals, {stats['already_extracted']} already extracted). Screening is a relevance filter, not evidence that no obligation exists.")
    elif stats["drafted"] == 0 and stats["duplicates"] == 0:
        stats["warnings"].append("No requirement candidates were accepted; review 'rejected' and consider manual entry. "
                                 "An empty extraction is not evidence of compliance or absence of obligations.")
    if stats["screened_out"]:
        stats["warnings"].append(f"{stats['screened_out']} of {stats['sections']} sections did not pass the "
                                 f"relevance screen ({stats['screening']}) and were not sent to the model.")
    return stats


def _validated_translation(output: dict[str, Any]) -> str | None:
    if output["parsed"] is None:
        return None
    try:
        return _Translation.model_validate(output["parsed"]).translation.strip()
    except ValidationError:
        return None


def _record_translation_attempt(db: CatalogDb, *, version_id: int, section_id: int, requirement_id: int,
                                llm: LocalLlm, started_at: str | None, output: dict[str, Any],
                                translation: str | None, job_id: str | None = None) -> int:
    validation_errors: list[dict[str, Any]] = []
    if output["error"] is not None:
        status = "LLM_ERROR"
    elif output["parsed"] is None:
        status = "MALFORMED_OUTPUT"
    elif translation is None:
        status = "VALIDATION_FAILED"
        try:
            _Translation.model_validate(output["parsed"])
        except ValidationError as exc:
            validation_errors = [{"path": ".".join(str(p) for p in e["loc"]) or "$", "message": e["msg"][:200],
                                  "code": "SCHEMA"} for e in exc.errors(include_input=False)]
    else:
        status = "SUCCEEDED"
    return _record_attempt(
        db, version_id=version_id, section_id=section_id, kind="TRANSLATION", requirement_id=requirement_id,
        llm=llm, prompt_version=TRANSLATE_PROMPT_VERSION, started_at=started_at or now_iso(), status=status,
        output=output, validated={"translation": translation} if translation is not None else None,
        validation_errors=validation_errors, job_id=job_id)


def translate_passage(llm: LocalLlm, text: str, language: str) -> str | None:
    """English working translation. Returns None when the model fails: a
    missing translation is safer than a wrong one."""
    output = _model_output(llm, SYSTEM_TRANSLATE, f"Source language: {language}\n\nPASSAGE:\n{text}",
                           TRANSLATION_SCHEMA)
    return _validated_translation(output)


def add_manual_requirement(db: CatalogDb, *, section_id: int, quote: str, pam_domains: list[str],
                           obligation_type: str, thresholds: list[dict[str, str]] | None = None,
                           translation_en: str | None = None, actor: str) -> int:
    """A reviewer-entered requirement goes through the same grounding checks."""
    s = db.one(
        "SELECT s.*, v.complete, v.status AS vstatus, v.effective_from, v.effective_to, d.framework_id, d.language, "
        "d.organization_scope AS doc_scope "
        "FROM document_section s JOIN regulatory_document_version v ON v.id=s.version_id "
        "JOIN regulatory_document d ON d.id=v.document_id WHERE s.id=?", (section_id,))
    if s is None:
        raise CatalogError("UNKNOWN_SECTION", str(section_id))
    if not s["complete"] or s["vstatus"] in ("REJECTED", "SUPERSEDED") or not s["framework_id"]:
        raise CatalogError("DOCUMENT_NOT_USABLE", "the section's document version cannot be cited")
    accepted, rejected = validate_candidates(
        {"requirements": [{"quote": quote, "pam_domains": pam_domains, "obligation_type": obligation_type,
                           "thresholds": thresholds or []}]}, s["text"])
    if not accepted:
        raise CatalogError("REQUIREMENT_REJECTED", "; ".join(rejected) or "duplicate")
    cand = accepted[0]
    is_english = s["language"].split("-")[0] == "en"
    with db.tx():
        rid = db.insert(
            "regulatory_requirement", framework_id=s["framework_id"], document_version_id=s["version_id"],
            section_id=section_id, section_ref=s["section_ref"], original_language=s["language"],
            original_text=cand.quote, obligation_type=cand.obligation_type, pam_domains=sorted(set(cand.pam_domains)),
            thresholds=[t.model_dump() for t in cand.thresholds], extraction={"method": "MANUAL", "entered_by": actor},
            translation_en=translation_en,
            translation_status="NOT_REQUIRED" if is_english else "UNREVIEWED",
            effective_from=s["effective_from"], effective_to=s["effective_to"], created_by=actor, created_at=now_iso(),
            organization_scope=s["doc_scope"])
        db.audit(actor, "DRAFT_MANUAL", "requirement", rid)
    return rid
