"""prepare_catalog: the Django rewrite's one-shot preparation job (contract 1.0).

Discovery mode: for the requested jurisdictions, run the automated pipeline
(``regintel.automation``) over every visible, review-approved framework. The
"official authority registry" is OPM's own registry of authorities, official
domains and configured sources - the engine NEVER searches the open internet;
jurisdictions without registered sources become structured gaps.

Import mode: for previously uploaded, organization-scoped documents, identify
the framework (requested, matched against the registered catalog, or a new
organization-scoped framework record), then run the same automated pipeline
over exactly those documents.

Both modes end with deterministic mapping preparation (``prepare_mappings``)
and recomputed template readiness. Everything a stage cannot decide becomes a
structured gap with a stable code - never invented content, never a silent
approval. All decisions carry ``decision_origin=AUTOMATED`` + policy version.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path
from typing import Any

from . import automation, coverage, registry
from . import plan as planning
from .db import CatalogDb, CatalogError, digest_of, now_iso
from .llm import LocalLlm
from .textproc import normalize

GAP_CODES = ("SOURCE_CONFIGURATION_REQUIRED", "FRAMEWORK_NOT_APPROVED", "FRAMEWORK_IDENTITY_UNRESOLVED",
             "AMBIGUOUS_FRAMEWORK_SELECTION", "INCOMPLETE_DOCUMENTS", "UNSUPPORTED_RULE", "MODEL_VALIDATION_FAILED",
             "OPERATIVE_SECTIONS_UNPROCESSED", "CAPABILITY_TABLE_NOT_FOUND", "CANONICAL_CONTROL_UNRESOLVED")


def _gap(gaps: list[dict[str, Any]], code: str, message: str, **ids: Any) -> None:
    gaps.append({"code": code, "message": message, **ids})


def identify_framework(db: CatalogDb, doc: dict[str, Any], first_text: str, scope: str,
                       jurisdictions: list[str], requested: list[str], actor: str) -> tuple[str | None, str | None]:
    """Framework for one uploaded document. Returns (framework_id, gap_message).

    Order: explicit request -> match against registered frameworks visible in
    this scope -> a new organization-scoped framework record (clearly marked,
    never official). Ambiguity is a gap, not a guess."""
    if requested:
        if len(requested) == 1:
            return requested[0], None
        hay = normalize((doc.get("title") or "") + " " + first_text).lower()
        hits = [f for f in requested if f.lower() in hay
                or normalize(db.scalar("SELECT title FROM regulatory_framework WHERE id=?", (f,)) or "").lower() in hay]
        if len(hits) == 1:
            return hits[0], None
        return None, (f"several frameworks were requested ({requested}) and document {doc['id']} matches "
                      f"{hits or 'none of them'}; re-run with the intended framework for this document")
    hay = normalize((doc.get("title") or "") + " " + first_text[:4000]).lower()
    pred = "(organization_scope IS NULL OR organization_scope=?)"
    candidates = db.q(f"SELECT id, title FROM regulatory_framework WHERE {pred}", (scope,))
    hits = [f["id"] for f in candidates
            if f["id"].lower() in hay or (len(f["title"]) >= 12 and normalize(f["title"]).lower() in hay)]
    if len(hits) == 1:
        return hits[0], None
    if len(hits) > 1:
        return None, f"document {doc['id']} matches several registered frameworks ({sorted(hits)[:5]}); request one explicitly"
    # No registered match: record an organization-scoped framework. It is the
    # organization's own working record - weakest legal claims, never official.
    fw_id = "ORG-" + digest_of({"scope": scope, "doc": doc["id"], "title": doc.get("title")})[:12].upper()
    if db.one("SELECT 1 FROM regulatory_framework WHERE id=?", (fw_id,)) is None:
        jurisdiction = (jurisdictions or ["INT"])[0]
        with db.tx():
            db.insert("regulatory_framework", id=fw_id, title=(doc.get("title") or f"Uploaded document {doc['id']}")[:300],
                      kind="INDUSTRY_FRAMEWORK", adoption="CONTRACTUAL", jurisdiction_code=jurisdiction,
                      authority_id=doc["authority_id"], industries=[], cross_border=0,
                      created_at=now_iso(), organization_scope=scope)
            db.audit(actor, "ORG_FRAMEWORK_CREATED", "regulatory_framework", fw_id, scope=scope)
        registry.verify_framework(db, fw_id, reviewer=automation.engine_actor(actor),
                                  findings=f"AUTOMATED ({automation.POLICY_VERSION}): organization-scoped framework "
                                           "record for an uploaded document; identity within the organization's own "
                                           "namespace only, never an official registration.",
                                  origin="AUTOMATED", policy_version=automation.POLICY_VERSION)
    return fw_id, None


def _single_tenant(db: CatalogDb, scope: str) -> str | None:
    tenants = [r["tenant_id"] for r in db.q("SELECT DISTINCT tenant_id FROM collector_capability WHERE "
                                            "organization_scope=?", (scope,))]
    return tenants[0] if len(tenants) == 1 else None


_VENDOR_MATRIX = re.compile(r"\b(?:capabilit\w*|control)\s+mapping(?:\s+matrix)?\b|\bmapping\s+matrix\b", re.I)


def _vendor_matrix(db: CatalogDb, doc: dict[str, Any], blob_dir: Any) -> bool:
    """A vendor capability/control mapping matrix is not a regulation: it is never extracted into
    requirements. (Capability matrices are not supported as an input; customers upload standards.)
    Checked on the title and the start of the stored upload (verified against its digest)."""
    head = ""
    v = db.one("SELECT storage_path, content_sha256 FROM regulatory_document_version WHERE document_id=? "
               "ORDER BY id DESC LIMIT 1", (doc["id"],))
    if v and v["storage_path"] and blob_dir is not None:
        path = Path(blob_dir) / Path(v["storage_path"]).name
        if path.is_file():
            data = path.read_bytes()
            if hashlib.sha256(data).hexdigest() == v["content_sha256"]:
                head = re.sub(r"<[^>]{0,400}>", " ", data[:20000].decode("utf-8", "ignore"))
    return bool(_VENDOR_MATRIX.search((doc.get("title") or "") + " " + normalize(head)[:4000]))


ORCHESTRATION_STAGES = ("resolve_documents", "extract_requirements", "validate_requirements",
                        "resolve_canonical_controls", "match_existing_rules", "propose_missing_rules",
                        "validate_rule_specs", "compile_generated_rules", "test_generated_rules",
                        "publish_generated_rules", "publish_mappings", "recompute_readiness", "complete")
ORCHESTRATION_STAGE = {
    "resolve": "resolve_documents", "extract": "extract_requirements", "candidate_review": "validate_requirements",
    "publish": "validate_requirements", "pipeline": "resolve_canonical_controls", "mappings": "match_existing_rules",
    "llm_mapping": "match_existing_rules", "llm_mapping_done": "match_existing_rules",
    "rule_generation": "propose_missing_rules", "readiness": "recompute_readiness",
    **{s: s for s in ORCHESTRATION_STAGES},
}


_OUTCOME_ALIASES = {"LLM_MAPPING_AMBIGUOUS": "RULE_PROPOSAL_AMBIGUOUS",
                    "MANUAL_ASSESSMENT_RECOMMENDED": "MANUAL_ASSESSMENT_REQUIRED"}
_NOT_PAM = ("OUTSIDE_PAM_SCOPE", "NON_OPERATIVE_TEXT", "NOT_MANDATORY")
_ASSIGNED = ("EXISTING_RULE_ASSIGNED", "GENERATED_RULE_ACTIVATED")


def orchestration_outcome(d: dict[str, Any]) -> str:
    """One outcome code per requirement across existing-rule matching and rule generation (§5.4)."""
    if d.get("outcome") in ("PUBLISHABLE", "EXISTING"):
        return "EXISTING_RULE_ASSIGNED"
    generated = (d.get("rule_generation") or {}).get("outcome")
    if generated:
        return _OUTCOME_ALIASES.get(generated, generated)
    code = d.get("gap_code") or d.get("outcome") or "MANUAL_ASSESSMENT_REQUIRED"
    return _OUTCOME_ALIASES.get(code, code)


def orchestration_counts(candidates: list[int], decisions: list[dict[str, Any]],
                         generated: dict[str, Any]) -> dict[str, int]:
    outcomes = Counter(d["orchestration_outcome"] for d in decisions)
    known = sum(outcomes[c] for c in (*_ASSIGNED, "GENERATED_RULE_VALIDATED", "PARAMETER_SOURCE_MISSING",
                                      "COLLECTOR_MISSING", "RULE_PROPOSAL_AMBIGUOUS", *_NOT_PAM))
    return {
        "requirements_processed": len(candidates),
        "pam_applicable_requirements": len(decisions) - sum(outcomes[c] for c in _NOT_PAM),
        "existing_rules_assigned": outcomes["EXISTING_RULE_ASSIGNED"],
        "rule_proposals_created": generated.get("rule_proposals_created", 0),
        "rules_generated": generated.get("rules_generated", 0),
        "rules_activated": generated.get("rules_activated", 0),
        "generated_mappings_published": generated.get("generated_mappings_published", 0),
        "missing_collectors": outcomes["COLLECTOR_MISSING"],
        "missing_parameters": outcomes["PARAMETER_SOURCE_MISSING"],
        "ambiguous_requirements": outcomes["RULE_PROPOSAL_AMBIGUOUS"],
        "unsupported_requirements": len(decisions) - known,
        "orchestration_outcomes": dict(sorted(outcomes.items())),
    }


def prepare_catalog(db: CatalogDb, *, actor: str, scope: str, mode: str, jurisdictions: list[str],
                    llm: LocalLlm, blob_dir: Any, engine: Any = None, industry: str | None = None,
                    requested_framework_ids: list[str] | None = None, include_inherited: bool = True,
                    document_ids: list[int] | None = None, translate: bool = True, as_of: str | None = None,
                    job_id: str | None = None, transport: Any = None, progress: Any = None,
                    languages: list[str] | None = None, screening: str | None = None,
                    tenant_id: str | None = None,
                    llm_mapping: bool = True, auto_rule_generation: bool = False,
                    auto_publish_validated_rules: bool = False, collector_capability_digest: str | None = None,
                    bundle_dir: Any = None, rule_store_path: Any = None) -> dict[str, Any]:
    from . import generated_rules as gr

    languages, screening = automation.pipeline_options(languages, screening)
    tenant_id = tenant_id or _single_tenant(db, scope)
    requested = list(requested_framework_ids or [])
    when = planning.parse_date(None) if as_of is None else str(as_of)
    gaps: list[dict[str, Any]] = []
    result: dict[str, Any] = {
        "organization_scope": scope, "mode": mode, "jurisdictions": jurisdictions, "industry": industry,
        "requested_framework_ids": requested, "include_inherited": include_inherited, "as_of": when,
        "policy_version": automation.POLICY_VERSION, "actor": automation.engine_actor(actor),
        "options": {"languages": languages, "screening": screening},
        "stages": [], "frameworks": [], "gaps": gaps, "llm_errors": 0, "statement": automation.STATEMENT,
    }

    def report(stage: str, **info: Any) -> None:
        # every marker also names its orchestration stage (DJANGO_CONTRACT §5.4) for a stable progress UI
        info = {"orchestration_stage": ORCHESTRATION_STAGE.get(stage, stage), **info}
        # per-item detail markers (rule generation) update the live marker only, not the result's stage list
        if not info.pop("detail", False):
            result["stages"].append({"stage": stage, "job_id": job_id, "at": now_iso(), **info})
        if progress is not None:
            progress(stage, **info)

    # ---- resolve which (framework, version_ids, org_scope) pipelines to run ----
    runs: list[tuple[str, list[int] | None, str | None]] = []
    if mode == "import":
        docs = db.q("SELECT d.*, s.config, s.authority_id FROM regulatory_document d JOIN source s ON s.id=d.source_id "
                    f"WHERE d.id IN ({','.join('?' * len(document_ids or []))})", list(document_ids or []))
        found = {d["id"] for d in docs}
        missing = [i for i in (document_ids or []) if i not in found]
        foreign = [d["id"] for d in docs if d["organization_scope"] != scope]
        if missing or foreign:  # cross-scope ids are reported exactly like unknown ones
            raise CatalogError("UNKNOWN_DOCUMENT", f"documents not found in this organization scope: "
                                                   f"{sorted(missing + foreign)}")
        by_fw: dict[str, list[int]] = {}
        for doc in docs:
            if _vendor_matrix(db, doc, blob_dir):
                _gap(gaps, "CAPABILITY_DOCUMENT_NOT_SUPPORTED", f"document {doc['id']} looks like a vendor capability "
                     "or control mapping matrix, not a regulation or standard; it was not extracted into requirements",
                     document_id=doc["id"])
                continue
            fw_id = doc["framework_id"]
            if not fw_id:
                first = db.one("SELECT s.text FROM document_section s JOIN regulatory_document_version v "
                               "ON v.id=s.version_id WHERE v.document_id=? ORDER BY v.id, s.ordinal LIMIT 1",
                               (doc["id"],))
                doc_jurisdictions = (doc["config"].get("discovery") or {}).get("jurisdictions") or jurisdictions
                fw_id, problem = identify_framework(db, doc, first["text"] if first else "", scope,
                                                    doc_jurisdictions, requested, actor)
                if fw_id is None:
                    _gap(gaps, "FRAMEWORK_IDENTITY_UNRESOLVED" if not requested else "AMBIGUOUS_FRAMEWORK_SELECTION",
                         problem or "", document_id=doc["id"])
                    continue
                with db.tx():
                    db.x("UPDATE regulatory_document SET framework_id=? WHERE id=?", (fw_id, doc["id"]))
                    db.audit(actor, "FRAMEWORK_IDENTIFIED", "regulatory_document", doc["id"], framework_id=fw_id)
            versions = [v["id"] for v in db.q(
                "SELECT id FROM regulatory_document_version WHERE document_id=? ORDER BY id", (doc["id"],))]
            by_fw.setdefault(fw_id, []).extend(versions)
        runs = [(fw, sorted(vids), scope) for fw, vids in sorted(by_fw.items())]
        report("resolve", mode=mode, documents=len(docs), frameworks=sorted(by_fw),
               unresolved=[g["document_id"] for g in gaps if "document_id" in g])
    elif mode == "discovery":
        codes: list[str] = []
        for code in jurisdictions:
            closure = registry.jurisdiction_closure(db, code, when)  # raises UNKNOWN_JURISDICTION -> 404 at submit
            codes.extend(c["code"] for c in closure) if include_inherited else codes.append(code)
        codes = sorted(set(codes))
        if requested:
            frameworks = [f for f in (db.one("SELECT * FROM regulatory_framework WHERE id=? AND "
                                             "(organization_scope IS NULL OR organization_scope=?)", (fid, scope))
                                      for fid in requested) if f]
        else:
            frameworks = db.q(
                f"SELECT * FROM regulatory_framework WHERE jurisdiction_code IN ({','.join('?' * len(codes))}) "
                "AND organization_scope IS NULL ORDER BY id", codes)
            if industry:
                frameworks = [f for f in frameworks if not f["industries"] or industry in f["industries"]]
        # official-discovery results are global (shared official catalog), so org_scope=None
        runs = [(f["id"], None, None) for f in frameworks]
        report("resolve", mode=mode, scope_codes=codes, frameworks=[f["id"] for f in frameworks])
        if not frameworks:
            _gap(gaps, "SOURCE_CONFIGURATION_REQUIRED",
                 f"No framework is registered for jurisdictions {codes}. OPM's authority registry only knows "
                 "registered authorities and configured official sources; it never searches the open internet. "
                 "Register the authority, framework and source, or upload the official document.")
    else:
        raise CatalogError("INVALID_MODE", mode)

    # ---- run the automated pipeline per framework ----
    published_requirements: list[int] = []
    for n, (fw_id, version_ids, run_scope) in enumerate(runs, 1):
        def inner(stage: str, _fw: str = fw_id, _n: int = n, **info: Any) -> None:
            # the inner pipeline's stages are the job's visible progress (otherwise it would show 'resolve' for hours)
            report(stage, **{"framework_id": _fw, "framework": f"{_n}/{len(runs)}", **info})
        sub = automation.build_framework(
            db, actor=actor, framework_id=fw_id, llm=llm, blob_dir=blob_dir, engine=engine,
            version_ids=version_ids, translate=translate, as_of=as_of, job_id=job_id, transport=transport,
            org_scope=run_scope, progress=inner, languages=languages, screening=screening)
        result["llm_errors"] += sub.get("llm_errors", 0)
        entry = {"framework_id": fw_id, "status": sub["status"], "outcome": sub.get("outcome"),
                 "documents": sub.get("documents"), "extraction": sub.get("extraction"),
                 "review": sub.get("review"), "publication": sub.get("publication"),
                 "section_coverage": sub.get("section_coverage", []),
                 "counts": sub.get("counts"), "blockers": sub.get("blockers", [])}
        for blocker in sub.get("blockers", []):
            _gap(gaps, blocker["code"], blocker["message"], framework_id=fw_id)
        for rejected in (sub.get("review") or {}).get("rejected", []):
            _gap(gaps, "MODEL_VALIDATION_FAILED",
                 "; ".join(p["message"] for p in rejected["problems"])[:500],
                 framework_id=fw_id, requirement_id=rejected["requirement_id"])
        published = (sub.get("publication") or {}).get("requirement_ids", [])
        published_requirements.extend(published)
        # also prepare mappings for this framework's previously published, still unmapped requirements; an
        # organization's job also covers the framework's global requirements (its mappings stay organization-scoped)
        pred = "r.organization_scope IS NULL" if run_scope is None else \
            "(r.organization_scope IS NULL OR r.organization_scope=?)"
        args = [fw_id] if run_scope is None else [fw_id, run_scope]
        entry["mapping_candidates"] = [r["id"] for r in db.q(
            f"SELECT r.id FROM regulatory_requirement r WHERE r.framework_id=? AND {pred} "
            "AND r.status='APPROVED' AND r.published_seq IS NOT NULL ORDER BY r.id", args)]
        result["frameworks"].append(entry)
    report("pipeline", frameworks=len(runs), published=len(published_requirements))

    # ---- deterministic mapping preparation + scoped publication of the mappings ----
    candidates = sorted({rid for e in result["frameworks"] for rid in e["mapping_candidates"]})
    # An import job never creates global mappings: global requirements are handled only by the
    # organization-scoped LLM-assisted step below.
    recipe_candidates = candidates if mode == "discovery" else [
        rid for rid in candidates
        if db.scalar("SELECT organization_scope FROM regulatory_requirement WHERE id=?", (rid,)) == scope]
    mappings = automation.prepare_mappings(db, engine, recipe_candidates, actor=actor)
    new_ids = [m["mapping_id"] for m in mappings["prepared"] if not m.get("existing")]
    if new_ids:
        from . import catalog
        mappings["publication"] = catalog.publish_scoped(db, automation.engine_actor(actor), [], new_ids,
                                                         organization_scope=scope if mode == "import" else None)
    by_req = {g["requirement_id"]: g for g in mappings.get("mapping_gaps", [])}
    for rid in mappings["unmapped"]:
        codes = sorted({g["code"] for g in by_req.get(rid, {}).get("gaps", [])})
        _gap(gaps, "UNSUPPORTED_RULE",
             "No executable check is bound to this requirement (reasons in mapping_gap_codes / mapping_gaps); it "
             "stays visible as a coverage gap.", requirement_id=rid, mapping_gap_codes=codes)
    result["mappings"] = mappings
    result["mapping_gaps"] = mappings.get("mapping_gaps", [])
    for entry in result["frameworks"]:
        for cov in entry.get("section_coverage") or []:
            if cov["operative_unprocessed"]:
                _gap(gaps, "OPERATIVE_SECTIONS_UNPROCESSED",
                     f"{cov['operative_unprocessed']} of {cov['operative']} operative sections of version "
                     f"{cov['version_id']} were not extracted (screening, language selection or failures); published "
                     "requirements do not establish coverage of them.", framework_id=entry["framework_id"],
                     version_id=cov["version_id"], section_refs=cov["unprocessed_refs"][:50])
    report("mappings", prepared=len(mappings["prepared"]), unmapped=len(mappings["unmapped"]),
           errors=len(mappings["errors"]))

    # ---- LLM-assisted assignment (analyst) behind the deterministic gate; organization-scoped results ----
    llm_ids: list[int] = []
    if llm_mapping and engine is not None and candidates:
        from . import catalog, llm_mapping as lm
        report("llm_mapping", candidates=len(candidates))
        assigned = lm.assign(db, engine, llm, candidates, scope=scope, tenant=tenant_id, actor=actor, job_id=job_id,
                             progress=report)
        llm_ids = assigned["mapping_ids"]
        if llm_ids:
            assigned["publication"] = catalog.publish_scoped(db, automation.engine_actor(actor), [], llm_ids,
                                                             organization_scope=scope)
        result["llm_errors"] += assigned.get("llm_errors", 0)
        for d in assigned["decisions"]:
            if d.get("gap_code") and d["outcome"] not in ("PUBLISHABLE", "EXISTING"):
                g = next((x for x in gaps if x.get("requirement_id") == d["requirement_id"]
                          and x["code"] == "UNSUPPORTED_RULE"), None)
                if g is not None:
                    g["llm_gap_code"] = d["gap_code"]
            elif d["outcome"] in ("PUBLISHABLE", "EXISTING"):
                gaps[:] = [x for x in gaps if not (x.get("requirement_id") == d["requirement_id"]
                                                   and x["code"] == "UNSUPPORTED_RULE")]
        result["llm_mapping"] = assigned
        report("llm_mapping_done", **assigned["counts"])

        # ---- bounded rule generation for what no existing rule covers (off unless requested and enabled) ----
        if auto_rule_generation:
            generated = gr.generate(
                db, engine, llm, assigned["decisions"], scope=scope, tenant=tenant_id, actor=actor, job_id=job_id,
                publish=auto_publish_validated_rules, pinned_digest=collector_capability_digest,
                bundle_dir=None if bundle_dir is None else Path(bundle_dir),
                store_path=None if rule_store_path is None else Path(rule_store_path), progress=report)
            if generated["mapping_ids"]:
                generated["publication"] = catalog.publish_scoped(db, automation.engine_actor(actor), [],
                                                                  generated["mapping_ids"], organization_scope=scope)
                llm_ids = llm_ids + generated["mapping_ids"]
            result["llm_errors"] += generated["llm_errors"]
            by_rid = {d["requirement_id"]: d for d in generated["decisions"]}
            for d in assigned["decisions"]:
                g = by_rid.get(d["requirement_id"])
                if g is not None:
                    d["rule_generation"] = {k: g.get(k) for k in ("decision_id", "outcome", "gap_code", "rule_id",
                                                                  "mapping_id", "message")}
                    if g["outcome"] == gr.GENERATED_RULE_ACTIVATED:
                        gaps[:] = [x for x in gaps if not (x.get("requirement_id") == d["requirement_id"]
                                                           and x["code"] == "UNSUPPORTED_RULE")]
                    else:
                        x = next((x for x in gaps if x.get("requirement_id") == d["requirement_id"]
                                  and x["code"] == "UNSUPPORTED_RULE"), None)
                        if x is not None:
                            x["rule_generation_gap_code"] = g["outcome"]
            result["rule_generation_decisions"] = generated["decisions"]
            result["rule_generation"] = {k: v for k, v in generated.items() if k != "decisions"}
        if llm_ids:
            report("publish_mappings", completed=len(llm_ids), total=len(llm_ids))
        result["mapping_decisions"] = [
            {**d, "orchestration_outcome": orchestration_outcome(d)} for d in assigned["decisions"]]
        # every decision (recipe, LLM-assisted and generated) as GET .../mapping-gaps shows it to this organization
        result["mapping_gaps"] = automation.requirement_mapping_gaps(
            db, gr.engine_for(db, engine, scope, tenant_id), candidates, scope=scope)

    # ---- recomputed readiness per framework, scoped like the runs (generated rules included) ----
    readiness = []
    view = gr.engine_for(db, engine, scope, tenant_id)
    for fw_id, _vids, run_scope in runs:
        fw = db.one("SELECT * FROM regulatory_framework WHERE id=?", (fw_id,))
        if engine is not None and fw is not None:
            summary = planning.template_summary(planning.build_plan(db, fw, when, view,
                                                                    org_scope=run_scope if run_scope else scope))
            readiness.append(summary)
    report("recompute_readiness", completed=len(readiness), total=len(runs))
    result["readiness"] = readiness
    result["coverage"] = {code: coverage.coverage_detail(db, code) for code in jurisdictions}
    result["counts"] = {
        "frameworks_processed": len(runs), "requirements_published": len(published_requirements),
        "mappings_prepared": len([m for m in mappings["prepared"] if not m.get("existing")]),
        "unmapped_requirements": len(mappings["unmapped"]), "gaps": len(gaps), "llm_errors": result["llm_errors"],
        "mapping_gaps_by_code": dict(sorted(Counter(g["code"] for e in result["mapping_gaps"]
                                                    for g in e["gaps"]).items())),
        **((result.get("llm_mapping") or {}).get("counts") or {
            "llm_candidates": 0, "mappings_validated": 0, "mappings_published": 0, "ambiguous_candidates": 0,
            "missing_parameters": 0, "missing_collectors": 0, "unsupported_requirements": 0}),
        **orchestration_counts(candidates, result.get("mapping_decisions") or [],
                               (result.get("rule_generation") or {}).get("counts") or {}),
    }
    result["counts"]["mappings_published"] += result["counts"]["generated_mappings_published"]
    report("complete", completed=1, total=1)
    if not runs:
        result.update(status="FAILED", outcome="NOTHING_TO_PREPARE",
                      error=(gaps[0]["code"] + ": " + gaps[0]["message"]) if gaps else "nothing to prepare")
    else:
        failed = [e for e in result["frameworks"] if e["status"] == "FAILED"]
        result["status"] = "FAILED" if len(failed) == len(runs) else ("PARTIAL" if gaps or result["llm_errors"] else "SUCCESS")
        if result["status"] == "FAILED":
            result["error"] = "; ".join(f"{e['framework_id']}: {e['outcome']}" for e in failed)[:400]
        result["outcome"] = "PREPARED" if published_requirements or new_ids or llm_ids else "NOTHING_NEW"
    return result


def generate_rules(db: CatalogDb, *, actor: str, scope: str, framework_ids: list[str], llm: LocalLlm, engine: Any,
                   tenant_id: str | None, publish: bool, collector_capability_digest: str | None,
                   job_id: str | None = None, progress: Any = None, bundle_dir: Path | str | None = None,
                   rule_store_path: Path | str | None = None) -> dict[str, Any]:
    """Rule generation only, for requirements already published in ``scope``: existing-rule matching (stored
    decisions are reused) then propose / validate / compile / test / activate, the same calls prepare_catalog
    makes after extraction, without retrieving, extracting or re-validating any document. Progress uses the same
    markers (llm_mapping counted per requirement, propose_missing_rules with sub-step and outcomes)."""
    from . import catalog, generated_rules as gr, llm_mapping as lm

    result: dict[str, Any] = {"status": "SUCCESS", "framework_ids": framework_ids, "stages": [], "llm_errors": 0,
                              "organization_scope": scope, "tenant_id": tenant_id}

    def report(stage: str, **info: Any) -> None:
        info = {"orchestration_stage": ORCHESTRATION_STAGE.get(stage, stage), **info}
        if not info.pop("detail", False):
            result["stages"].append({"stage": stage, "job_id": job_id, "at": now_iso(), **info})
        if progress is not None:
            progress(stage, **info)

    if engine is None:
        raise CatalogError("BUNDLE_UNAVAILABLE", "rule generation needs the policy bundle (existing-rule matching)")
    marks = ",".join("?" * len(framework_ids))
    candidates = [r["id"] for r in db.q(
        f"SELECT id FROM regulatory_requirement WHERE framework_id IN ({marks}) AND status='APPROVED' AND "
        "published_seq IS NOT NULL AND (organization_scope IS NULL OR organization_scope=?) ORDER BY id",
        [*framework_ids, scope])]
    report("resolve", requirements=len(candidates))
    report("llm_mapping", candidates=len(candidates))
    assigned = lm.assign(db, engine, llm, candidates, scope=scope, tenant=tenant_id, actor=actor, job_id=job_id,
                         progress=report)
    if assigned["mapping_ids"]:
        assigned["publication"] = catalog.publish_scoped(db, automation.engine_actor(actor), [],
                                                         assigned["mapping_ids"], organization_scope=scope)
    result["llm_errors"] += assigned.get("llm_errors", 0)
    report("llm_mapping_done", **assigned["counts"])
    generated = gr.generate(db, engine, llm, assigned["decisions"], scope=scope, tenant=tenant_id, actor=actor,
                            job_id=job_id, publish=publish, pinned_digest=collector_capability_digest,
                            bundle_dir=None if bundle_dir is None else Path(bundle_dir),
                            store_path=None if rule_store_path is None else Path(rule_store_path), progress=report)
    # only mappings that are still approved: one withdrawn while the job ran must not block the others
    live = [m for m in generated["mapping_ids"] if db.scalar(
        "SELECT status FROM framework_control_mapping WHERE id=?", (m,)) == "APPROVED"]
    if live:
        generated["publication"] = catalog.publish_scoped(db, automation.engine_actor(actor), [], live,
                                                          organization_scope=scope)
    report("publish_mappings", mappings=len(live))
    result["llm_errors"] += generated["llm_errors"]
    result.update(existing_rule_matching=assigned["counts"], counts=generated["counts"],
                  rule_generation_decisions=generated["decisions"], mapping_ids=live,
                  prompt_version=generated["prompt_version"], model=generated["model"])
    report("complete", **generated["counts"])
    result["status"] = "PARTIAL" if result["llm_errors"] else "SUCCESS"
    return result
