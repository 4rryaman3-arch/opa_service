"""Preload model drafts prepared offline by ``scripts/prepare_catalog_documents.py``.

The staging package holds, per official document, the sections and the
grounded candidates the local model already proposed (``pam-keyword-screen-v1``).
When a staged document is byte-identical (same SHA-256) to a global catalog
document version, its candidates are imported as ordinary model DRAFTS:

* every candidate is re-validated and re-grounded against the catalog's own
  section text (a staged section whose text differs is skipped and reported);
* each processed section gets an EXTRACTION attempt row whose
  ``raw_unavailable_reason`` states it was imported, so later automated runs
  skip it instead of calling the model again;
* nothing is reviewed, approved or published here - drafts go through the
  normal manual review or the automated policy like any other model output.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from . import extraction
from .db import CatalogDb, now_iso
from .textproc import normalize

IMPORT_REASON = ("imported from the offline staging package (scripts/prepare_catalog_documents.py); the original "
                 "raw model output was not retained")


def import_staging(db: CatalogDb, staging_dir: Path, *, actor: str) -> dict[str, Any]:
    report: dict[str, Any] = {"files": [], "drafted": 0, "duplicates": 0, "sections_imported": 0,
                              "requirement_ids": []}
    for path in sorted(Path(staging_dir).glob("*.json")):
        if path.name == "summary.json":
            continue
        staged = json.loads(path.read_text(encoding="utf-8"))
        entry: dict[str, Any] = {"file": path.name, "framework_id": staged.get("framework_id"), "version_id": None,
                                 "sections_imported": 0, "already_extracted": 0, "section_mismatch": [],
                                 "drafted": 0, "duplicates": 0, "rejected": []}
        report["files"].append(entry)
        version = db.one(
            "SELECT v.id FROM regulatory_document_version v JOIN regulatory_document d ON d.id=v.document_id "
            "WHERE v.content_sha256=? AND d.language=? AND d.framework_id=? AND d.organization_scope IS NULL "
            "ORDER BY v.id LIMIT 1", (staged.get("sha256"), staged.get("language"), staged.get("framework_id")))
        if version is None:
            entry["skipped"] = "no global catalog version with the same content hash, language and framework"
            continue
        v = extraction.load_version(db, version["id"])
        entry["version_id"] = v["id"]
        if v["status"] in ("REJECTED", "SUPERSEDED") or not v["complete"]:
            entry["skipped"] = f"catalog version {v['id']} is {v['status']} / complete={v['complete']}"
            continue
        model = staged.get("model") or {}
        info = SimpleNamespace(model=model.get("model", "unknown"), version=model.get("version", ""),
                               runtime=model.get("runtime", ""))
        provenance = {"method": "LOCAL_LLM", "model": info.model, "model_version": info.version,
                      "runtime": info.runtime, "prompt_version": staged.get("prompt_version"),
                      "screening": staged.get("screening"), "imported_from": f"staging:{path.name}"}
        staged_sections = {str(s["ordinal"]): s for s in staged.get("sections", [])}
        for ordinal, ex in sorted((staged.get("extractions") or {}).items(), key=lambda kv: int(kv[0])):
            if ex.get("screened_out"):
                continue
            s = db.one("SELECT * FROM document_section WHERE version_id=? AND ordinal=?", (v["id"], int(ordinal)))
            staged_s = staged_sections.get(ordinal)
            if s is None or staged_s is None or normalize(s["text"]) != normalize(staged_s["text"]):
                entry["section_mismatch"].append(int(ordinal))
                continue
            if extraction.section_already_extracted(db, v["id"], s["id"]):
                entry["already_extracted"] += 1
                continue
            if staged.get("prompt_version") != extraction.PROMPT_VERSION:
                entry["section_mismatch"].append(int(ordinal))  # a different prompt is not the same extraction
                continue
            raw = {"requirements": ex.get("requirements") or []}
            accepted, rejections = extraction.validate_candidates_detailed(raw, s["text"])
            stats = {"duplicates": 0, "translation_failures": 0, "attempt_ids": [], "drafted": 0,
                     "requirement_ids": []}
            started = now_iso()
            ids = extraction.store_candidates(db, v, s, accepted, llm=None, model_info=info, provenance=provenance,
                                              actor=actor, translate=False, job_id=None, stats=stats)
            status = "VALIDATION_FAILED" if rejections and not accepted else ("PARTIAL" if rejections else "SUCCEEDED")
            output = {"raw": None, "truncated": False, "unavailable_reason": IMPORT_REASON, "parsed": raw,
                      "parse_error": None, "error": None}
            extraction._record_attempt(
                db, version_id=v["id"], section_id=s["id"], kind="EXTRACTION", requirement_id=None,
                llm=SimpleNamespace(info=info), prompt_version=extraction.PROMPT_VERSION, started_at=started,
                status=status, output=output, validated={"requirements": [c.model_dump() for c in accepted]},
                validation_errors=[{"index": r["index"], **e, "code": r["code"]}
                                   for r in rejections for e in r["errors"]],
                accepted_ids=ids, rejected=rejections)
            entry["sections_imported"] += 1
            entry["drafted"] += stats["drafted"]
            entry["duplicates"] += stats["duplicates"]
            entry["rejected"].extend(f"#{ordinal}: {r['code']}" for r in rejections)
            report["requirement_ids"].extend(ids)
        report["drafted"] += entry["drafted"]
        report["duplicates"] += entry["duplicates"]
        report["sections_imported"] += entry["sections_imported"]
    return report
