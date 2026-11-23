"""Operator / reviewer CLI:  python -m regintel <command> ...

Runs on the OMEN host (it needs outbound HTTPS for source synchronization, the
local GPU runtime for extraction and the OPA binary for bundle tests). The API
containers need none of those and only read the resulting catalog database.

Settings load from .env in the working directory; shell variables override it.
Environment (all optional except the model for extraction / llm-check):
  OPM_REGINTEL_DB            catalog database        (default data/regintel/catalog.db)
  OPM_REGINTEL_BLOB_DIR      retrieved documents     (default data/regintel/documents)
  OPM_REGINTEL_BUNDLE_STORE  immutable bundles       (default bundle-store)
  OPM_REGINTEL_BASE_BUNDLE   base policy bundle      (default policy-bundle)
  OPM_REGINTEL_OPA_BINARY    OPA binary              (default .tools/opa[.exe], then PATH)
  OPM_REGINTEL_LLM_URL       local Ollama endpoint   (default http://127.0.0.1:11434)
  OPM_REGINTEL_LLM_MODEL     multilingual model tag  (required for `extract`)
  OPM_REGINTEL_LLM_NUM_CTX   context tokens          (default 4096)
  OPM_REGINTEL_LLM_NUM_PREDICT output tokens         (default 2048)
  OPM_REGINTEL_LLM_TIMEOUT   inference timeout       (default 600 seconds)
  OPM_REGINTEL_LLM_KEEP_ALIVE loaded model lifetime  (default 5m)
  OPM_REGINTEL_REQUIRE_GPU   reject CPU-only output  (default 1)
  OPM_REGINTEL_LLM_PROVIDER  ollama | azure_openai   (default ollama; azure_openai also needs
                             OPM_REGINTEL_ALLOW_HOSTED_LLM=1, OPM_REGINTEL_AZURE_ENDPOINT,
                             OPM_REGINTEL_AZURE_DEPLOYMENT and AZURE_OPENAI_API_KEY)

Every write takes --actor (the person doing it). Review commands refuse an
actor who authored the item.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from . import applicability, catalog, coverage, extraction, registry, rules
from .db import CatalogDb, CatalogError
from .sources import registry as sources

ROOT = Path.cwd()


def _env(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default))


def _opa_binary() -> str | None:
    explicit = os.environ.get("OPM_REGINTEL_OPA_BINARY")
    local = ROOT / ".tools" / ("opa.exe" if os.name == "nt" else "opa")
    return explicit or (str(local) if local.exists() else shutil.which("opa"))


def _load(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _llm():
    from .llm import AzureOpenAIClient, OllamaClient

    provider = os.environ.get("OPM_REGINTEL_LLM_PROVIDER", "ollama").strip().lower()
    if provider == "azure_openai":
        if os.environ.get("OPM_REGINTEL_ALLOW_HOSTED_LLM", "0").strip().lower() not in ("1", "true", "yes", "on"):
            raise CatalogError("LLM_NOT_CONFIGURED", "OPM_REGINTEL_LLM_PROVIDER=azure_openai sends regulatory text to a "
                                                     "hosted model; also set OPM_REGINTEL_ALLOW_HOSTED_LLM=1 to allow it")
        endpoint = os.environ.get("OPM_REGINTEL_AZURE_ENDPOINT", "")
        if not endpoint:
            raise CatalogError("LLM_NOT_CONFIGURED", "set OPM_REGINTEL_AZURE_ENDPOINT to the Azure resource or project URL")
        return AzureOpenAIClient(
            endpoint, os.environ.get("OPM_REGINTEL_AZURE_DEPLOYMENT") or os.environ.get("OPM_REGINTEL_LLM_MODEL", ""),
            os.environ.get("OPM_REGINTEL_AZURE_API_KEY") or os.environ.get("AZURE_OPENAI_API_KEY", ""),
            max_tokens=int(os.environ.get("OPM_REGINTEL_LLM_NUM_PREDICT", "4096")),
            timeout=float(os.environ.get("OPM_REGINTEL_LLM_TIMEOUT", "600")))
    if provider != "ollama":
        raise CatalogError("LLM_NOT_CONFIGURED", f"unknown OPM_REGINTEL_LLM_PROVIDER '{provider}' (ollama, azure_openai)")
    model = os.environ.get("OPM_REGINTEL_LLM_MODEL")
    if not model:
        raise CatalogError("LLM_NOT_CONFIGURED", "set OPM_REGINTEL_LLM_MODEL to an installed multilingual model")
    return OllamaClient(os.environ.get("OPM_REGINTEL_LLM_URL", "http://127.0.0.1:11434"), model,
                        require_gpu=os.environ.get("OPM_REGINTEL_REQUIRE_GPU", "1") != "0",
                        num_ctx=int(os.environ.get("OPM_REGINTEL_LLM_NUM_CTX", "4096")),
                        num_predict=int(os.environ.get("OPM_REGINTEL_LLM_NUM_PREDICT", "2048")),
                        timeout=float(os.environ.get("OPM_REGINTEL_LLM_TIMEOUT", "600")),
                        keep_alive=os.environ.get("OPM_REGINTEL_LLM_KEEP_ALIVE", "5m"))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m regintel", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    def cmd(name: str, help: str, actor: bool = True) -> argparse.ArgumentParser:
        c = sub.add_parser(name, help=help)
        if actor:
            c.add_argument("--actor", required=True, help="person performing the action")
        return c

    c = cmd("init", "create the database and seed the ISO 3166 registry, groups and PAM controls")
    c.add_argument("--starter-sources", action="store_true", help="also load example source proposals (all UNVERIFIED)")
    c.add_argument("--no-subdivisions", action="store_true")

    c = cmd("add", "add registry / draft catalog entities from a JSON file")
    c.add_argument("kind", choices=["jurisdiction", "membership", "authority", "framework", "source", "requirement",
                                    "mapping", "evidence-requirement", "applicability-criteria", "remediation", "rule"])
    c.add_argument("--file", required=True)

    c = cmd("verify-source", "record a human verification (or rejection) of a proposed source")
    c.add_argument("source_id")
    c.add_argument("--outcome", choices=["VERIFIED", "REJECTED"], required=True)
    c.add_argument("--evidence", required=True, help="how the source was confirmed as the authority's official channel")

    c = cmd("sync", "retrieve documents from verified sources")
    c.add_argument("source_id", nargs="?")
    c.add_argument("--all", action="store_true")

    c = cmd("review-document", "confirm a retrieved document version is the complete official text")
    c.add_argument("version_id", type=int)
    c.add_argument("--decision", choices=["APPROVED", "REJECTED"], required=True)
    for opt in ("--published-on", "--effective-from", "--effective-to"):
        c.add_argument(opt)
    c.add_argument("--supersede-previous", action="store_true")
    c.add_argument("--comment", default="")

    c = cmd("verify-framework", "record framework dates/lifecycle confirmed from a reviewed document version")
    c.add_argument("framework_id")
    c.add_argument("--evidence-version", type=int, required=True)
    c.add_argument("--lifecycle", choices=["NOT_YET_IN_FORCE", "IN_FORCE", "REPEALED", "SUPERSEDED"], required=True)
    for opt in ("--published-on", "--effective-from", "--effective-to", "--superseded-by"):
        c.add_argument(opt)

    c = cmd("extract", "draft PAM requirements from a document version with the local GPU model")
    c.add_argument("version_id", type=int)
    c.add_argument("--no-translate", action="store_true")

    c = cmd("review-translation", "accept (optionally correcting) or reject an English working translation")
    c.add_argument("requirement_id", type=int)
    c.add_argument("--decision", choices=["REVIEWED", "REJECTED"], required=True)
    c.add_argument("--corrected")

    c = cmd("review", "approve or reject a draft")
    c.add_argument("kind", choices=[*catalog.TABLES, "rule"])
    c.add_argument("id", type=int)
    c.add_argument("--decision", choices=["APPROVED", "REJECTED"], required=True)
    c.add_argument("--comment", default="")
    c.add_argument("--reviewed-in-original-language", action="store_true",
                   help="attest that the reviewer read the original-language passage (requirements only)")

    cmd("publish", "publish all approved catalog entities as one immutable publication")
    c = cmd("withdraw", "withdraw a published entity (publishes a tombstone)")
    c.add_argument("kind", choices=list(catalog.TABLES))
    c.add_argument("id", type=int)
    c.add_argument("--reason", required=True)
    c.add_argument("--repealed", action="store_true")

    cmd("bundle-build", "build and test a new immutable policy bundle from approved rule versions")
    c = cmd("bundle-activate", "activate a bundle version (an earlier version = rollback; 'base' = no catalog rules)")
    c.add_argument("version")

    c = cmd("list", "show work queues and registry contents", actor=False)
    c.add_argument("what", choices=["sources", "documents", "sections", "requirements", "pending", "bundles", "changes"])
    c.add_argument("--id", type=int, help="document version id (sections) ")
    c.add_argument("--status")

    cmd("coverage", "print the coverage dashboard", actor=False).add_argument("--json", action="store_true")
    c = cmd("applicability", "screen an organization profile (JSON file)", actor=False)
    c.add_argument("--file", required=True)
    cmd("llm-check", "verify the local model endpoint, model and GPU placement", actor=False)
    return p


def _add(db: CatalogDb, kind: str, d: dict[str, Any], actor: str) -> Any:
    if kind == "jurisdiction":
        return registry.add_jurisdiction(db, d["code"], d["kind"], d["name"], d.get("parent_code"), actor=actor)
    if kind == "membership":
        return registry.add_membership(db, d["group"], d["member"], d["valid_from"], d.get("valid_to"), actor=actor)
    if kind == "authority":
        return registry.add_authority(db, d["id"], d["name"], d["jurisdiction"], d["official_domains"],
                                      d.get("languages"), actor=actor)
    if kind == "framework":
        return registry.add_framework(
            db, d["id"], d["title"], d["kind"], d["adoption"], d["jurisdiction"], authority_id=d.get("authority"),
            industries=d.get("industries"), cross_border=bool(d.get("cross_border")),
            implements_framework_id=d.get("implements_framework_id"), actor=actor)
    if kind == "source":
        return sources.propose_source(db, d["id"], d["adapter_type"], d["name"], d["authority"], d["jurisdiction"],
                                      d["config"], languages=d["languages"], actor=actor,
                                      freshness_sla_hours=d.get("freshness_sla_hours", 168))
    if kind == "requirement":
        return extraction.add_manual_requirement(
            db, section_id=d["section_id"], quote=d["quote"], pam_domains=d["pam_domains"],
            obligation_type=d["obligation_type"], thresholds=d.get("thresholds"),
            translation_en=d.get("translation_en"), actor=actor)
    if kind == "mapping":
        return catalog.create_mapping(db, actor=actor, **d)
    if kind == "evidence-requirement":
        return catalog.create_evidence_requirement(db, actor=actor, **d)
    if kind == "applicability-criteria":
        return catalog.create_applicability_criteria(db, actor=actor, **d)
    if kind == "remediation":
        return catalog.create_remediation(db, actor=actor, **d)
    return rules.draft_rule_version(db, actor=actor, **d)


def _list(db: CatalogDb, a: argparse.Namespace) -> Any:
    if a.what == "sources":
        return coverage.stale_sources(db)
    if a.what == "documents":
        return db.q("SELECT v.id AS version_id, d.source_id, d.framework_id, d.external_id, d.language, v.version_label, "
                    "v.status, v.complete, v.incomplete_reason, v.retrieved_at FROM regulatory_document_version v "
                    "JOIN regulatory_document d ON d.id=v.document_id WHERE (? IS NULL OR v.status=?) ORDER BY v.id",
                    (a.status, a.status))
    if a.what == "sections":
        return db.q("SELECT id, ordinal, section_ref, substr(text,1,160) AS preview FROM document_section "
                    "WHERE version_id=? ORDER BY ordinal", (a.id,))
    if a.what == "requirements":
        return db.q("SELECT id, framework_id, section_ref, original_language, obligation_type, pam_domains, thresholds, "
                    "translation_status, status, created_by, original_text, translation_en FROM regulatory_requirement "
                    "WHERE status=? ORDER BY id", (a.status or "DRAFT",))
    if a.what == "pending":
        return {"awaiting_publication": catalog.pending_publication(db),
                "rule_versions": db.q("SELECT id, rule_id, version, status, authored_by, ai_generated FROM rule_version "
                                      "WHERE status IN ('DRAFT','APPROVED') ORDER BY id")}
    if a.what == "bundles":
        return db.q("SELECT version, base_version, digest, created_at, created_by, active FROM bundle_version ORDER BY created_at")
    return db.q("SELECT * FROM regulatory_change ORDER BY id")


def run(a: argparse.Namespace, db: CatalogDb) -> Any:
    store = _env("OPM_REGINTEL_BUNDLE_STORE", "bundle-store")
    if a.cmd == "init":
        out = registry.seed_registry(db, a.actor, subdivisions=not a.no_subdivisions)
        if a.starter_sources:
            out.update(registry.seed_starter_sources(db, a.actor))
        return out
    if a.cmd == "add":
        payload = _load(a.file)
        return {"created": [_add(db, a.kind, d, a.actor) for d in (payload if isinstance(payload, list) else [payload])]}
    if a.cmd == "verify-source":
        return sources.verify_source(db, a.source_id, verifier=a.actor, outcome=a.outcome, evidence=a.evidence)
    if a.cmd == "sync":
        ids = [s["id"] for s in db.q("SELECT id FROM source WHERE status='VERIFIED' ORDER BY id")] if a.all else [a.source_id]
        if not ids or ids == [None]:
            raise CatalogError("NOTHING_TO_SYNC", "name a source or use --all (only VERIFIED sources are synchronized)")
        return [sources.sync_source(db, i, blob_dir=_env("OPM_REGINTEL_BLOB_DIR", "data/regintel/documents"), actor=a.actor)
                for i in ids]
    if a.cmd == "review-document":
        return catalog.review_document_version(
            db, a.version_id, reviewer=a.actor, decision=a.decision, comment=a.comment, published_on=a.published_on,
            effective_from=a.effective_from, effective_to=a.effective_to, supersede_previous=a.supersede_previous)
    if a.cmd == "verify-framework":
        return {"catalog_version": registry.verify_framework(
            db, a.framework_id, reviewer=a.actor, evidence_version_id=a.evidence_version, lifecycle=a.lifecycle,
            published_on=a.published_on, effective_from=a.effective_from, effective_to=a.effective_to,
            superseded_by=a.superseded_by)}
    if a.cmd == "extract":
        with _llm() as llm:
            return extraction.extract_version(db, a.version_id, llm, actor=a.actor, translate=not a.no_translate)
    if a.cmd == "review-translation":
        return catalog.review_translation(db, a.requirement_id, reviewer=a.actor, decision=a.decision,
                                          corrected_translation=a.corrected)
    if a.cmd == "review":
        if a.kind == "rule":
            return rules.review_rule_version(db, a.id, reviewer=a.actor, decision=a.decision, comment=a.comment)
        return catalog.review(db, a.kind, a.id, reviewer=a.actor, decision=a.decision, comment=a.comment,
                              attestations={"reviewed_in_original_language": True} if a.reviewed_in_original_language else {})
    if a.cmd == "publish":
        return catalog.publish_catalog(db, a.actor)
    if a.cmd == "withdraw":
        return catalog.withdraw(db, a.kind, a.id, actor=a.actor, reason=a.reason,
                                status="REPEALED" if a.repealed else "WITHDRAWN")
    if a.cmd == "bundle-build":
        tests = ROOT / "policy-tests"
        return rules.build_bundle(db, base_dir=_env("OPM_REGINTEL_BASE_BUNDLE", "policy-bundle"), store_dir=store,
                                  tests_dir=tests if tests.is_dir() else None, opa_binary=_opa_binary(), actor=a.actor)
    if a.cmd == "bundle-activate":
        out = rules.activate_bundle(db, store, None if a.version == "base" else a.version, actor=a.actor)
        out["next_step"] = "restart OPA and the API on the new bundle directory (see docs/REGINTEL.md)"
        return out
    if a.cmd == "list":
        return _list(db, a)
    if a.cmd == "coverage":
        m = coverage.metrics(db)
        return m if a.json else coverage.render_text(m)
    if a.cmd == "applicability":
        return applicability.evaluate(db, applicability.OrganizationProfile.model_validate(_load(a.file)))
    if a.cmd == "llm-check":
        with _llm() as llm:
            response = llm.generate_json("Reply with JSON.", "Return {\"ok\": true}.",
                                        {"type": "object", "properties": {"ok": {"const": True}},
                                         "required": ["ok"], "additionalProperties": False})
            if response != {"ok": True}:
                raise CatalogError("LLM_CHECK_FAILED", "the model did not return the requested JSON")
            out = {"model": llm.info.model, "model_version": llm.info.version, "runtime": llm.info.runtime}
            if hasattr(llm, "gpu_status"):  # local runtime only
                out.update(num_ctx=llm.num_ctx, gpu=llm.gpu_status())
            return out
    raise CatalogError("UNKNOWN_COMMAND", a.cmd)


def main(argv: list[str] | None = None) -> int:
    # Shell environment takes precedence over the local operator configuration.
    load_dotenv(ROOT / ".env", override=False)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # regulatory text is multilingual
    a = build_parser().parse_args(argv)
    db = CatalogDb(_env("OPM_REGINTEL_DB", "data/regintel/catalog.db"))
    try:
        out = run(a, db)
    except CatalogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - LLM / validation errors: report, never half-apply
        print(f"error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()
    print(out if isinstance(out, str) else json.dumps(out, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
