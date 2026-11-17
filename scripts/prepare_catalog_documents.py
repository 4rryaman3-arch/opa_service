"""Download configured English EU texts and prepare local, unpublished extraction drafts.

This staging workflow does not create human verification/approval records.
Reruns reuse downloaded content and completed sections. Use --fetch-only to
download and parse without inference. Output is local operator review material.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
from regintel import extraction, textproc
from regintel.__main__ import _llm
from regintel.sources.registry import build_adapter
from regintel.sources.base import Fetcher

from regintel.screening import PAM_TERMS, screened_text  # noqa: E402,F401  (shared with the automated pipeline)


def save(path, data):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)


def write_review_report(output):
    lines = ["# EU regulatory document extraction — review package", "",
        "Status: UNREVIEWED. These are model proposals, not published regulatory requirements.", "",
        "The source and document completeness still need human verification. Each candidate must be reviewed "
        "in context before catalog approval/publication. No mappings or executable rules are created here.", "",
        "All parsed sections were screened for PAM terms; matching passages and neighboring paragraphs were "
        "sent to the local model. Screening can miss obligations. Use --all-sections for exhaustive inference; "
        "neither mode establishes legal completeness or applicability.", ""]
    for path in sorted(output.glob("EU-*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        lines += [f"## {data['framework_id']} ({data['language']})", "",
            f"Source: {data['url']}", "", f"Content SHA-256: `{data['sha256']}`", "",
            f"Sections processed: {len(data['extractions'])}/{len(data['sections'])}; "
            f"inference errors: {len(data['errors'])}.", ""]
        count = 0
        for item in data["extractions"].values():
            for candidate in item["requirements"]:
                count += 1
                lines += [f"### Candidate {count}: {item['section_ref']}", "",
                    "Model classification: " + candidate["obligation_type"] + "; " + ", ".join(candidate["pam_domains"]), "",
                    "> " + candidate["quote"].replace("\n", "\n> "), "",
                    "Reviewer decision: [ ] accept [ ] reject [ ] correct; rationale: __________", ""]
        lines += [f"Total grounded candidates: {count}.", ""]
        if data["errors"]:
            lines += ["Errors: " + json.dumps(data["errors"], ensure_ascii=False), ""]
    (output / "REVIEW.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "data/regintel/staging/eu-starter")
    parser.add_argument("--fetch-only", action="store_true")
    parser.add_argument("--all-sections", action="store_true", help="disable relevance screening (much slower)")
    args = parser.parse_args()
    load_dotenv(ROOT / ".env", override=False)
    args.output.mkdir(parents=True, exist_ok=True)
    seed = json.loads((ROOT / "regintel/data/starter_sources.json").read_text(encoding="utf-8"))
    source = seed["sources"][0]
    source["languages"] = ["en"]
    adapter = build_adapter(source)
    fetcher = Fetcher(adapter.config)
    paths = []
    try:
        for ref in adapter.discover(fetcher):
            path = args.output / f"{ref.framework_id}-{ref.language}.json"
            if not path.exists():
                document = adapter.fetch(fetcher, ref)
                parsed = textproc.parse_document(document.content, document.format, charset=document.charset,
                                                 heading_classes=adapter.heading_classes)
                if not parsed.complete:
                    raise RuntimeError(f"{ref.framework_id}: incomplete document: {parsed.incomplete_reason}")
                blob = args.output / f"{document.sha256}.html"
                blob.write_bytes(document.content)
                save(path, {"framework_id": ref.framework_id, "language": ref.language,
                            "url": ref.url, "retrieved_url": document.retrieved_url,
                            "sha256": document.sha256, "raw_file": blob.name,
                            "status": "UNREVIEWED_STAGING", "source_verified_by_human": False,
                            "published": False, "sections": [asdict(s) for s in parsed.sections],
                            "extractions": {}, "errors": {}})
            paths.append(path)
            data = json.loads(path.read_text(encoding="utf-8"))
            print(f"{ref.framework_id}: downloaded/parsed {len(data['sections'])} sections", flush=True)
    finally:
        fetcher.close()
    if args.fetch_only:
        return 0
    with _llm() as llm:
        for path in paths:
            data = json.loads(path.read_text(encoding="utf-8"))
            mode = "all-sections-v1" if args.all_sections else "pam-keyword-screen-v1"
            if (data.get("screening") != mode or data.get("model") != asdict(llm.info)
                    or data.get("prompt_version") != extraction.PROMPT_VERSION):
                data["extractions"] = {}
                data["errors"] = {}
            data["screening"] = mode
            data["model"] = asdict(llm.info)
            data["prompt_version"] = extraction.PROMPT_VERSION
            for section in data["sections"]:
                key = str(section["ordinal"])
                if key in data["extractions"]:
                    continue
                try:
                    text = section["text"] if args.all_sections else screened_text(section["text"])
                    if not text:
                        data["extractions"][key] = {"section_ref": section["section_ref"],
                            "requirements": [], "rejected": [], "screened_out": True}
                        save(path, data)
                        continue
                    raw = llm.generate_json(extraction.SYSTEM_EXTRACT,
                        f"Document language: en\n\nSECTION:\n{text}", extraction.EXTRACTION_SCHEMA)
                    accepted, rejected = extraction.validate_candidates(raw, section["text"])
                    data["extractions"][key] = {"section_ref": section["section_ref"],
                        "requirements": [c.model_dump() for c in accepted], "rejected": rejected}
                    data["errors"].pop(key, None)
                except Exception as exc:
                    data["errors"][key] = f"{type(exc).__name__}: {exc}"
                save(path, data)
                count = sum(len(e["requirements"]) for e in data["extractions"].values())
                print(f"{data['framework_id']}: {len(data['extractions'])}/{len(data['sections'])} sections; "
                      f"{count} candidates; {len(data['errors'])} errors", flush=True)
            data["processing_complete"] = len(data["extractions"]) == len(data["sections"]) and not data["errors"]
            save(path, data)
    summary = []
    for path in paths:
        data = json.loads(path.read_text(encoding="utf-8"))
        summary.append({"framework_id": data["framework_id"], "file": path.name,
            "sections": len(data["sections"]), "processed": len(data["extractions"]),
            "candidates": sum(len(e["requirements"]) for e in data["extractions"].values()),
            "screened_out": sum(bool(e.get("screened_out")) for e in data["extractions"].values()),
            "screening": data["screening"],
            "errors": data["errors"], "processing_complete": data.get("processing_complete", False)})
    save(args.output / "summary.json", summary)
    write_review_report(args.output)
    print(json.dumps(summary, indent=2), flush=True)
    return 1 if any(s["errors"] for s in summary) else 0


if __name__ == "__main__":
    raise SystemExit(main())
