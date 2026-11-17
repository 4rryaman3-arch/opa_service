"""Vendor capability-mapping documents (e.g. the Securden NIST SP 800-53 control mapping matrix).

Such a document is NOT a regulation. Its table rows say which product capability a vendor
aligns with a control. They are extracted table-aware (PDF layout mode / HTML tables), stored
as ``capability_mapping_row`` (source_origin VENDOR_CAPABILITY_MAPPING, organization-scoped) and
resolved against the official control headings of the framework's published source text. They
are never published as regulatory requirements; they are supplemental capability evidence for
the LLM mapping analyst (``regintel.llm_mapping``) and never proof of a customer's compliance.
"""
from __future__ import annotations

import hashlib
import html
import io
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from . import control_ids
from .db import CatalogDb, now_iso

SOURCE_ORIGIN = "VENDOR_CAPABILITY_MAPPING"
_ID = re.compile(r"^([A-Z]{2})\s*-\s*(\d{1,2})(?:\s*\(\s*(\d{1,2})\s*\))?\b")
_HEADER_WORDS = ("control", "capabilit")
_STOP = {"of", "to", "in", "on", "by", "an", "or", "at", "as", "is", "be", "a", "and"}


def _canon(m: re.Match[str]) -> str:
    return f"{m.group(1)}-{int(m.group(2))}" + (f"({int(m.group(3))})" if m.group(3) else "")


def _join(parts: list[str]) -> str:
    """Join wrapped cell lines. Narrow columns break words without a hyphen ("Managemen" / "t"):
    a single short lowercase fragment that is not a word is glued to the previous one."""
    out = ""
    for p in (x.strip() for x in parts):
        if not p:
            continue
        frag = re.match(r"([a-z]{1,2})(?=\s|$)", p)
        if out and frag and frag.group(1) not in _STOP and out[-1:].isalpha():
            out += p  # "Unsuccessfu" / "l Login Attempts" -> "Unsuccessful Login Attempts"
        elif out.endswith("-") and p[:1].islower():
            out += p  # "least-" / "privilege" -> "least-privilege" (the hyphen is part of the word)
        else:
            out = f"{out} {p}" if out else p
    return re.sub(r"\s+", " ", out).replace("�", "'").strip()


# ------------------------------------------------------------------ PDF (layout mode)


def _runs(line: str) -> list[tuple[int, str]]:
    return [(m.start(), m.group(0)) for m in re.finditer(r"\S+(?: \S+)*", line)]


def _pdf_rows(content: bytes) -> list[dict[str, Any]]:
    from pypdf import PdfReader

    reader = PdfReader(io.BytesIO(content))
    rows: list[dict[str, Any]] = []
    cur: dict[str, Any] | None = None
    bounds: list[int] | None = None
    for pno, page in enumerate(reader.pages, 1):
        lines = (page.extract_text(extraction_mode="layout") or "").splitlines()
        header_at = None
        for i, line in enumerate(lines):
            low = line.lower()
            if all(w in low for w in _HEADER_WORDS) and len(_runs(line)) >= 3:
                starts = [s for s, _ in _runs(line)][:4]
                if len(starts) == 4:
                    bounds = [(starts[k] + starts[k + 1]) // 2 for k in range(3)]
                    header_at = i
                    break
        if header_at is None or bounds is None:
            continue
        body = lines[header_at + 1:]
        # the header's second line ("Title  Requirement") is part of the header
        if body and all(r[1].lower() in ("title", "requirement") for r in _runs(body[0])):
            body = body[1:]
        for line in body:
            runs = _runs(line)
            if not runs:
                continue
            if len(runs) == 1 and runs[0][0] < bounds[0] and len(runs[0][1]) > 40:
                cur = None  # full-width prose: the table has ended
                continue
            cells: list[list[str]] = [[], [], [], []]
            for start, text in runs:
                col = sum(1 for b in bounds if start >= b)
                cells[col].append(text)
            m = _ID.match(" ".join(cells[1])) if cells[1] else None
            if m:
                cur = {"control_id": _canon(m), "family": [], "title": [], "requirement": [], "capability": [],
                       "pages": [pno]}
                rows.append(cur)
                rest = " ".join(cells[1])[m.end():].strip()
                cells[1] = [rest] if rest else []
            if cur is None:
                continue
            if pno not in cur["pages"]:
                cur["pages"].append(pno)
            for key, col in (("family", 0), ("title", 1), ("requirement", 2), ("capability", 3)):
                cur[key].extend(cells[col])
    return [_finish(r, i) for i, r in enumerate(rows)]


def _finish(r: dict[str, Any], index: int) -> dict[str, Any]:
    pages = r.get("pages") or []
    return {"row_index": index, "control_id": r["control_id"], "control_family": _join(r["family"]),
            "control_title": _join(r["title"]), "requirement_summary": _join(r["requirement"]),
            "capability_text": _join(r["capability"]),
            "source_section": (f"pages {pages[0]}-{pages[-1]}" if len(pages) > 1 else f"page {pages[0]}") if pages
            else r.get("source_section", "table")}


# ------------------------------------------------------------------ HTML tables


class _Table(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[list[str]] = []
        self._row: list[str] | None = None
        self._cell: list[str] | None = None

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag == "tr":
            self._row = []
        elif tag in ("td", "th") and self._row is not None:
            self._cell = []
        elif tag == "br" and self._cell is not None:
            self._cell.append(" ")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("td", "th") and self._row is not None and self._cell is not None:
            self._row.append(re.sub(r"\s+", " ", "".join(self._cell)).strip())
            self._cell = None
        elif tag == "tr" and self._row is not None:
            self.rows.append(self._row)
            self._row = None

    def handle_data(self, data: str) -> None:
        if self._cell is not None:
            self._cell.append(data)


def _html_rows(content: bytes) -> list[dict[str, Any]]:
    p = _Table()
    p.feed(html.unescape(content.decode("utf-8", errors="replace")))
    out: list[dict[str, Any]] = []
    for cells in p.rows:
        if len(cells) < 4:
            continue
        m = _ID.match(cells[1])
        if not m:
            continue
        title = cells[1][m.end():].strip()
        out.append(_finish({"control_id": _canon(m), "family": [cells[0]], "title": [title],
                            "requirement": [cells[2]], "capability": [" ".join(cells[3:])],
                            "source_section": f"table row {len(out) + 1}"}, len(out)))
    return out


def extract_rows(content: bytes, fmt: str) -> list[dict[str, Any]]:
    """Table rows of a capability-mapping document, in document order (empty if it has no such table)."""
    try:
        if fmt == "pdf":
            return _pdf_rows(content)
        if fmt == "html":
            return _html_rows(content)
    except Exception:  # noqa: BLE001 - an unparseable table is simply not a capability table
        return []
    return []


def looks_like_capability_mapping(rows: list[dict[str, Any]], text: str) -> bool:
    """A table of >= 3 control-ID rows with a capability column, in a document about capability alignment."""
    low = (text or "").lower()
    return len(rows) >= 3 and sum(1 for r in rows if r["capability_text"]) >= 3 and (
        "capabilit" in low and ("mapping" in low or "alignment" in low or "matrix" in low))


# ------------------------------------------------------------------ storage + resolution


def official_index(db: CatalogDb, framework_id: str) -> tuple[int | None, dict[str, str]]:
    """Control IDs -> official titles from the latest reviewed, global source version of the framework."""
    row = db.one("SELECT v.id FROM regulatory_document_version v JOIN regulatory_document d ON d.id=v.document_id "
                 "WHERE d.framework_id=? AND d.organization_scope IS NULL AND v.status='REVIEWED' AND v.complete=1 "
                 "ORDER BY v.id DESC LIMIT 1", (framework_id,))
    if row is None:
        return None, {}
    idx = control_ids.VersionIndex(db, row["id"])
    titles = {b[2]: b[3] for b in idx.base}
    base_by_title = {b[3]: b[2] for b in idx.base}
    for e in idx.enh:
        titles.setdefault(f"{base_by_title[e[3]]}({e[2]})", e[4])
    return row["id"], titles


def linked_requirements(db: CatalogDb, framework_id: str, control_id: str, scope: str | None) -> list[int]:
    """Published requirements of the framework whose derived canonical control matches the row
    (a base-control row covers its clauses and enhancements; an enhancement row only itself)."""
    reqs = db.q("SELECT * FROM regulatory_requirement WHERE framework_id=? AND status='APPROVED' AND published_seq IS "
                "NOT NULL AND (organization_scope IS NULL" + (" OR organization_scope=?" if scope else "") + ") ORDER BY id",
                (framework_id, *([scope] if scope else [])))
    refs = control_ids.annotate(db, reqs)
    out = []
    for r in reqs:
        ref = refs.get(r["id"]) or {}
        if ref.get("status") != "DERIVED":
            continue
        if ref.get("canonical_id") == control_id or ("(" not in control_id and ref.get("control_id") == control_id):
            out.append(r["id"])
    return out


def ingest(db: CatalogDb, *, scope: str, document_id: int, version_id: int, framework_id: str,
           rows: list[dict[str, Any]], actor: str) -> dict[str, Any]:
    """Store the rows (idempotent per scope/version/row) and resolve each against the official controls."""
    official_version, titles = official_index(db, framework_id)
    stored, unresolved = [], []
    for r in rows:
        cid = r["control_id"]
        found = cid in titles
        reqs = linked_requirements(db, framework_id, cid, scope) if found else []
        status = ("RESOLVED" if reqs else "OFFICIAL_CONTROL_WITHOUT_PUBLISHED_REQUIREMENT") if found \
            else "CANONICAL_CONTROL_UNRESOLVED"
        digest = hashlib.sha256(repr(sorted(r.items())).encode()).hexdigest()
        existing = db.one("SELECT id FROM capability_mapping_row WHERE organization_scope=? AND version_id=? AND "
                          "row_index=?", (scope, version_id, r["row_index"]))
        with db.tx():
            if existing is None:
                rid = db.insert("capability_mapping_row", organization_scope=scope, document_id=document_id,
                                version_id=version_id, row_index=r["row_index"], framework_id=framework_id,
                                control_id=cid, control_title=r["control_title"],
                                official_control_title=titles.get(cid), control_family=r["control_family"],
                                requirement_summary=r["requirement_summary"], capability_text=r["capability_text"],
                                source_section=r["source_section"], source_origin=SOURCE_ORIGIN,
                                official_version_id=official_version, resolution_status=status,
                                requirement_ids=reqs, row_digest=digest, created_by=actor, created_at=now_iso())
                db.audit(actor, "CAPABILITY_ROW_STORED", "capability_mapping_row", rid, document_id=document_id)
            else:
                rid = existing["id"]
                db.x("UPDATE capability_mapping_row SET requirement_ids=?, resolution_status=?, "
                     "official_version_id=?, official_control_title=? WHERE id=?",
                     (repr_json(reqs), status, official_version, titles.get(cid), rid))
        stored.append(rid)
        if status == "CANONICAL_CONTROL_UNRESOLVED":
            unresolved.append(cid)
    return {"document_id": document_id, "version_id": version_id, "framework_id": framework_id,
            "official_version_id": official_version, "rows": len(stored), "row_ids": stored,
            "resolved": db.scalar("SELECT COUNT(*) FROM capability_mapping_row WHERE organization_scope=? AND "
                                  "version_id=? AND resolution_status='RESOLVED'", (scope, version_id)),
            "unresolved_control_ids": unresolved}


def repr_json(value: Any) -> str:
    import json
    return json.dumps(value)


def rows_for_requirement(db: CatalogDb, requirement_id: int, scope: str | None) -> list[dict[str, Any]]:
    if scope is None:
        return []
    rows = db.q("SELECT * FROM capability_mapping_row WHERE organization_scope=? ORDER BY id", (scope,))
    return [r for r in rows if requirement_id in (r["requirement_ids"] or [])]


def document_bytes(db: CatalogDb, version_id: int, blob_dir: Any) -> tuple[bytes, str] | None:
    v = db.one("SELECT storage_path, format, content_sha256 FROM regulatory_document_version WHERE id=?", (version_id,))
    if not v or not v["storage_path"] or blob_dir is None:
        return None
    path = Path(blob_dir) / Path(v["storage_path"]).name  # stored as a file name inside the blob directory
    if not path.is_file():
        return None
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != v["content_sha256"]:
        return None  # stored bytes changed: never extract from unverifiable content
    return data, v["format"]
