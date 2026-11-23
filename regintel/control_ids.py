"""Canonical control references for catalog-style standards (NIST SP 800-53 layout).

PDF extraction stores page sections ("#46 page 46"). The canonical identity of a
passage - control ``AC-7``, enhancement ``AC-2(2)``, clause ``a`` - is recovered
deterministically from the headings in the official text itself:

  ``AC-7 UNSUCCESSFUL LOGON ATTEMPTS Control: a. ...``                 base control
  ``(2) ACCOUNT MANAGEMENT | AUTOMATED TEMPORARY ... Automatically``   enhancement

An enhancement is accepted only when its base title equals the title of the
nearest preceding base control. The passage is also located relative to the
``Discussion:`` marker: discussion text explains a control; it is not the control
statement. Nothing here alters a stored requirement (published rows are
immutable); the result is a derived, explainable annotation. No model is used.
"""
from __future__ import annotations

import re
from bisect import bisect_right
from typing import Any

from .db import CatalogDb

METHOD = "DERIVED_FROM_SOURCE_HEADINGS"
_WS = re.compile(r"\s+")
_T = r"[A-Z][A-Z0-9 ,/()'&—–-]{2,}?"
_BASE = re.compile(rf"\b([A-Z]{{2}})-(\d{{1,2}}) ({_T}) Control:")
_ENH = re.compile(rf"\((\d{{1,2}})\) ({_T}) \| ({_T})(?= (?:[A-Z][a-z]|\[|\()| Control)")
# "a. " in control statements, "(a) " in enhancements; after ':' / ';' / '.' or "; and" / "; or"
_CLAUSE = re.compile(r"(?:^|(?<=[;:.] )|(?<=; and )|(?<=; or ))(?:([a-z])\.|\(([a-z])\)) ")
_DISCUSSION = "Discussion:"


def _norm(text: str) -> str:
    return _WS.sub(" ", text or "").strip()


class VersionIndex:
    """Normalized text of one document version with base and enhancement headings."""

    def __init__(self, db: CatalogDb, version_id: int) -> None:
        self.version_id = version_id
        parts, self.starts, self.sections = [], [], []
        offset = 0
        for s in db.q("SELECT id, ordinal, section_ref, text FROM document_section WHERE version_id=? ORDER BY ordinal",
                      (version_id,)):
            t = _norm(s["text"])
            self.starts.append(offset)
            self.sections.append(s)
            parts.append(t)
            offset += len(t) + 1
        self.text = " ".join(parts)
        self.base = [(m.start(), m.end(), f"{m.group(1)}-{int(m.group(2))}", m.group(3).strip())
                     for m in _BASE.finditer(self.text)]
        base_titles = {b[3] for b in self.base}
        self.enh = [(m.start(), m.end(), int(m.group(1)), m.group(2).strip(), m.group(3).strip())
                    for m in _ENH.finditer(self.text) if m.group(2).strip() in base_titles]
        self._base_pos = [b[0] for b in self.base]
        self._enh_pos = [e[0] for e in self.enh]
        self._sec_ids = {s["id"]: i for i, s in enumerate(self.sections)}

    def locate(self, section_id: int, quote: str) -> int | None:
        i = self._sec_ids.get(section_id)
        if i is None:
            return None
        q = _norm(quote)
        at = self.text.find(q, self.starts[i])
        return at if at >= 0 else None

    def reference(self, section_id: int, quote: str) -> dict[str, Any]:
        pos = self.locate(section_id, quote)
        if pos is None:
            return {"canonical_id": None, "method": METHOD, "status": "QUOTE_NOT_LOCATED"}
        bi = bisect_right(self._base_pos, pos) - 1
        if bi < 0:
            return {"canonical_id": None, "method": METHOD, "status": "NO_CONTROL_HEADING_BEFORE_PASSAGE",
                    "control_headings_in_version": len(self.base)}
        b_start, b_end, control_id, title = self.base[bi]
        enhancement, enh_title, head_end = None, None, b_end
        ei = bisect_right(self._enh_pos, pos) - 1
        if ei >= 0:
            e_start, e_end, number, base_title, etitle = self.enh[ei]
            if e_start > b_start and base_title == title:
                enhancement, enh_title, head_end = number, etitle, e_end
        between = self.text[head_end:pos]
        location = "DISCUSSION" if _DISCUSSION in between else "CONTROL_STATEMENT"
        clause = None
        if location == "CONTROL_STATEMENT":
            own = re.match(r"(?:([a-z])\.|\(([a-z])\)) ", _norm(quote))
            marks = list(_CLAUSE.finditer(self.text[head_end - 1:pos]))  # include the ':' of "Control:"
            hit = own or (marks[-1] if marks else None)
            clause = (hit.group(1) or hit.group(2)) if hit else None
        canonical = control_id + (f"({enhancement})" if enhancement else "")
        return {"canonical_id": canonical, "control_id": control_id, "control_title": title,
                "enhancement": enhancement, "enhancement_title": enh_title, "clause": clause,
                "location": location, "method": METHOD, "status": "DERIVED"}

    def controls(self) -> list[str]:
        """Every base control and enhancement heading found in the version, in document order."""
        out: list[tuple[int, str]] = [(b[0], b[2]) for b in self.base]
        titles = {b[3]: b[2] for b in self.base}
        out += [(e[0], f"{titles[e[3]]}({e[2]})") for e in self.enh]
        seen, ordered = set(), []
        for _, cid in sorted(out):
            if cid not in seen:
                seen.add(cid)
                ordered.append(cid)
        return ordered


def annotate(db: CatalogDb, requirements: list[dict[str, Any]], *, _cache: dict[int, VersionIndex] | None = None
             ) -> dict[int, dict[str, Any]]:
    """requirement id -> canonical reference (derived; never stored)."""
    cache = {} if _cache is None else _cache
    out = {}
    for r in requirements:
        vid = r.get("document_version_id")
        if vid is None or r.get("section_id") is None:
            out[r["id"]] = {"canonical_id": None, "method": METHOD, "status": "NO_SOURCE_SECTION"}
            continue
        if vid not in cache:
            cache[vid] = VersionIndex(db, vid)
        out[r["id"]] = cache[vid].reference(r["section_id"], r["original_text"])
    return out


def coverage_report(db: CatalogDb, framework_id: str, *, families: tuple[str, ...] = ("AC", "AU", "IA"),
                    org_scope: str | None = None) -> dict[str, Any]:
    """Published requirements with canonical references, duplicates, and control headings of the
    official text that have no published requirement (extraction omissions). The extracted subset is
    never presented as the complete catalog."""
    scope_sql = "organization_scope IS NULL" + (" OR organization_scope=?" if org_scope else "")
    reqs = db.q(f"SELECT * FROM regulatory_requirement WHERE framework_id=? AND status='APPROVED' "
                f"AND published_seq IS NOT NULL AND ({scope_sql}) ORDER BY id",
                (framework_id, *([org_scope] if org_scope else [])))
    cache: dict[int, VersionIndex] = {}
    refs = annotate(db, reqs, _cache=cache)
    by_canonical: dict[str, list[int]] = {}
    for rid, ref in refs.items():
        if ref.get("canonical_id"):
            key = ref["canonical_id"] + (f" {ref['clause']}" if ref.get("clause") else "")
            by_canonical.setdefault(key, []).append(rid)
    versions = []
    for vid, idx in sorted(cache.items()):
        v = db.one("SELECT id, version_label, content_sha256, published_on FROM regulatory_document_version WHERE id=?",
                   (vid,))
        found = idx.controls()
        covered = {ref["canonical_id"] for ref in refs.values() if ref.get("canonical_id")}
        missing = [c for c in found if c not in covered and c.split("-")[0] in families]
        versions.append({"document_version_id": vid, "version_label": v["version_label"] if v else None,
                         "content_sha256": v["content_sha256"] if v else None,
                         "control_headings_found": len(found),
                         "controls_with_published_requirements": sorted(covered & set(found)),
                         "omitted_controls_in_families": missing, "families": list(families)})
    return {
        "framework_id": framework_id, "method": METHOD,
        "statement": "Canonical references are derived from headings in the official text; stored section "
                     "references are unchanged. The published requirements are an extracted subset, not the "
                     "complete control catalog.",
        "requirements": [{"requirement_id": r["id"], "section_ref": r["section_ref"],
                          "obligation_type": r["obligation_type"], **refs[r["id"]]} for r in reqs],
        "multiple_requirements_per_clause": {k: v for k, v in sorted(by_canonical.items()) if len(v) > 1},
        "discussion_text_requirements": [rid for rid, ref in refs.items() if ref.get("location") == "DISCUSSION"],
        "unresolved": [rid for rid, ref in refs.items() if not ref.get("canonical_id")],
        "versions": versions,
    }
