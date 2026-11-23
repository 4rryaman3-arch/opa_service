"""Hub controls: which catalog controls a PAM rule may test, and with which evidence (no model).

The hub is the Securden NIST SP 800-53 control mapping matrix (``securden_nist_800_53_matrix.json``): each
entry names a control (or clause / enhancement, also through ``aliases``) and the one evidence type Securden
produces for it. A generated rule is allowed only where the source passage is the statement of a hub control
and only on that control's evidence types. This is a deterministic gate in front of the model, so a passage
about physical cabling, documentation or a table-of-contents line can never get a PAM rule, whatever wording it
shares with PAM evidence.

Documents without catalog control headings (regulations, organization policies) are not governed by the hub:
``scope_gap`` returns None for them and their existing screening applies unchanged.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

HUB_VERSION = "control-hub-v1"
_MATRIX_FILE = Path(__file__).resolve().parent / "securden_nist_800_53_matrix.json"


@lru_cache(maxsize=1)
def entries() -> tuple[dict[str, Any], ...]:
    if not _MATRIX_FILE.is_file():
        return ()
    return tuple(json.loads(_MATRIX_FILE.read_text(encoding="utf-8")).get("controls", []))


def _keys(ref: dict[str, Any]) -> set[str]:
    cid = (ref.get("canonical_id") or "").upper()
    clause = (ref.get("clause") or "").upper()
    if not cid:
        return set()
    return {cid, f"{cid} {clause}", f"{cid}({clause})"} if clause else {cid}


def entries_for(ref: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Hub entries naming exactly this control, clause or enhancement (an enhancement is never covered by its
    base control: AC-3(3) mandatory access control is not AC-3)."""
    keys = _keys(ref or {})
    if not keys:
        return []
    return [e for e in entries()
            if {e["control_id"].upper(), *(a.upper() for a in e.get("aliases", []))} & keys]


def evidence_types(ref: dict[str, Any] | None) -> set[str]:
    return {e["evidence_type"] for e in entries_for(ref) if e.get("evidence_type")}


def governed(ref: dict[str, Any] | None) -> bool:
    """True when the passage comes from a version with catalog control headings."""
    ref = ref or {}
    return ref.get("status") == "DERIVED" or bool(ref.get("control_headings_in_version"))


def scope_gap(ref: dict[str, Any] | None) -> str | None:
    """Why no PAM rule may be generated for this passage, or None when the hub allows it (or does not apply)."""
    ref = ref or {}
    status = ref.get("status")
    if status == "NO_CONTROL_HEADING_BEFORE_PASSAGE" and ref.get("control_headings_in_version"):
        return (f"{HUB_VERSION}: the passage comes before the first control heading of the document (front matter, "
                "table of contents or headings); it is not a control statement")
    if status != "DERIVED":
        return None
    cid = ref.get("canonical_id") or "?"
    if ref.get("location") == "DISCUSSION":
        return (f"{HUB_VERSION}: the passage is discussion text of {cid}; discussion explains a control and is not "
                "its statement")
    if not entries_for(ref):
        clause = f" {ref['clause']}" if ref.get("clause") else ""
        return (f"{HUB_VERSION}: {cid}{clause} is not a hub control (the Securden NIST SP 800-53 matrix lists no PAM "
                "evidence for it); no PAM rule is generated")
    return None


def mapping_gap(ref: dict[str, Any] | None, evidence_type: str | None) -> str | None:
    """Why an existing generated mapping on this passage must be withdrawn, or None to keep it."""
    ref = ref or {}
    gap = scope_gap(ref)
    if gap or ref.get("status") != "DERIVED":
        return gap
    allowed = evidence_types(ref)
    if evidence_type not in allowed:
        return (f"{HUB_VERSION}: the rule tests {evidence_type}, but {ref.get('canonical_id')} is covered by "
                f"{', '.join(sorted(allowed))}")
    return None
