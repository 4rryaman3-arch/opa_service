"""Jurisdiction registry: seeding, inheritance and dated memberships.

The registry is reference data. A jurisdiction being present here says nothing
about regulatory coverage; coverage is computed from verified sources, reviewed
documents and published artifacts (see ``coverage.py``).
"""

from __future__ import annotations

import json
import re
from importlib import resources
from typing import Any

from .db import CatalogDb, CatalogError, digest_of, now_iso

CODE_RE = re.compile(r"^[A-Z]{2,3}(-[A-Z0-9]{1,3})?$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
FRAMEWORK_ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{1,47}$")
LANG_RE = re.compile(r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _data(name: str) -> dict[str, Any]:
    return json.loads(resources.files("regintel.data").joinpath(name).read_text(encoding="utf-8"))


def check_date(value: str | None, field: str) -> str | None:
    if value is not None and not DATE_RE.match(value):
        raise CatalogError("INVALID_DATE", f"{field} must be YYYY-MM-DD")
    return value


def seed_registry(db: CatalogDb, actor: str = "seed", subdivisions: bool = True) -> dict[str, int]:
    """Idempotently load ISO 3166-1/-2, supranational groups and PAM controls."""
    iso1, groups, controls = _data("iso3166_1.json"), _data("groups.json"), _data("pam_controls.json")
    src1 = iso1["meta"]["derived_from"]
    with db.tx():
        for e in iso1["entries"]:
            db.x(
                "INSERT OR IGNORE INTO jurisdiction (code, kind, name, alpha3, numeric_code, registry_source) "
                "VALUES (?,?,?,?,?,?)",
                (e["alpha2"], "COUNTRY_OR_TERRITORY", e["name"], e["alpha3"], e["numeric"], f"ISO 3166-1; {src1}"),
            )
        if subdivisions:
            iso2 = _data("iso3166_2.json")
            # Parents first: a subdivision's parent may itself be a subdivision.
            pending = list(iso2["entries"])
            known = {r["code"] for r in db.q("SELECT code FROM jurisdiction")}
            while pending:
                rest = []
                for e in pending:
                    parent = e["parent"] or e["country"]
                    if parent not in known:
                        rest.append(e)
                        continue
                    db.x(
                        "INSERT OR IGNORE INTO jurisdiction (code, kind, name, parent_code, subdivision_type, registry_source) "
                        "VALUES (?,?,?,?,?,?)",
                        (e["code"], "SUBDIVISION", e["name"], parent, e["type"], f"ISO 3166-2; {src1}"),
                    )
                    known.add(e["code"])
                if len(rest) == len(pending):  # orphaned parents: attach to the country
                    for e in rest:
                        e["parent"] = None
                pending = rest
        for j in groups["jurisdictions"]:
            db.x("INSERT OR IGNORE INTO jurisdiction (code, kind, name, registry_source) VALUES (?,?,?,?)",
                 (j["code"], j["kind"], j["name"], "regintel/data/groups.json"))
        for m in groups["memberships"]:
            db.x("INSERT OR IGNORE INTO jurisdiction_membership VALUES (?,?,?,?)",
                 (m["group"], m["member"], m["valid_from"], m["valid_to"]))
        for c in controls["controls"]:
            db.x("INSERT OR IGNORE INTO pam_control (id, domain, title, description) VALUES (?,?,?,?)",
                 (c["id"], c["domain"], c["title"], c["description"]))
            for rule_id in c["predefined_rules"]:
                db.x("INSERT OR IGNORE INTO opa_rule_definition (rule_id, pam_control_id, kind, title, created_at) "
                     "VALUES (?,?,?,?,?)", (rule_id, c["id"], "PREDEFINED_REGO", c["title"], now_iso()))
        db.audit(actor, "SEED_REGISTRY", "jurisdiction", "*")
    return {
        "jurisdictions": db.scalar("SELECT COUNT(*) FROM jurisdiction"),
        "memberships": db.scalar("SELECT COUNT(*) FROM jurisdiction_membership"),
        "pam_controls": db.scalar("SELECT COUNT(*) FROM pam_control"),
    }


def seed_starter_sources(db: CatalogDb, actor: str = "seed") -> dict[str, int]:
    """Optional example proposals. Everything lands as PROPOSED / UNVERIFIED."""
    from .sources.registry import propose_source

    data = _data("starter_sources.json")
    with db.tx():
        for a in data["authorities"]:
            if not db.one("SELECT 1 FROM regulatory_authority WHERE id=?", (a["id"],)):
                add_authority(db, a["id"], a["name"], a["jurisdiction"], a["official_domains"], actor=actor)
        for f in data["frameworks"]:
            if not db.one("SELECT 1 FROM regulatory_framework WHERE id=?", (f["id"],)):
                add_framework(db, f["id"], f["title"], f["kind"], f["adoption"], f["jurisdiction"],
                              authority_id=f.get("authority"), cross_border=bool(f.get("cross_border")), actor=actor)
        for s in data["sources"]:
            if not db.one("SELECT 1 FROM source WHERE id=?", (s["id"],)):
                propose_source(db, s["id"], s["adapter_type"], s["name"], s["authority"], s["jurisdiction"],
                               s["config"], languages=s["languages"], origin="SEED", actor=actor)
    return {"sources": db.scalar("SELECT COUNT(*) FROM source"),
            "frameworks": db.scalar("SELECT COUNT(*) FROM regulatory_framework")}


# ------------------------------------------------------------------ writers


def require_jurisdiction(db: CatalogDb, code: str) -> dict[str, Any]:
    row = db.one("SELECT * FROM jurisdiction WHERE code=?", (code,))
    if row is None:
        raise CatalogError("UNKNOWN_JURISDICTION", f"jurisdiction '{code}' is not in the registry")
    return row


def add_jurisdiction(db: CatalogDb, code: str, kind: str, name: str, parent_code: str | None = None,
                     actor: str = "operator") -> None:
    """Register a jurisdiction not covered by ISO 3166 (regional body, etc.)."""
    if not CODE_RE.match(code):
        raise CatalogError("INVALID_CODE", "jurisdiction code must look like 'XX', 'XXX' or 'XX-YYY'")
    if parent_code:
        require_jurisdiction(db, parent_code)
    with db.tx():
        db.insert("jurisdiction", code=code, kind=kind, name=name, parent_code=parent_code,
                  registry_source=f"manual:{actor}")
        db.audit(actor, "ADD", "jurisdiction", code)


def add_membership(db: CatalogDb, group: str, member: str, valid_from: str, valid_to: str | None = None,
                   actor: str = "operator") -> None:
    require_jurisdiction(db, group)
    require_jurisdiction(db, member)
    check_date(valid_from, "valid_from")
    check_date(valid_to, "valid_to")
    with db.tx():
        db.x("INSERT INTO jurisdiction_membership VALUES (?,?,?,?)", (group, member, valid_from, valid_to))
        db.audit(actor, "ADD", "jurisdiction_membership", f"{group}:{member}")


def add_authority(db: CatalogDb, id: str, name: str, jurisdiction: str, official_domains: list[str],
                  languages: list[str] | None = None, actor: str = "operator") -> None:
    if not SLUG_RE.match(id):
        raise CatalogError("INVALID_ID", "authority id must be a lowercase slug")
    require_jurisdiction(db, jurisdiction)
    with db.tx():
        db.insert("regulatory_authority", id=id, name=name, jurisdiction_code=jurisdiction,
                  official_domains=sorted(d.lower() for d in official_domains), languages=languages or [],
                  created_at=now_iso())
        db.audit(actor, "ADD", "regulatory_authority", id)


def add_framework(db: CatalogDb, id: str, title: str, kind: str, adoption: str, jurisdiction: str, *,
                  authority_id: str | None = None, industries: list[str] | None = None, cross_border: bool = False,
                  implements_framework_id: str | None = None, actor: str = "operator") -> None:
    """Register a framework. It starts UNVERIFIED with no dates: dates and
    lifecycle are set by ``verify_framework`` from the official text."""
    if not FRAMEWORK_ID_RE.match(id):
        raise CatalogError("INVALID_ID", "framework id must match [A-Z0-9-]{2,48}")
    require_jurisdiction(db, jurisdiction)
    with db.tx():
        db.insert("regulatory_framework", id=id, title=title, kind=kind, adoption=adoption,
                  jurisdiction_code=jurisdiction, authority_id=authority_id,
                  industries=sorted(industries or []), cross_border=int(cross_border),
                  implements_framework_id=implements_framework_id, created_at=now_iso())
        db.audit(actor, "ADD", "regulatory_framework", id)


def verify_framework(db: CatalogDb, framework_id: str, *, reviewer: str, decision: str = "APPROVED",
                     findings: str = "", evidence_version_id: int | None = None, lifecycle: str | None = None,
                     published_on: str | None = None, effective_from: str | None = None,
                     effective_to: str | None = None, superseded_by: str | None = None,
                     origin: str = "HUMAN", policy_version: str | None = None) -> int:
    """Record a reviewer's decision on a registered framework, with their findings.

    APPROVED marks the framework VERIFIED. Lifecycle and dates are optional, but
    when supplied they must be confirmed against a complete, reviewed official
    document version of that framework. REJECTED records the findings and leaves
    (or returns) the framework UNVERIFIED. Returns the catalog version."""
    fw = db.one("SELECT * FROM regulatory_framework WHERE id=?", (framework_id,))
    if fw is None:
        raise CatalogError("UNKNOWN_FRAMEWORK", framework_id)
    if decision not in ("APPROVED", "REJECTED"):
        raise CatalogError("INVALID_DECISION", decision)
    findings = (findings or "").strip()
    content = {k: v for k, v in fw.items() if k not in ("verification_status", "verified_by", "updated_seq")}
    if decision == "REJECTED":
        if len(findings) < 3:
            raise CatalogError("FINDINGS_REQUIRED", "state why the framework is rejected")
        with db.tx():
            if fw["verification_status"] == "VERIFIED":  # a published attribute changes: announce it
                seq = db.publish(reviewer, "REGISTRY", [("framework", framework_id, "UPSERT")], {"framework": framework_id})
                db.x("UPDATE regulatory_framework SET verification_status='UNVERIFIED', verified_by=NULL, updated_seq=? "
                     "WHERE id=?", (seq, framework_id))
            db.insert("review_approval", entity_type="framework", entity_id=framework_id, decision="REJECTED",
                      reviewer=reviewer, comment=findings, entity_digest=digest_of(content), decided_at=now_iso(),
                      decision_origin=origin, policy_version=policy_version)
            db.audit(reviewer, "FRAMEWORK_REJECTED", "regulatory_framework", framework_id)
        return db.catalog_version()
    dated = lifecycle or published_on or effective_from or effective_to or superseded_by
    if dated and not lifecycle:
        raise CatalogError("MISSING_LIFECYCLE", "dates and successors can only be recorded together with a lifecycle")
    if dated or evidence_version_id is not None:
        ev = db.one(
            "SELECT v.status, v.complete, d.framework_id FROM regulatory_document_version v "
            "JOIN regulatory_document d ON d.id=v.document_id WHERE v.id=?", (evidence_version_id,))
        if ev is None or ev["status"] != "REVIEWED" or not ev["complete"] or ev["framework_id"] != framework_id:
            raise CatalogError("EVIDENCE_NOT_REVIEWED",
                               "framework lifecycle and dates must be confirmed against a complete, reviewed official "
                               "document version of that framework")
    for name, v in (("published_on", published_on), ("effective_from", effective_from), ("effective_to", effective_to)):
        check_date(v, name)
    if lifecycle in ("REPEALED", "SUPERSEDED") and not effective_to:
        raise CatalogError("MISSING_END_DATE", "a repealed or superseded framework needs effective_to")
    if lifecycle == "SUPERSEDED" and not superseded_by:
        raise CatalogError("MISSING_SUCCESSOR", "a superseded framework needs superseded_by")
    if lifecycle in ("IN_FORCE", "REPEALED", "SUPERSEDED") and not effective_from:
        raise CatalogError("MISSING_START_DATE", "effective_from is required once a framework has been in force")
    with db.tx():
        seq = db.publish(reviewer, "REGISTRY", [("framework", framework_id, "UPSERT")], {"framework": framework_id})
        if lifecycle:
            db.x(
                "UPDATE regulatory_framework SET lifecycle=?, published_on=?, effective_from=?, effective_to=?, "
                "superseded_by=?, verification_status='VERIFIED', verified_by=?, updated_seq=? WHERE id=?",
                (lifecycle, published_on, effective_from, effective_to, superseded_by, reviewer, seq, framework_id),
            )
        else:  # plain approval: recorded attributes are left exactly as they are
            db.x("UPDATE regulatory_framework SET verification_status='VERIFIED', verified_by=?, updated_seq=? WHERE id=?",
                 (reviewer, seq, framework_id))
        db.insert("review_approval", entity_type="framework", entity_id=framework_id, decision="APPROVED",
                  reviewer=reviewer, comment=findings, attestations={"evidence_version_id": evidence_version_id},
                  entity_digest=str(evidence_version_id) if evidence_version_id else digest_of(content),
                  decided_at=now_iso(), decision_origin=origin, policy_version=policy_version)
        db.audit(reviewer, "FRAMEWORK_APPROVED", "regulatory_framework", framework_id)
    return seq


# ------------------------------------------------------------------ queries


def jurisdiction_closure(db: CatalogDb, code: str, as_of: str) -> list[dict[str, str]]:
    """Every jurisdiction whose rules can reach ``code`` on ``as_of``:
    itself, its parents (subdivision -> country) and any group that one of
    those was a member of on that date. Returned with the path that explains it."""
    require_jurisdiction(db, code)
    out: list[dict[str, str]] = [{"code": code, "via": "SELF"}]
    seen = {code}
    chain = [code]
    current = code
    while True:
        parent = db.scalar("SELECT parent_code FROM jurisdiction WHERE code=?", (current,))
        if not parent or parent in seen:
            break
        out.append({"code": parent, "via": f"PARENT_OF:{current}"})
        seen.add(parent)
        chain.append(parent)
        current = parent
    frontier = list(chain)
    while frontier:
        member = frontier.pop(0)
        for row in db.q(
            "SELECT group_code FROM jurisdiction_membership WHERE member_code=? AND valid_from<=? "
            "AND (valid_to IS NULL OR valid_to>?) ORDER BY group_code", (member, as_of, as_of)):
            g = row["group_code"]
            if g not in seen:
                seen.add(g)
                out.append({"code": g, "via": f"MEMBER:{member}"})
                frontier.append(g)
    return out
