"""Deterministic applicability filtering.

Pure function of (organization profile, catalog state, as-of date). No LLM is
involved anywhere in this module. The result is a *screening aid*: it narrows
which frameworks an organization should look at and says why; it is not a
legal determination, and every result carries that statement.

Outcomes
  APPLICABLE              the customer selected it / a contract requires it, or
                          reviewed criteria are fully satisfied by the profile
  POTENTIALLY_APPLICABLE  jurisdictional nexus exists but the profile does not
                          contain enough facts to satisfy or rule out the criteria
  NOT_APPLICABLE          not in force on the date, no nexus, or a reviewed
                          criterion is contradicted by the profile
  REQUIRES_LEGAL_REVIEW   nexus exists but there are no reviewed criteria, the
                          framework is unverified, the nexus is cross-border, or
                          the criteria themselves demand counsel

A country match alone never yields APPLICABLE.
"""

from __future__ import annotations

from datetime import date
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .catalog import CRITERIA_LISTS
from .db import CatalogDb, CatalogError
from .registry import jurisdiction_closure

DISCLAIMER = (
    "Applicability results are a deterministic screening aid derived from the organization profile supplied and "
    "from reviewed catalog criteria. They are not legal advice or a legal determination of applicability."
)

Term = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_-]{1,63}$")]
Code = Annotated[str, StringConstraints(pattern=r"^[A-Z]{2,3}(-[A-Z0-9]{1,3})?$")]
FrameworkId = Annotated[str, StringConstraints(pattern=r"^[A-Z0-9][A-Z0-9-]{1,47}$")]


class OrganizationProfile(BaseModel):
    """``None`` means "not stated" (unknown); an empty list means "none"."""

    model_config = ConfigDict(extra="forbid")

    countries_of_operation: list[Code] = Field(min_length=1, max_length=300)
    data_processing_jurisdictions: list[Code] = Field(default_factory=list, max_length=300)
    industries: list[Term] | None = Field(default=None, max_length=50)
    organization_types: list[Term] | None = Field(default=None, max_length=50)
    regulated_activities: list[Term] | None = Field(default=None, max_length=100)
    system_scopes: list[Term] | None = Field(default=None, max_length=100)
    selected_frameworks: list[FrameworkId] = Field(default_factory=list, max_length=200)
    contractual_frameworks: list[FrameworkId] = Field(default_factory=list, max_length=200)
    as_of: date | None = None


def _in_force(fw: dict[str, Any], as_of: str) -> tuple[bool | None, str]:
    """True / False / None (cannot tell: dates were never verified)."""
    if fw["verification_status"] != "VERIFIED" or fw["lifecycle"] == "UNKNOWN":
        return None, "framework dates and status have not been verified against the official text"
    if not fw["effective_from"] or fw["effective_from"] > as_of:
        return False, f"not yet in force on {as_of}" + (f" (effective from {fw['effective_from']})" if fw["effective_from"] else "")
    if fw["effective_to"] and fw["effective_to"] <= as_of:
        why = f"{fw['lifecycle'].lower().replace('_', ' ')} from {fw['effective_to']}"
        if fw["superseded_by"]:
            why += f"; superseded by {fw['superseded_by']}"
        return False, why
    return True, f"in force on {as_of}"


def evaluate(db: CatalogDb, profile: OrganizationProfile) -> dict[str, Any]:
    as_of = (profile.as_of or date.today()).isoformat()
    try:
        reach: dict[str, list[str]] = {}       # jurisdiction -> how the profile reaches it
        for dimension, codes in (("OPERATION", profile.countries_of_operation),
                                 ("DATA_PROCESSING", profile.data_processing_jurisdictions)):
            for code in sorted(set(codes)):
                for hop in jurisdiction_closure(db, code, as_of):
                    path = f"{dimension}:{code}" + ("" if hop["via"] == "SELF" else f" via {hop['via']}")
                    reach.setdefault(hop["code"], []).append(path)
    except CatalogError as exc:
        raise CatalogError("UNKNOWN_JURISDICTION", exc.message) from exc

    selected, contractual = set(profile.selected_frameworks), set(profile.contractual_frameworks)
    known = {r["id"] for r in db.q("SELECT id FROM regulatory_framework")}
    results = []
    for fw in db.q("SELECT * FROM regulatory_framework ORDER BY id"):
        paths = sorted(reach.get(fw["jurisdiction_code"], []))
        nexus = sorted({p.split(":")[0] for p in paths})
        chosen = "CUSTOMER_SELECTED" if fw["id"] in selected else "CONTRACTUAL" if fw["id"] in contractual else None
        if not paths and not chosen and not fw["cross_border"]:
            continue  # unrelated to this profile; listing every framework on earth is noise
        criteria_row = db.one(
            "SELECT * FROM applicability_criteria WHERE framework_id=? AND status='APPROVED' AND published_seq IS NOT NULL",
            (fw["id"],))
        results.append(_decide(fw, as_of, paths, nexus, chosen, criteria_row, profile))

    unknown = sorted((selected | contractual) - known)
    return {
        "as_of": as_of,
        "disclaimer": DISCLAIMER,
        "jurisdictions_considered": {k: sorted(v) for k, v in sorted(reach.items())},
        "results": results,
        "unsupported_frameworks": [
            {"framework_id": f, "outcome": "REQUIRES_LEGAL_REVIEW",
             "reasons": ["framework is not registered in the catalog; no assessment is possible"]} for f in unknown],
    }


def _decide(fw: dict[str, Any], as_of: str, paths: list[str], nexus: list[str], chosen: str | None,
            criteria_row: dict[str, Any] | None, profile: OrganizationProfile) -> dict[str, Any]:
    reasons: list[str] = []
    basis: list[str] = []
    in_force, why = _in_force(fw, as_of)
    reasons.append(why)

    def result(outcome: str) -> dict[str, Any]:
        return {
            "framework_id": fw["id"], "title": fw["title"], "jurisdiction": fw["jurisdiction_code"],
            "adoption": fw["adoption"], "outcome": outcome, "basis": basis, "reasons": reasons,
            "jurisdiction_paths": paths,
            "criteria_id": criteria_row["id"] if criteria_row else None,
            "framework_verification_status": fw["verification_status"],
            "implements_framework_id": fw["implements_framework_id"],
        }

    if in_force is False:
        basis.append("NOT_IN_FORCE")
        return result("NOT_APPLICABLE")
    if chosen:
        # A voluntary/contractual commitment, not a statement about the law.
        basis.append(chosen)
        reasons.append("included because the customer selected it" if chosen == "CUSTOMER_SELECTED"
                       else "included because a contractual obligation names it")
        if in_force is None:
            reasons.append("its dates are unverified, so the applicable version cannot be confirmed")
        return result("APPLICABLE")
    if fw["adoption"] != "STATUTORY":
        basis.append("NOT_SELECTED")
        reasons.append(f"{fw['adoption'].lower()} framework that the customer has neither selected nor is contractually bound to")
        return result("NOT_APPLICABLE")
    if not paths:
        basis.append("CROSS_BORDER_SCOPE")
        reasons.append("framework can apply outside its territory; no territorial nexus was found in the profile")
        return result("REQUIRES_LEGAL_REVIEW")
    basis.append("JURISDICTIONAL_NEXUS")
    if in_force is None:
        basis.append("FRAMEWORK_UNVERIFIED")
        return result("REQUIRES_LEGAL_REVIEW")
    if criteria_row is None:
        basis.append("NO_REVIEWED_CRITERIA")
        reasons.append("jurisdictional nexus exists but no reviewed applicability criteria are published for this framework")
        return result("REQUIRES_LEGAL_REVIEW")

    c = criteria_row["criteria"]
    if not set(nexus) & set(c["nexus"]):
        basis.append("NEXUS_TYPE_NOT_COVERED")
        reasons.append(f"profile reaches this jurisdiction only through {nexus}, which the reviewed criteria do not address")
        return result("REQUIRES_LEGAL_REVIEW")
    if c["legal_review_required"]:
        basis.append("CRITERIA_REQUIRE_LEGAL_REVIEW")
        reasons.append(c["legal_review_note"] or "the reviewed criteria require legal review")
        return result("REQUIRES_LEGAL_REVIEW")
    if c["all_entities_in_jurisdiction"]:
        basis.append("REVIEWED_CRITERIA_ALL_ENTITIES")
        reasons.append("reviewed criteria state the framework covers all entities with this nexus")
        return result("APPLICABLE")

    unknown, matched, specified = [], [], 0
    for key in CRITERIA_LISTS:
        wanted = c[key]
        if wanted is None:
            continue
        specified += 1
        have = getattr(profile, key)
        if have is None:
            unknown.append(key)
        elif set(have) & set(wanted):
            matched.append(key)
            reasons.append(f"{key}: profile matches {sorted(set(have) & set(wanted))}")
        else:
            basis.append("CRITERION_NOT_MET")
            reasons.append(f"{key}: profile {sorted(have)} matches none of {wanted}")
            return result("NOT_APPLICABLE")
    if specified == 0:
        basis.append("COUNTRY_MATCH_ONLY")
        reasons.append("reviewed criteria contain no scoping conditions beyond jurisdiction; a country match alone is not sufficient")
        return result("POTENTIALLY_APPLICABLE")
    if unknown:
        basis.append("PROFILE_INCOMPLETE")
        reasons.append(f"profile does not state {unknown}, which the criteria depend on")
        return result("POTENTIALLY_APPLICABLE")
    basis.append("REVIEWED_CRITERIA_SATISFIED")
    return result("APPLICABLE")
