"""Deterministic text checks that decide what automation may approve and map
(the organization-profile applicability engine is ``regintel.applicability``).

Two questions, answered from the requirement's own quoted text and the position
of its section, never from model-assigned ``pam_domains``:

* **Is the passage operative?** Recitals (preamble) explain an act; they do not
  impose duties. A section is preamble when its reference says so (EUR-Lex
  HTML) or when it precedes the enacting formula ("HAVE ADOPTED THIS
  REGULATION/DIRECTIVE") of its document version (PDF pages).
* **Is it addressed to the regulated organization?** Duties of Member States,
  the Commission, supervisory bodies or CSIRTs, and rights of data subjects,
  are not privileged-account controls of the evaluated organization.

``mapping_gaps`` then states, per requirement, why no (or only a partial)
executable check exists. Codes are technical mapping observations, not
determinations of legal applicability.
"""

from __future__ import annotations

import os
import re
from typing import Any

from .db import CatalogDb

# ---------------------------------------------------------------- codes

NON_OPERATIVE_TEXT = "NON_OPERATIVE_TEXT"
OUTSIDE_PAM_SCOPE = "OUTSIDE_PAM_SCOPE"
MAPPING_MISSING = "MAPPING_MISSING"
POLICY_CONTEXT_REQUIRED = "POLICY_CONTEXT_REQUIRED"
NO_EXECUTABLE_RULE = "NO_EXECUTABLE_RULE"
COLLECTOR_MISSING = "COLLECTOR_MISSING"
PARTIAL_COVERAGE = "PARTIAL_COVERAGE"
GAP_CODES = (NON_OPERATIVE_TEXT, OUTSIDE_PAM_SCOPE, MAPPING_MISSING, POLICY_CONTEXT_REQUIRED, NO_EXECUTABLE_RULE,
             COLLECTOR_MISSING, PARTIAL_COVERAGE)

# Rules whose evidence the PAM (Django) bridge actually collects. Automation never maps a
# requirement to any other rule: the check could not run on real evidence. Extend only
# after the collector schema is agreed with the Django side.
DEFAULT_BRIDGE_COLLECTED_RULES = ("PAM-ROTATION-001", "PAM-DORMANT-001", "PAM-SESSREC-001")


def bridge_collected_rules() -> tuple[str, ...]:
    raw = os.environ.get("OPM_REGINTEL_BRIDGE_COLLECTED_RULES", "").strip()
    if not raw:
        return DEFAULT_BRIDGE_COLLECTED_RULES
    return tuple(sorted({r.strip() for r in raw.split(",") if r.strip()}))


# ---------------------------------------------------------------- operative position

_ENACTING = re.compile(r"\bHA(?:VE|S)\s+ADOPTED\s+THIS\s+(?:REGULATION|DIRECTIVE|DECISION)\b")
_PREAMBLE_REF = re.compile(r"\(preamble\)|\brecitals?\b", re.I)
_WS = re.compile(r"\s+")


def _norm(text: str) -> str:
    return _WS.sub(" ", text).strip()


def enacting_position(db: CatalogDb, version_id: int) -> tuple[int, int] | None:
    """(section ordinal, character offset in normalized text) of the enacting formula, if any."""
    for s in db.q("SELECT ordinal, text FROM document_section WHERE version_id=? ORDER BY ordinal", (version_id,)):
        m = _ENACTING.search(_norm(s["text"]))
        if m:
            return s["ordinal"], m.end()
    return None


def section_is_operative(section: dict[str, Any], enacting: tuple[int, int] | None,
                         quote: str | None = None) -> tuple[bool, str]:
    """(operative?, reason). ``quote`` locates the passage inside the enacting section."""
    if _PREAMBLE_REF.search(section.get("section_ref") or "") or _PREAMBLE_REF.search(section.get("heading") or ""):
        return False, f"section {section.get('section_ref')!r} is part of the preamble (recitals)"
    if enacting is None:
        return True, "no enacting formula in this version; position-based recital detection not applicable"
    ordinal, offset = enacting
    if section["ordinal"] < ordinal:
        return False, f"section {section.get('section_ref')!r} precedes the enacting formula (recitals)"
    if section["ordinal"] == ordinal:
        if quote is None:
            return True, "section contains the enacting formula; operative text follows it"
        at = _norm(section["text"]).find(_norm(quote))
        if at < 0 or at < offset:
            return False, "the passage is located before the enacting formula (recitals) or could not be located"
    return True, "operative part of the act"


# ---------------------------------------------------------------- addressee

_PUBLIC_BODY = (r"Member States?|(?:the\s+)?Commission|ENISA|(?:the\s+)?CSIRTs?(?:\s+network)?|"
                r"(?:national\s+)?(?:competent|supervisory|designated)\s+authorit(?:y|ies)|"
                r"(?:the\s+)?(?:Cooperation Group|Board|ESAs|EBA|EIOPA|ESMA|Lead Overseer|single points? of contact)")
_ADDRESSEE_PUBLIC = re.compile(
    rf"^(?:[^,.;]{{0,80}},\s*)?(?:the\s+|all\s+|each\s+)?(?:{_PUBLIC_BODY})\b[^.;]{{0,60}}?"
    r"\b(?:shall|should|must|may|are|is|will|have|has)\b", re.I)
_DATA_SUBJECT_RIGHT = re.compile(r"\bdata subjects?\b[^.;]{0,60}\b(?:right|entitled)\b", re.I)


def addressee_problem(quote: str) -> str | None:
    text = _norm(quote)
    m = _ADDRESSEE_PUBLIC.match(text)
    if m:
        return f"the passage is addressed to a public body ({m.group(0)[:60]!r}), not to the evaluated organization"
    if _DATA_SUBJECT_RIGHT.search(text):
        return "the passage grants a data-subject right; it is not a privileged-account control"
    return None


_MODAL = re.compile(r"\b(?:shall|should|must)\b")


_SUBJECT_PUBLIC = re.compile(rf"\b(?:{_PUBLIC_BODY})$", re.I)


def lead_in(section_text: str, quote: str) -> str | None:
    """For a list-point quote ("implement policies ..."), the subject words right before the
    modal of the introducing clause ("... financial entities" in "..., financial entities shall:")."""
    text, q = _norm(section_text), _norm(quote)
    at = text.find(q)
    if at <= 0:
        return None
    modals = list(_MODAL.finditer(text[:at]))
    if not modals:
        return None
    subject = text[:modals[-1].start()].rstrip(" ,")
    return subject[-80:] or None


def lead_in_problem(section_text: str, quote: str) -> str | None:
    subject = lead_in(section_text, quote)
    if subject and _SUBJECT_PUBLIC.search(subject):
        return (f"the list point belongs to a clause addressed to a public body ('...{subject[-40:]} shall'), "
                "not to the evaluated organization")
    return None


_LICENSING = re.compile(
    r"\b(?:copyright|all rights reserved|available free of charge|is (?:in|part of) the public domain|"
    r"not subject to copyright|permission to (?:reproduce|copy)|licen[cs]ed under|creative commons|"
    r"this publication is available|may be used (?:by|for) [^.;]{0,40}without (?:restriction|permission)|"
    r"official (?:version|text) of (?:this|the) publication)\b", re.I)


def assess(db: CatalogDb, req: dict[str, Any], *, _cache: dict[int, Any] | None = None) -> list[dict[str, str]]:
    """Problems that bar automated approval or mapping (empty = operative and in PAM scope)."""
    section = db.one("SELECT * FROM document_section WHERE id=?", (req["section_id"],)) if req.get("section_id") else None
    problems: list[dict[str, str]] = []
    if section is not None:
        vid = section["version_id"]
        if _cache is not None and vid in _cache:
            enacting = _cache[vid]
        else:
            enacting = enacting_position(db, vid)
            if _cache is not None:
                _cache[vid] = enacting
        ok, why = section_is_operative(section, enacting, req["original_text"])
        if not ok:
            problems.append({"code": NON_OPERATIVE_TEXT, "message": why})
    if _LICENSING.search(req["original_text"] or ""):
        problems.append({"code": NON_OPERATIVE_TEXT, "message": "licensing, copyright or document-provenance "
                         "statement about the publication itself; it imposes no PAM duty"})
    who = addressee_problem(req["original_text"])
    quote = _norm(req["original_text"])
    if who is None and section is not None and quote[:1].islower():
        who = lead_in_problem(section["text"], quote)
    if who:
        problems.append({"code": OUTSIDE_PAM_SCOPE, "message": who})
    return problems


# ---------------------------------------------------------------- tested behaviour

_DAYS = re.compile(r"(\d{1,4})\s*(?:calendar\s+)?(?:days?|tag(?:e|en)?)\b", re.IGNORECASE)

# (topic, pattern over the quote, rule or None, parameter names whose value must come from the text)
TOPICS: tuple[tuple[str, re.Pattern[str], str | None, tuple[str, ...]], ...] = (
    ("credential rotation",
     re.compile(r"\b(?:passwords?|credentials?|secrets?|Zugangsdaten|Passw[oö]rt\w*)\b[^.;]{0,60}"
                r"\b(?:rotat\w*|chang\w*|renew\w*|ändern|wechseln)|\b(?:rotat\w*|chang\w*)\b[^.;]{0,30}"
                r"\b(?:passwords?|credentials?|secrets?)\b", re.I),
     "PAM-ROTATION-001", ("max_rotation_age_days",)),
    ("dormant accounts",
     re.compile(r"\b(?:dormant|inactiv\w*|unused|ungenutzt\w*)\b[^.;]{0,40}\baccounts?\b|\baccounts?\b[^.;]{0,40}"
                r"\b(?:dormant|inactiv\w*|unused)\b|\b(?:access|accounts?)\b[^.;]{0,60}\b(?:disabled|removed|revoked|"
                r"deactivated)\b[^.;]{0,30}\bdays? of inactivity\b", re.I),
     "PAM-DORMANT-001", ("dormant_after_days",)),
    ("privileged session recording",
     re.compile(r"\b(?:record\w*|aufzeichn\w*)\b[^.;]{0,40}\bsessions?\b|\bsessions?\b[^.;]{0,40}\b(?:record\w*|"
                r"aufzeichn\w*)|\bcontent of (?:a |the )?user sessions?\b|\bsession audit\b", re.I),
     "PAM-SESSREC-001", ()),
    ("approval of privileged access",
     re.compile(r"\bapprov\w*\b[^.;]{0,60}\baccess\b|\baccess\b[^.;]{0,80}\bapprov\w*", re.I),
     "PAM-APPROVAL-001", ("max_approval_age_hours",)),
    ("periodic access review",
     re.compile(r"\breview\w*\b[^.;]{0,40}\baccess\s+(?:rights|privileges|permissions)|\baccess\s+(?:rights|"
                r"privileges)\b[^.;]{0,40}\breview", re.I),
     "PAM-REVIEW-001", ("review_interval_days",)),
    ("failed authentication attempts",
     re.compile(r"\b(?:failed|unsuccessful|invalid)\b(?!\s+device\b)[^.;]{0,30}\b(?:log-?ins?|logons?|"
                r"authentication|attempts)\b", re.I),  # device-logon purge (e.g. NIST AC-7(2)) is not PAM logon
     "PAM-AUTHFAIL-001", ("max_failed_attempts", "window_minutes", "lockout_is_mitigation")),
    # Actual accesses joined to the entitlement in force at access time. Approval alone is not authorization.
    ("access authorization at access time",
     re.compile(r"\bvalid access authori[sz]ation\b", re.I), "PAM-UNAUTH-001", ()),
    ("break-glass / emergency access",
     re.compile(r"\b(?:break-?glass|emergency\s+access)\b", re.I), "PAM-BREAKGLASS-001",
     ("min_justification_length", "require_ticket_reference", "post_review_within_hours")),
    # MFA at access (event history). A configuration snapshot (PAM-MFACFG-001) does not show that
    # MFA was performed, and failed-logon monitoring (PAM-AUTHFAIL-001) is not MFA.
    ("multi-factor authentication",
     re.compile(r"\b(?:multi-?factor|two-?factor|2fa|mfa)\b", re.I), "PAM-MFAACC-001", ("accepted_methods",)),
    ("strong authentication",
     re.compile(r"\bstrong\b[^.;]{0,20}\bauthenticat\w*", re.I), None, ()),
    ("privileged session idle limit",
     re.compile(r"\b(?:idle|inactiv\w*)\b[^.;]{0,40}\bsessions?\b|\bsessions?\b[^.;]{0,60}\b(?:idle|inactiv\w*)\b|"
                r"\bsession\s+lock\w*", re.I), "PAM-SESSIDLE-001", ("max_idle_minutes",)),
    ("privileged session duration limit",
     re.compile(r"\bsessions?\b[^.;]{0,40}\b(?:duration|length|time-?limit\w*)\b|\btime-?limited\s+sessions?\b",
                re.I), "PAM-SESSDUR-001", ("max_session_minutes",)),
    ("mfa configuration enforcement",
     re.compile(r"\b(?:mfa|multi-?factor|2fa)\s+(?:configuration|enforce\w*|policy|required for all)\b", re.I),
     "PAM-MFACFG-001", ("accepted_methods",)),
    ("policy or SoD exception approval",
     re.compile(r"\b(?:policy|sod|segregation of duties)\s+exceptions?\b", re.I),
     "PAM-EXCEPTION-001", ()),
    ("password policy configuration",
     re.compile(r"\bpassword\s+policy\b|\bpassword\s+(?:length|complexity|history)\b", re.I),
     "PAM-PWDCFG-001", ()),
    ("audit log forwarding and export",
     re.compile(r"\baudit\s+(?:forwarding|export|offload|siem|syslog)\b", re.I),
     "PAM-AUDCFG-001", ()),
    ("backup configuration and encryption",
     re.compile(r"\bbackups?\s+(?:schedul\w*|encrypt\w*|configuration)\b", re.I),
     "PAM-BKPCFG-001", ()),
    ("endpoint privilege elevation",
     re.compile(r"\b(?:endpoint|workstation)\s+(?:elevation|privilege\s+elevation)\b|\belevated\s+execution\b", re.I),
     "PAM-ENDELEV-001", ()),
    ("local administrator membership",
     re.compile(r"\blocal\s+admin(?:istrator)?\s+membership\b|\blocal\s+administrators\s+group\b", re.I),
     "PAM-LOCADM-001", ()),
    ("application control allowlist policy",
     re.compile(r"\bapplication\s+(?:control|allowlist\w*|whitelisting|blocklist\w*)\b", re.I),
     "PAM-APPCTRL-001", ()),
    ("cryptographic protection",
     re.compile(r"\b(?:cryptograph\w*|encrypt\w*)\b", re.I), None, ()),
    ("change management",
     re.compile(r"\bchange\s+management\b", re.I), None, ()),
    # Behaviours that existing rules do NOT test; named so the gap says so instead of guessing a rule.
    ("event-triggered authenticator change (age-based rotation does not test it)",
     re.compile(r"\b(?:chang\w*|refresh\w*)\b[^.;]{0,30}\bauthenticators?\b[^.;]{0,80}\b(?:membership|events?)\b",
                re.I), None, ()),
    ("temporary and emergency account expiry (dormancy does not test it)",
     re.compile(r"\btemporary and emergency accounts?\b", re.I), None, ()),
    ("mobile device purge or wipe",
     re.compile(r"\b(?:purge|wipe)\b[^.;]{0,80}\bmobile devices?\b", re.I), None, ()),
    ("separation of duties",
     re.compile(r"\b(?:separation|segregation) of duties\b|\bduties of individuals requiring separation\b", re.I),
     None, ()),
    ("password composition and blocklists",
     re.compile(r"\bcomposition and complexity\b|\bcommonly-used, expected, or compromised passwords\b", re.I),
     None, ()),
    ("audit record content, review, retention or protection (beyond log completeness)",
     re.compile(r"\baudit (?:records?|information|logging)\b", re.I), None, ()),
)

# NIST-style organization-defined parameters: "[Assignment: organization-defined ...]" and
# "[Selection: ...]". The standard leaves these to the organization; they are never filled in.
_ODP = re.compile(r"\[(?:Assignment|Selection)[^\]]{0,400}\]", re.I)


def organization_defined(text: str) -> list[str]:
    return [_norm(m.group(0)) for m in _ODP.finditer(text or "")]


_MINUTES = re.compile(r"(\d{1,5})\s*(?:minutes?|mins?|Minuten)\b", re.IGNORECASE)
_HOURS = re.compile(r"(\d{1,4})\s*(?:hours?|Stunden)\b", re.IGNORECASE)
# The unit a parameter's value must literally be stated in; other parameters are never read from text.
PARAMETER_UNITS = {"max_rotation_age_days": _DAYS, "dormant_after_days": _DAYS, "review_interval_days": _DAYS,
                   "max_idle_minutes": _MINUTES, "max_session_minutes": _MINUTES, "window_minutes": _MINUTES,
                   "max_approval_age_hours": _HOURS, "post_review_within_hours": _HOURS}


def stated_value(req: dict[str, Any], parameter: str) -> int | None:
    """A value for ``parameter`` stated literally (in its own unit) in the requirement's verified thresholds."""
    pattern = PARAMETER_UNITS.get(parameter)
    if pattern is None:
        return None
    if pattern is _DAYS:
        return stated_days(req)
    for t in req.get("thresholds") or []:
        m = pattern.search(t.get("value_text", ""))
        if m:
            return int(m.group(1))
    return None


def unstated_parameters(req: dict[str, Any], params: tuple[str, ...]) -> list[str]:
    return [p for p in params if stated_value(req, p) is None]


def topics(quote: str) -> list[tuple[str, str | None, tuple[str, ...]]]:
    return [(name, rule, params) for name, pattern, rule, params in TOPICS if pattern.search(quote)]


def stated_days(req: dict[str, Any]) -> int | None:
    """A day count stated literally in the requirement (thresholds were verified to occur in the quote)."""
    for t in req.get("thresholds") or []:
        m = _DAYS.search(t.get("value_text", ""))
        if m and 1 <= int(m.group(1)) <= 730:
            return int(m.group(1))
    return None


def mapping_gaps(db: CatalogDb, req: dict[str, Any], *, mapped_rules: list[str], bundle_rules: set[str],
                 collected: tuple[str, ...] | None = None, _cache: dict[int, Any] | None = None
                 ) -> list[dict[str, Any]]:
    """Structured reasons why a requirement has no, or only partial, executable coverage."""
    collected = bridge_collected_rules() if collected is None else collected
    out: list[dict[str, Any]] = []
    for p in assess(db, req, _cache=_cache):
        out.append({"code": p["code"], "reason": p["message"]})
    if out:  # not an operative duty of the organization: nothing to map, even partially
        return out
    text = req["translation_en"] or req["original_text"]
    found = topics(text)
    odps = organization_defined(text)
    for rule in mapped_rules:
        out.append({"code": PARTIAL_COVERAGE, "rule_id": rule,
                    "reason": "the executable rule tests the recorded PAM control only; the remaining (organizational, "
                              "procedural or broader technical) content of the passage is not assessed"})
    for name, rule, params in found:
        if rule is not None and rule in mapped_rules:
            continue
        if rule is None:
            out.append({"code": NO_EXECUTABLE_RULE, "topic": name,
                        "reason": f"no rule in the bundle tests {name}"})
        elif rule not in bundle_rules:
            out.append({"code": NO_EXECUTABLE_RULE, "topic": name, "rule_id": rule,
                        "reason": f"{rule} ({name}) is not in the running bundle"})
        elif rule not in collected:
            out.append({"code": COLLECTOR_MISSING, "topic": name, "rule_id": rule,
                        "reason": f"{rule} exists but the PAM bridge supplies no evidence for it; a collector schema "
                                  "must be agreed with the Django side before it can be mapped"})
        elif unstated_parameters(req, params):
            missing = unstated_parameters(req, params)
            out.append({"code": POLICY_CONTEXT_REQUIRED, "topic": name, "rule_id": rule, "parameters": missing,
                        "reason": f"the passage states no value for {', '.join(missing)}; a rule default or company "
                                  "policy is not a legal threshold. Needs a documented, versioned policy source "
                                  "(organization policy context, provenance CUSTOMER_POLICY)",
                        **({"organization_defined": odps} if odps else {})})
        elif odps and rule not in mapped_rules:
            out.append({"code": POLICY_CONTEXT_REQUIRED, "topic": name, "rule_id": rule, "parameters": [],
                        "organization_defined": odps,
                        "reason": "the passage leaves its selectors, values or circumstances to the organization "
                                  "(organization-defined parameters); the targets and settings must come from a "
                                  "documented, versioned policy source (organization policy context, provenance "
                                  "CUSTOMER_POLICY) before the rule can be bound"})
        else:
            out.append({"code": MAPPING_MISSING, "topic": name, "rule_id": rule,
                        "reason": "a collected rule may apply but the deterministic policy found no qualifying signal "
                                  "(e.g. not mandatory or not about privileged accounts); needs a human mapping decision"})
    if not out:
        out.append({"code": MAPPING_MISSING,
                    "reason": "no PAM-testable behaviour was identified in the passage text; needs a human mapping "
                              "decision (MANUAL assessment or a new rule and collector)"})
    return out
