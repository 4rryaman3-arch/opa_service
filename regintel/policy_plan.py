"""Organization policy bindings inside an evaluation plan (provenance CUSTOMER_POLICY).

Selected policy versions are bound to the plan's requirements without changing
any regulatory row, mapping or threshold:

  * a policy control only resolves a POLICY_CONTEXT_REQUIRED gap for the rule it
    pins (``addresses_gap_rules``); a requirement that already has a published
    regulatory mapping for that rule keeps it, and the company value is never
    applied to it;
  * COLLECTOR_MISSING, NO_EXECUTABLE_RULE, PARTIAL_COVERAGE, MAPPING_MISSING and
    the applicability gates stay open and visible;
  * every binding is checked against the pinned control definition, the pinned
    rule version in the running bundle, the organization's collector handshake,
    effective dates (with deterministic supersession) and target overlaps.

Policy codes
  POLICY_CONFLICT               overlapping targets and time, different parameters
  POLICY_SCOPE_UNRESOLVED       overlap cannot be decided without (historical) membership
  POLICY_CONTEXT_NOT_EFFECTIVE  part of the reporting period has no policy in force
"""
from __future__ import annotations

from typing import Any, Callable

from app.models.common import format_utc

from . import mapping_policy as mp, policy_contexts as pctx, policy_controls as pc
from .db import CatalogDb, CatalogError, digest_of
from .plan import parameter_problems

POLICY_CONFLICT = "POLICY_CONFLICT"
POLICY_SCOPE_UNRESOLVED = "POLICY_SCOPE_UNRESOLVED"
POLICY_CONTEXT_NOT_EFFECTIVE = "POLICY_CONTEXT_NOT_EFFECTIVE"
POLICY_CODES = (POLICY_CONFLICT, POLICY_SCOPE_UNRESOLVED, POLICY_CONTEXT_NOT_EFFECTIVE)
RESOLVED, PARTIALLY_RESOLVED, BLOCKED, OPEN = "RESOLVED_BY_POLICY", "PARTIALLY_RESOLVED", "BLOCKED", "OPEN"


def load_versions(db: CatalogDb, ids: list[str], scope: str, tenant: str) -> list[dict[str, Any]]:
    rows = []
    for vid in sorted(set(ids)):
        row = db.one("SELECT * FROM policy_context_version WHERE id=?", (vid,))
        if row is None or row["organization_scope"] != scope or row["tenant_id"] != tenant:
            raise CatalogError("UNKNOWN_POLICY_VERSION", "Policy version not found in this organization scope.",
                               details={"policy_version_id": vid})
        rows.append(row)
    return rows


# ---------------------------------------------------------------- targets


def _members(target: dict[str, Any], window: tuple[str, str], resolutions: dict[tuple[str, str], dict[str, Any]]
             ) -> set[tuple[str, str]] | None:
    """Member set of a target during ``window`` (None when unknown)."""
    kind = pc.TARGET_TYPES[target["type"]]["kind"]
    if kind == "LEAF":
        return {(target["type"], target["id"])}
    res = resolutions.get((target["type"], target.get("id") or ""))
    if res is None or not res["complete"] or res["valid_from"] > window[0] or (res["valid_to"] or pctx.FOREVER) < window[1]:
        return None  # no complete membership covering the whole window (e.g. only current membership known)
    return {(m["type"], m["id"]) for m in res["members"]}


def _pair_overlap(a: dict[str, Any], b: dict[str, Any], window: tuple[str, str],
                  resolutions: dict[tuple[str, str], dict[str, Any]]) -> bool | None:
    if a == b or "ORGANIZATION" in (a["type"], b["type"]):
        return True
    ka, kb = pc.TARGET_TYPES[a["type"]]["kind"], pc.TARGET_TYPES[b["type"]]["kind"]
    if ka == kb == "LEAF" and a["type"] == b["type"]:
        return False
    ma, mb = _members(a, window, resolutions), _members(b, window, resolutions)
    if ma is None or mb is None:
        return None
    if {t for t, _ in ma} != {t for t, _ in mb} and ma and mb:
        return None  # e.g. accounts vs resources: related only through PAM data OPM does not hold
    return bool(ma & mb)


def targets_overlap(ta: list[dict[str, Any]], tb: list[dict[str, Any]], window: tuple[str, str],
                    resolutions: dict[tuple[str, str], dict[str, Any]]) -> bool | None:
    unknown = False
    for a in ta:
        for b in tb:
            r = _pair_overlap(a, b, window, resolutions)
            if r:
                return True
            unknown = unknown or r is None
    return None if unknown else False


def _intersect(a: list[tuple[str, str]], b: list[tuple[str, str]]) -> list[tuple[str, str]]:
    out = []
    for x0, x1 in a:
        for y0, y1 in b:
            s, e = max(x0, y0), min(x1, y1)
            if s < e:
                out.append((s, e))
    return sorted(out)


# ---------------------------------------------------------------- resolution


def resolve(db: CatalogDb, plan: dict[str, Any], *, engine: Any, scope: str, tenant: str, version_ids: list[str],
            period: tuple[str, str], resolutions: list[dict[str, Any]], cap: dict[str, Any],
            rule_active: Callable[[str], bool] | None = None) -> dict[str, Any]:
    """Policy section of a plan plus per-requirement gap resolution. Mutates ``plan``
    additively (requirements[].policy_resolution, digest_input.policy_context)."""
    selected = load_versions(db, version_ids, scope, tenant)
    res_index = {(r["target"]["type"], r["target"].get("id") or ""): r for r in resolutions}
    blockers: dict[str, dict[str, Any]] = {}

    def block(binding: dict[str, Any], code: str, message: str, **detail: Any) -> None:
        binding["blocker_codes"].append(code)
        binding["blocker_details"].append({"code": code, "message": message, **detail})
        entry = blockers.setdefault(code, {"code": code, "message": message, "binding_ids": []})
        if binding["binding_id"] not in entry["binding_ids"]:
            entry["binding_ids"].append(binding["binding_id"])

    context_versions: dict[str, int] = {}
    bindings: list[dict[str, Any]] = []
    versions_out = []
    for v in selected:
        all_versions = pctx.versions_of(db, v["context_id"])
        context_versions[v["context_id"]] = all_versions[-1]["version"]
        in_force = pctx.clip(pctx.winning_intervals(all_versions)[v["version"]], *period)
        versions_out.append({"policy_version_id": v["id"], "policy_context_id": v["context_id"],
                             "version": v["version"], "digest": v["digest"], "title": v["title"],
                             "effective_from": v["effective_from"], "effective_to": v["effective_to"],
                             "in_force_in_period": [{"start": a, "end": b} for a, b in in_force]})
        for entry in v["policy_controls"]:
            defn = pc.get(entry["control_id"], entry["control_version"])
            b = {"binding_id": f"{v['id']}#{entry['entry_id']}", "provenance": pctx.ORIGIN,
                 "policy_version_id": v["id"], "policy_context_id": v["context_id"], "policy_version": v["version"],
                 "policy_version_digest": v["digest"], "policy_effective_from": v["effective_from"],
                 "policy_effective_to": v["effective_to"], "control_id": entry["control_id"],
                 "control_version": entry["control_version"],
                 "control_definition_digest": entry["control_definition_digest"],
                 "assessment_mode": defn["assessment_mode"] if defn else None,
                 "control_parameters": entry["parameters"], "targets": entry["targets"],
                 "target_set_digest": "sha256:" + digest_of(entry["targets"]),
                 "rule_id": None, "rule_version": None, "evidence_type": None, "evidence_schema_version": None,
                 "rule_parameters": None, "windows": in_force, "blocker_codes": [], "blocker_details": [],
                 "addresses_requirement_ids": [], "execution_ids": []}
            bindings.append(b)
            if defn is None:
                block(b, "CONTROL_DEFINITION_UNAVAILABLE", "The pinned control version is not in this OPM release.")
                continue
            if defn["definition_digest"] != entry["control_definition_digest"]:
                block(b, "CONTROL_DEFINITION_CHANGED", "The pinned control definition changed; save a new version.")
            if not defn["bindings"]:
                block(b, mp.NO_EXECUTABLE_RULE, "Documented policy only: no rule implements this control.")
                continue
            rb = defn["bindings"][0]
            b.update(rule_id=rb["rule_id"], rule_version=rb["rule_version"], evidence_type=rb["evidence_type"],
                     evidence_schema_version=rb["evidence_schema_version"],
                     rule_parameters={rb["parameter_map"][k]: val for k, val in entry["parameters"].items()},
                     addresses_gap_rules=defn["addresses_gap_rules"])
            support = pc.binding_support(rb, cap, engine)
            for code in support["blocker_codes"]:
                block(b, code, {"COLLECTOR_MISSING": "The organization's collector does not declare this evidence "
                                                     "type; the control cannot be assessed end to end.",
                                "EVIDENCE_SCHEMA_INCOMPATIBLE": "The collector declared a different evidence schema "
                                                                "version than the pinned rule needs.",
                                "RULE_NOT_IN_BUNDLE": "The pinned rule version is not in the running bundle.",
                                "RULE_CONTRACT_MISMATCH": "The pinned rule's evidence or parameters changed."}[code],
                      evidence_type=rb["evidence_type"])
            spec = engine.rules.get(rb["rule_id"], {}).get(rb["rule_version"])
            if spec is not None:
                if spec.status != "ACTIVE":
                    block(b, "RULE_VERSION_UNAVAILABLE", f"{spec.rule_id} {spec.version} is {spec.status}.")
                rule_window = [(format_utc(spec.effective_from),
                                format_utc(spec.effective_to) if spec.effective_to else pctx.FOREVER)]
                outside = [w for w in b["windows"] if not _intersect([w], rule_window) == [w]]
                b["windows"] = _intersect(b["windows"], rule_window)
                if outside:
                    b["rule_not_effective"] = [{"start": a, "end": e} for a, e in outside]
                problems = parameter_problems(spec, b["rule_parameters"], {})
                if problems:
                    block(b, "PARAMETERS_INCOMPATIBLE", "; ".join(m for _, m in problems))
                if rule_active is not None and not rule_active(spec.rule_id):
                    block(b, "RULE_INACTIVE_FOR_TENANT", f"{spec.rule_id} is deactivated for this tenant.")
            if not b["windows"]:
                block(b, POLICY_CONTEXT_NOT_EFFECTIVE, "The policy version is not in force (or is superseded) at any "
                                                       "time in the reporting period.")

    # ---- conflicts between bindings of the same rule
    by_rule: dict[str, list[dict[str, Any]]] = {}
    for b in bindings:
        if b["rule_id"]:
            by_rule.setdefault(b["rule_id"], []).append(b)
    for rule_id, group in sorted(by_rule.items()):
        for i, a in enumerate(group):
            for c in group[i + 1:]:
                if a["rule_parameters"] == c["rule_parameters"]:
                    continue
                for window in _intersect(a["windows"], c["windows"]):
                    overlap = targets_overlap(a["targets"], c["targets"], window, res_index)
                    if overlap is False:
                        continue
                    code = POLICY_CONFLICT if overlap else POLICY_SCOPE_UNRESOLVED
                    msg = ("Overlapping targets carry different parameter values for the same rule in the same period."
                           if overlap else "Whether the targets overlap depends on membership OPM was not given "
                                           "(complete, covering the period); supply target_resolutions.")
                    for x, y in ((a, c), (c, a)):
                        if code not in x["blocker_codes"]:
                            block(x, code, msg, with_binding_id=y["binding_id"],
                                  window={"start": window[0], "end": window[1]})
                    break

    # ---- executions (one per usable binding and in-force window)
    executions: dict[str, dict[str, Any]] = {}
    for b in bindings:
        if b["blocker_codes"] or not b["rule_id"]:
            continue
        for start, end in b["windows"]:
            identity = {"rule_id": b["rule_id"], "rule_version": b["rule_version"], "parameters": b["rule_parameters"],
                        "binding_id": b["binding_id"], "policy_version_digest": b["policy_version_digest"],
                        "target_set_digest": b["target_set_digest"], "reporting_period": {"start": start, "end": end}}
            eid = "pexec-" + digest_of(identity)[:16]
            spec = engine.rules[b["rule_id"]][b["rule_version"]]
            executions[eid] = {
                "execution_id": eid, "provenance": pctx.ORIGIN, **identity,
                "evidence_type": b["evidence_type"], "evidence_schema_version": b["evidence_schema_version"],
                "evidence_requirements": list(spec.evidence_requirements), "assessment_mode": b["assessment_mode"],
                "control_id": b["control_id"], "control_version": b["control_version"],
                "policy_version_id": b["policy_version_id"], "policy_context_id": b["policy_context_id"],
                "targets": b["targets"],
                "evaluate_request": {
                    "rule_id": b["rule_id"], "rule_version": b["rule_version"],
                    "reporting_period": {"start": start, "end": end},
                    "policy_settings": {"policy_version": b["policy_version_id"],
                                        "effective_from": b["policy_effective_from"],
                                        **({"effective_to": b["policy_effective_to"]} if b["policy_effective_to"] else {}),
                                        "parameters": b["rule_parameters"]}},
                "evidence_partition": {
                    "include": "records of objects that are members of any of 'targets' during reporting_period, as "
                               "resolved by Django inside the organization",
                    "expected_record_count": "the size of that frozen member set (completeness.expected_record_count)",
                    "target_set_digest": b["target_set_digest"]},
                "requirement_ids": []}
            b["execution_ids"].append(eid)

    # ---- per-requirement gap resolution
    collected = pc.collected_rules(cap, engine)
    bundle_rules = set(engine.rules)
    cache: dict[int, Any] = {}
    whole = period
    for r in plan["requirements"]:
        req = db.one("SELECT * FROM regulatory_requirement WHERE id=?", (r["requirement_id"],))
        mapped = sorted({m["rule_id"] for m in r["mappings"] if m["execution_id"]})
        gaps = mp.mapping_gaps(db, req, mapped_rules=mapped, bundle_rules=bundle_rules, collected=collected,
                               _cache=cache) if req else []
        out_gaps, req_execs = [], []
        for g in gaps:
            rule = g.get("rule_id")
            cands = [b for b in bindings if rule and b["rule_id"] == rule and rule in b.get("addresses_gap_rules", [])]
            entry = {**g, "status": OPEN, "policy_codes": [], "binding_ids": [b["binding_id"] for b in cands],
                     "uncovered_intervals": [], "target_coverage": None}
            if g["code"] == mp.POLICY_CONTEXT_REQUIRED and cands:
                usable = [b for b in cands if not b["blocker_codes"]]
                for b in cands:
                    if r["requirement_id"] not in b["addresses_requirement_ids"]:
                        b["addresses_requirement_ids"].append(r["requirement_id"])
                covered = sorted(w for b in usable for w in b["windows"])
                uncovered = pctx.subtract(whole, covered)
                org_wide = [w for b in usable if any(t["type"] == "ORGANIZATION" for t in b["targets"])
                            for w in b["windows"]]
                entry["uncovered_intervals"] = [{"start": a, "end": e} for a, e in uncovered]
                entry["target_coverage"] = ("ORGANIZATION" if not pctx.subtract(whole, sorted(org_wide))
                                            else "SELECTED_TARGETS" if usable else None)
                entry["policy_codes"] = sorted({c for b in cands for c in b["blocker_codes"]}
                                               | ({POLICY_CONTEXT_NOT_EFFECTIVE} if uncovered and usable else set()))
                if not usable:
                    entry["status"] = BLOCKED
                elif uncovered or entry["target_coverage"] != "ORGANIZATION":
                    entry["status"] = PARTIALLY_RESOLVED
                else:
                    entry["status"] = RESOLVED
                for b in usable:
                    for eid in b["execution_ids"]:
                        req_execs.append(eid)
                        if r["requirement_id"] not in executions[eid]["requirement_ids"]:
                            executions[eid]["requirement_ids"].append(r["requirement_id"])
            elif cands:  # a policy exists but cannot close this gap (e.g. no collector)
                entry["policy_codes"] = sorted({c for b in cands for c in b["blocker_codes"]})
            out_gaps.append(entry)
            if entry["status"] in (RESOLVED, PARTIALLY_RESOLVED):
                # the policy-bound rule tests its PAM control only, exactly like a regulatory mapping
                out_gaps.append({"code": mp.PARTIAL_COVERAGE, "rule_id": rule, "status": OPEN, "policy_codes": [],
                                 "binding_ids": entry["binding_ids"], "uncovered_intervals": [],
                                 "target_coverage": None,
                                 "reason": "the policy-bound rule tests the recorded PAM control only; the remaining "
                                           "content of the passage (other conditions, organizational or procedural "
                                           "aspects) is not assessed"})
        statuses = {g["status"] for g in out_gaps}
        r["policy_resolution"] = {
            "gaps": out_gaps, "policy_execution_ids": sorted(set(req_execs)),
            "summary": ("NO_GAPS" if not out_gaps else RESOLVED if statuses == {RESOLVED}
                        else PARTIALLY_RESOLVED if statuses & {RESOLVED, PARTIALLY_RESOLVED} else OPEN)}

    for b in bindings:
        if not b["addresses_requirement_ids"]:
            b["unused_reason"] = ("NO_MATCHING_GAP: no published requirement of this framework has a "
                                  "POLICY_CONTEXT_REQUIRED gap this control resolves (regulatory thresholds are never "
                                  "replaced by company values)")
            b["execution_ids"] = []  # never run: it is linked to no requirement of this framework
        b["windows"] = [{"start": a, "end": e} for a, e in b["windows"]]
    used = {e for b in bindings for e in b["execution_ids"]}
    plan_execs = [executions[e] for e in sorted(used)]
    section = {
        "reporting_period": {"start": period[0], "end": period[1]},
        "provenance": pctx.ORIGIN,
        "statement": "Organization policy values are company thresholds declared by the organization, not legislation. "
                     "They resolve only POLICY_CONTEXT_REQUIRED gaps and never alter regulatory requirements, mappings "
                     "or thresholds.",
        "versions": versions_out,
        "collector_capabilities": {k: cap.get(k) for k in ("source", "digest", "declared_at", "evidence",
                                                           "legacy_rules") if k in cap},
        "target_resolutions": [{"target": r["target"], "complete": r["complete"], "valid_from": r["valid_from"],
                                "valid_to": r["valid_to"], "member_count": len(r["members"]),
                                "membership_digest": "sha256:" + digest_of(sorted(
                                    (m["type"], m["id"]) for m in r["members"]))} for r in resolutions],
        "bindings": bindings, "executions": plan_execs,
        "blockers": sorted(blockers.values(), key=lambda x: x["code"]),
        "totals": {"bindings": len(bindings), "blocked_bindings": sum(1 for b in bindings if b["blocker_codes"]),
                   "unused_bindings": sum(1 for b in bindings if not b["addresses_requirement_ids"]),
                   "executions": len(plan_execs),
                   "requirements_resolved": sum(1 for r in plan["requirements"]
                                                if r["policy_resolution"]["summary"] == RESOLVED),
                   "requirements_partially_resolved": sum(1 for r in plan["requirements"]
                                                          if r["policy_resolution"]["summary"] == PARTIALLY_RESOLVED)},
    }
    plan["digest_input"]["policy_context"] = {
        "reporting_period": section["reporting_period"],
        "versions": [{"policy_version_id": v["policy_version_id"], "digest": v["digest"]} for v in versions_out],
        "context_latest_versions": context_versions,
        "collector_capabilities": section["collector_capabilities"],
        "target_resolutions": section["target_resolutions"],
        "bindings": [{k: b[k] for k in ("binding_id", "blocker_codes", "execution_ids", "addresses_requirement_ids")}
                     for b in bindings],
        "executions": [{k: e[k] for k in ("execution_id", "rule_id", "rule_version", "parameters", "reporting_period",
                                          "policy_version_digest", "target_set_digest", "requirement_ids")}
                       for e in plan_execs],
        "requirements": [{"requirement_id": r["requirement_id"],
                          "gaps": [[g["code"], g.get("rule_id"), g["status"], g["policy_codes"]]
                                   for g in r["policy_resolution"]["gaps"]],
                          "policy_execution_ids": r["policy_resolution"]["policy_execution_ids"]}
                         for r in plan["requirements"]],
    }
    return section
