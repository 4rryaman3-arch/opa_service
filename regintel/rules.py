"""Executable rules: structured definitions -> tested, immutable OPA bundles.

Regulatory interpretation ends before this module. A rule here is a technical
control test attached to a PAM control; which regulations that control
supports is answered by the reviewed mappings, not by the rule.

  * Definitions are structured JSON validated by the existing compiler
    (allowlisted evidence fields and operators) and evaluated by the existing
    fixed Rego interpreter ``securden.custom.v1``. No Rego is ever generated.
  * Every threshold in a definition must declare where it comes from. Calling
    a threshold REGULATORY requires an approved requirement whose official
    text literally contains that number.
  * Publication = building a new bundle version from the base bundle plus all
    approved rule versions, running ``opa check --strict``, the Rego unit
    tests and every rule's own test cases against the candidate, and only
    then recording it. Bundle directories are write-once; activation verifies
    their digest; rollback is activating an earlier version.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from datetime import timedelta
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field, StringConstraints, TypeAdapter, ValidationError

from app.engine.catalog import Catalog
from app.engine.compiler import ENGINE_PACKAGE, CompileResult, compile_rule
from app.engine.evaluator import Evaluator, custom_spec_from_row
from app.models.api import Evidence, ReportingPeriod
from app.models.common import UtcDatetime
from app.models.custom_rules import CustomFrameworkMapping, CustomRuleDefinition

from .db import CatalogDb, CatalogError, digest_of, now_iso

ORIGINS = ("REGULATORY", "SECURDEN_DEFAULT", "CUSTOMER_POLICY")
DURATION_OPS = frozenset({"older_than_days", "within_last_days"})
COMPARISON_OPS = frozenset({"gt", "gte", "lt", "lte", "eq", "ne"})
_dt = TypeAdapter(UtcDatetime)


class RegRuleDefinition(CustomRuleDefinition):
    """Same safe schema as customer rules; catalog rules live in the REG- namespace
    and carry no hand-written framework mappings (those come from reviewed mappings)."""

    rule_id: Annotated[str, StringConstraints(pattern=r"^REG(-[A-Z0-9]{1,20}){1,4}$")]
    framework_mappings: list[CustomFrameworkMapping] = Field(default_factory=list, max_length=0)


def _conditions(group: dict[str, Any] | None):
    if group:
        yield from group["conditions"]
        for sub in group["groups"]:
            yield from sub["conditions"]


def threshold_conditions(compiled: dict[str, Any]) -> dict[str, int]:
    """Condition id -> numeric threshold, for every numeric comparison in the rule."""
    out: dict[str, int] = {}
    for c in list(_conditions(compiled["scope"])) + list(_conditions(compiled["violation"])):
        if c["op"] in DURATION_OPS or (c["type"] == "integer" and c["op"] in COMPARISON_OPS):
            out[c["id"]] = c["value"]
    if compiled["tolerance"] > 0:
        out["tolerance"] = compiled["tolerance"]
    return out


def check_threshold_provenance(db: CatalogDb, compiled: dict[str, Any], provenance: list[dict[str, Any]]) -> None:
    thresholds = threshold_conditions(compiled)
    declared = {str(p.get("condition")): p for p in provenance}
    missing = sorted(set(thresholds) - set(declared))
    if missing:
        raise CatalogError("THRESHOLD_PROVENANCE_MISSING",
                           f"thresholds {missing} must each declare an origin ({', '.join(ORIGINS)})")
    extra = sorted(set(declared) - set(thresholds))
    if extra:
        raise CatalogError("THRESHOLD_PROVENANCE_INVALID", f"{extra} are not thresholds of this rule")
    for cid, p in declared.items():
        if p.get("origin") not in ORIGINS:
            raise CatalogError("THRESHOLD_PROVENANCE_INVALID", f"{cid}: origin must be one of {ORIGINS}")
        if p["origin"] != "REGULATORY":
            if len(str(p.get("note", "")).strip()) < 10:
                raise CatalogError("THRESHOLD_PROVENANCE_INVALID", f"{cid}: non-regulatory thresholds need an explanatory note")
            continue
        req = db.one("SELECT * FROM regulatory_requirement WHERE id=?", (p.get("requirement_id"),))
        if req is None or req["status"] != "APPROVED":
            raise CatalogError("THRESHOLD_NOT_IN_SOURCE", f"{cid}: REGULATORY origin needs an approved requirement")
        if not re.search(rf"(?<!\d){thresholds[cid]}(?!\d)", req["original_text"]):
            raise CatalogError(
                "THRESHOLD_NOT_IN_SOURCE",
                f"{cid}: the value {thresholds[cid]} does not appear in the official text of requirement {req['id']}; "
                "a converted or inferred value is an interpretation and must be declared SECURDEN_DEFAULT or CUSTOMER_POLICY")


def _validate_tests(definition: RegRuleDefinition, tests: list[dict[str, Any]]) -> None:
    if not isinstance(tests, list) or len(tests) > 50:
        raise CatalogError("RULE_TESTS_INVALID", "tests must be a list of at most 50 cases")
    expected = {t.get("expected_status") for t in tests}
    if not {"PASS", "FAIL"} <= expected:
        raise CatalogError("RULE_TESTS_REQUIRED", "a rule needs at least one test expecting PASS and one expecting FAIL")
    names = [t.get("name") for t in tests]
    if len(set(names)) != len(names) or not all(isinstance(n, str) and n for n in names):
        raise CatalogError("RULE_TESTS_INVALID", "test names must be unique non-empty strings")
    for t in tests:
        if set(t) - {"name", "as_of", "records", "expected_status", "expected_violation_subjects"}:
            raise CatalogError("RULE_TESTS_INVALID", f"{t['name']}: unknown keys")
        try:
            _test_input(definition.model_dump(mode="json"), {}, t)
        except (ValidationError, KeyError, ValueError) as exc:
            raise CatalogError("RULE_TESTS_INVALID", f"{t['name']}: {type(exc).__name__}: {str(exc)[:300]}") from exc


def _test_input(definition: dict[str, Any], compiled: dict[str, Any], test: dict[str, Any]) -> dict[str, Any]:
    """Builds the OPA input through the service's own code path."""
    end = _dt.validate_python(test["as_of"])
    evidence = Evidence.model_validate({
        "evidence_type": definition["evidence_type"], "records": test["records"],
        "completeness": {"expected_record_count": len(test["records"]), "received_record_count": len(test["records"]),
                         "source_complete": True, "collection_errors": 0}})
    spec = custom_spec_from_row({"definition": definition, "status": "ACTIVE", "compiled": compiled})
    return Evaluator.build_input(spec, ReportingPeriod(start=end - timedelta(days=30), end=end), evidence, [],
                                 {"scope_tags": []})


def _compile(definition: dict[str, Any]) -> tuple[RegRuleDefinition, CompileResult]:
    try:
        model = RegRuleDefinition.model_validate(definition)
    except ValidationError as exc:
        raise CatalogError("RULE_INVALID", "; ".join(
            f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors(include_input=False))) from exc
    result = compile_rule(model)
    if not result.valid:
        raise CatalogError("RULE_INVALID", json.dumps(result.errors))
    return model, result


def draft_rule_version(db: CatalogDb, *, definition: dict[str, Any], pam_control_id: str,
                       threshold_provenance: list[dict[str, Any]], tests: list[dict[str, Any]], actor: str,
                       ai_generated: bool = False) -> int:
    model, result = _compile(definition)
    if not db.one("SELECT 1 FROM pam_control WHERE id=?", (pam_control_id,)):
        raise CatalogError("UNKNOWN_PAM_CONTROL", pam_control_id)
    check_threshold_provenance(db, result.compiled, threshold_provenance)  # type: ignore[arg-type]
    _validate_tests(model, tests)
    with db.tx():
        existing = db.one("SELECT * FROM opa_rule_definition WHERE rule_id=?", (model.rule_id,))
        if existing is None:
            db.insert("opa_rule_definition", rule_id=model.rule_id, pam_control_id=pam_control_id, kind="STRUCTURED",
                      title=model.title, created_at=now_iso())
        elif existing["kind"] != "STRUCTURED" or existing["pam_control_id"] != pam_control_id:
            raise CatalogError("RULE_CONFLICT", f"{model.rule_id} already exists with a different kind or control")
        if db.one("SELECT 1 FROM rule_version WHERE rule_id=? AND version=?", (model.rule_id, model.version)):
            raise CatalogError("RULE_VERSION_EXISTS", "rule versions are immutable; create a new version")
        rid = db.insert("rule_version", rule_id=model.rule_id, version=model.version,
                        definition=model.model_dump(mode="json"), digest=result.digest,
                        threshold_provenance=threshold_provenance, tests=tests, authored_by=actor,
                        ai_generated=int(ai_generated), created_at=now_iso())
        db.audit(actor, "DRAFT", "rule_version", rid, ai_generated=ai_generated)
    return rid


def review_rule_version(db: CatalogDb, rule_version_id: int, *, reviewer: str, decision: str, comment: str = "") -> None:
    rv = db.one("SELECT * FROM rule_version WHERE id=?", (rule_version_id,))
    if rv is None:
        raise CatalogError("NOT_FOUND", f"rule_version {rule_version_id}")
    if rv["status"] != "DRAFT":
        raise CatalogError("NOT_DRAFT", f"rule version is {rv['status']}")
    if decision not in ("APPROVED", "REJECTED"):
        raise CatalogError("INVALID_DECISION", decision)
    if reviewer == rv["authored_by"] or reviewer.startswith("llm:"):
        raise CatalogError("SELF_APPROVAL", "the reviewer must be a person other than the author")
    if decision == "APPROVED":
        _, result = _compile(rv["definition"])
        check_threshold_provenance(db, result.compiled, rv["threshold_provenance"])  # type: ignore[arg-type]
    with db.tx():
        db.x("UPDATE rule_version SET status=? WHERE id=?", (decision, rule_version_id))
        db.insert("review_approval", entity_type="rule_version", entity_id=str(rule_version_id), decision=decision,
                  reviewer=reviewer, comment=comment, entity_digest=rv["digest"], decided_at=now_iso())
        db.audit(reviewer, decision, "rule_version", rule_version_id)


def retire_rule_version(db: CatalogDb, rule_version_id: int, *, actor: str) -> None:
    """Takes effect in the next bundle build (kept as RETIRED for historical evaluations)."""
    with db.tx():
        db.x("UPDATE rule_version SET status='RETIRED' WHERE id=? AND status='APPROVED'", (rule_version_id,))
        db.audit(actor, "RETIRE", "rule_version", rule_version_id)


# ------------------------------------------------------------------ bundles


def tree_digest(root: Path) -> tuple[str, dict[str, str]]:
    files = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(root.rglob("*")) if p.is_file()}
    return digest_of(files), files


def _opa(binary: str, args: list[str], cwd: Path, stdin: str | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run([binary, *args], cwd=cwd, input=stdin, capture_output=True, text=True, timeout=180,
                              encoding="utf-8")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CatalogError("OPA_UNAVAILABLE", f"could not run OPA: {type(exc).__name__}") from exc


def _catalog_entries(db: CatalogDb, rows: list[dict[str, Any]]) -> dict[str, Any]:
    rules: dict[str, Any] = {}
    for rv in rows:
        d = rv["definition"]
        _, result = _compile(d)
        check_threshold_provenance(db, result.compiled, rv["threshold_provenance"])  # type: ignore[arg-type]
        control = db.scalar("SELECT pam_control_id FROM opa_rule_definition WHERE rule_id=?", (d["rule_id"],))
        mappings = db.q(
            "SELECT m.id, r.framework_id, r.section_ref FROM framework_control_mapping m JOIN regulatory_requirement r "
            "ON r.id=m.requirement_id WHERE m.pam_control_id=? AND m.status='APPROVED' AND m.published_seq IS NOT NULL "
            "AND r.status='APPROVED' ORDER BY r.framework_id, r.section_ref, m.id", (control,))
        entry = rules.setdefault(d["rule_id"], {"title": d["title"], "subject_field": d["subject_field"], "versions": {}})
        entry["versions"][d["version"]] = {
            "status": "ACTIVE" if rv["status"] == "APPROVED" else "RETIRED",
            "effective_from": d["effective_from"], "effective_to": d.get("effective_to"),
            "package": ENGINE_PACKAGE, "source": "PUBLISHED", "compiled": result.compiled,
            "severity": d["severity"], "description": d.get("description", ""),
            "evidence_type": d["evidence_type"],
            "evidence_requirements": [f"Records of evidence type '{d['evidence_type']}'"],
            "parameters": {},
            "framework_mappings": [
                {"framework": m["framework_id"], "control": m["section_ref"][:200],
                 "title": f"interpretive mapping #{m['id']} via {control}"} for m in mappings],
            "remediation": d.get("remediation", ""),
        }
    return rules


def check_bundle_consistency(bundle_dir: Path) -> list[str]:
    """Static consistency between the rule catalog and the Rego in a bundle."""
    problems: list[str] = []
    try:
        catalog = Catalog.load(bundle_dir)
    except Exception as exc:  # noqa: BLE001
        return [f"catalog does not load: {type(exc).__name__}: {exc}"]
    packages = set()
    for rego in bundle_dir.rglob("*.rego"):
        m = re.search(r"^package\s+([a-z0-9_.]+)\s*$", rego.read_text(encoding="utf-8"), re.M)
        if m:
            packages.add(m.group(1))
    for rule_id, versions in catalog.rules.items():
        for version, spec in versions.items():
            if spec.package not in packages:
                problems.append(f"{rule_id} {version}: package {spec.package} is not in the bundle")
            if spec.source == "PUBLISHED":
                if spec.compiled is None or spec.package != ENGINE_PACKAGE:
                    problems.append(f"{rule_id} {version}: published rule without compiled definition")
                elif (spec.compiled["rule_id"], spec.compiled["rule_version"]) != (rule_id, version):
                    problems.append(f"{rule_id} {version}: compiled identity mismatch")
            elif spec.compiled is not None:
                problems.append(f"{rule_id} {version}: predefined rule carries a compiled definition")
    return problems


def build_bundle(db: CatalogDb, *, base_dir: Path, store_dir: Path, tests_dir: Path | None, opa_binary: str | None,
                 actor: str) -> dict[str, Any]:
    """Build, test and record a new immutable bundle version. Does not activate it."""
    if not opa_binary:
        raise CatalogError("OPA_UNAVAILABLE", "an OPA binary is required: rules are never published untested")
    rows = db.q("SELECT rv.* FROM rule_version rv JOIN opa_rule_definition d ON d.rule_id=rv.rule_id "
                "WHERE d.kind='STRUCTURED' AND rv.status IN ('APPROVED','RETIRED') ORDER BY rv.rule_id, rv.id")
    approved = [r for r in rows if r["status"] == "APPROVED"]
    for rv in approved:
        if not db.one("SELECT 1 FROM review_approval WHERE entity_type='rule_version' AND entity_id=? AND decision='APPROVED'",
                      (str(rv["id"]),)):
            raise CatalogError("UNREVIEWED_RULE", f"{rv['rule_id']} {rv['version']} has no approval record")
    base = json.loads((base_dir / "securden" / "bundle" / "data.json").read_text(encoding="utf-8"))
    n = int(db.scalar("SELECT COUNT(*) FROM bundle_version") or 0) + 1
    version = f"{base['version']}-reg{n:04d}"
    target = store_dir / "versions" / version
    if target.exists():
        raise CatalogError("BUNDLE_EXISTS", f"{version} already exists; bundle versions are immutable")
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(base_dir, target)
    report: dict[str, Any] = {"opa_check": None, "rego_unit_tests": None, "consistency": None, "rule_tests": []}
    try:
        catalog_path = target / "securden" / "catalog" / "data.json"
        catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
        entries = _catalog_entries(db, rows)
        clash = sorted(set(entries) & set(catalog["rules"]))
        if clash:
            raise CatalogError("RULE_CONFLICT", f"{clash} collide with predefined rule ids")
        catalog["rules"].update(entries)
        catalog_path.write_text(json.dumps(catalog, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        (target / "securden" / "bundle" / "data.json").write_text(
            json.dumps({**base, "version": version, "base_version": base["version"]}, indent=2) + "\n",
            encoding="utf-8", newline="\n")

        failures: list[str] = []
        rel = target.name  # relative on purpose: OPA parses "D:\..." as "<prefix>:<path>"
        check = _opa(opa_binary, ["check", "--strict", rel], target.parent)
        report["opa_check"] = "PASS" if check.returncode == 0 else "FAIL"
        if check.returncode:
            failures.append("opa check --strict: " + (check.stdout + check.stderr)[:500])
        if tests_dir is not None and tests_dir.is_dir():
            staged = target.parent / f".tests-{version}"
            shutil.copytree(tests_dir, staged)
            try:
                unit = _opa(opa_binary, ["test", rel, staged.name], target.parent)
            finally:
                shutil.rmtree(staged, ignore_errors=True)
            report["rego_unit_tests"] = "PASS" if unit.returncode == 0 else "FAIL"
            if unit.returncode:
                failures.append("opa test: " + (unit.stdout + unit.stderr)[:500])
        problems = check_bundle_consistency(target)
        report["consistency"] = "PASS" if not problems else "FAIL"
        failures.extend(problems)
        for rv in approved:
            d = rv["definition"]
            compiled = entries[d["rule_id"]]["versions"][d["version"]]["compiled"]
            for t in rv["tests"]:
                outcome = _run_rule_test(opa_binary, target, version, d, compiled, t)
                report["rule_tests"].append({"rule_id": d["rule_id"], "version": d["version"], "test": t["name"], **outcome})
                if not outcome["passed"]:
                    failures.append(f"{d['rule_id']} {d['version']} test '{t['name']}': {outcome['detail']}")
        if failures:
            raise CatalogError("BUNDLE_TESTS_FAILED", "; ".join(failures))

        digest, files = tree_digest(target)
        manifests = store_dir / "manifests"
        manifests.mkdir(exist_ok=True)
        (manifests / f"{version}.json").write_text(json.dumps(
            {"version": version, "base_version": base["version"], "digest": digest, "files": files,
             "rule_versions": [f"{r['rule_id']} {r['version']} sha256:{r['digest']}" for r in rows]},
            indent=2) + "\n", encoding="utf-8", newline="\n")
        for p in target.rglob("*"):
            if p.is_file():
                os.chmod(p, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        with db.tx():
            db.insert("bundle_version", version=version, base_version=base["version"], digest=digest,
                      created_at=now_iso(), created_by=actor, test_report=report)
            for rv in rows:
                db.insert("bundle_rule", bundle_version=version, rule_version_id=rv["id"])
            db.audit(actor, "BUNDLE_BUILT", "bundle_version", version, rules=len(rows))
    except BaseException:
        _rmtree(target)
        raise
    return {"version": version, "digest": digest, "rule_versions": len(rows), "test_report": report}


def _run_rule_test(opa_binary: str, bundle_dir: Path, bundle_version: str, definition: dict[str, Any],
                   compiled: dict[str, Any], test: dict[str, Any]) -> dict[str, Any]:
    opa_input = _test_input(definition, compiled, test)
    proc = _opa(opa_binary, ["eval", "--data", bundle_dir.name, "--stdin-input", "--format", "json",
                             f"data.{ENGINE_PACKAGE}.decision"], bundle_dir.parent, stdin=json.dumps(opa_input))
    if proc.returncode != 0:
        return {"passed": False, "detail": "opa eval failed: " + (proc.stdout + proc.stderr)[:300]}
    try:
        decision = json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError, json.JSONDecodeError):
        return {"passed": False, "detail": "decision undefined"}
    if decision.get("bundle_version") != bundle_version:
        return {"passed": False, "detail": "decision reports a different bundle version"}
    if decision.get("status") != test["expected_status"]:
        return {"passed": False, "detail": f"expected {test['expected_status']}, got {decision.get('status')}"}
    if "expected_violation_subjects" in test:
        got = sorted(v["subject_id"] for v in decision["violations"])
        if got != sorted(test["expected_violation_subjects"]):
            return {"passed": False, "detail": f"expected violations {sorted(test['expected_violation_subjects'])}, got {got}"}
    return {"passed": True, "detail": decision["status"]}


def _rmtree(path: Path) -> None:
    for p in path.rglob("*"):  # bundle files are read-only once recorded
        if p.is_file():
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
    shutil.rmtree(path, ignore_errors=True)


def verify_bundle(db: CatalogDb, store_dir: Path, version: str) -> None:
    row = db.one("SELECT * FROM bundle_version WHERE version=?", (version,))
    if row is None:
        raise CatalogError("UNKNOWN_BUNDLE", version)
    target = store_dir / "versions" / version
    if not target.is_dir() or tree_digest(target)[0] != row["digest"]:
        raise CatalogError("BUNDLE_TAMPERED", f"bundle {version} is missing or does not match its recorded digest")


def active_bundle(store_dir: Path) -> str | None:
    pointer = store_dir / "ACTIVE"
    return pointer.read_text(encoding="utf-8").strip() or None if pointer.exists() else None


def resolve_bundle_dir(store_dir: Path | None, default: Path) -> Path:
    """The directory OPA and the API must both load."""
    version = active_bundle(store_dir) if store_dir else None
    return (store_dir / "versions" / version) if store_dir and version else default


def activate_bundle(db: CatalogDb, store_dir: Path, version: str | None, *, actor: str) -> dict[str, Any]:
    """Point the deployment at a bundle version (``None`` = the base bundle).
    Activating an earlier version is the rollback operation. The services must
    be restarted afterwards; until both run the same bundle the API fails closed."""
    if version is not None:
        verify_bundle(db, store_dir, version)
    previous = active_bundle(store_dir)
    old = {r["rule_version_id"] for r in db.q("SELECT rule_version_id FROM bundle_rule WHERE bundle_version=?", (previous,))}
    new = {r["rule_version_id"] for r in db.q("SELECT rule_version_id FROM bundle_rule WHERE bundle_version=?", (version,))}
    changes = [("rule_version", i, "UPSERT") for i in sorted(new)] + \
              [("rule_version", i, "WITHDRAW") for i in sorted(old - new)]
    with db.tx():
        db.x("UPDATE bundle_version SET active=0")
        if version is not None:
            db.x("UPDATE bundle_version SET active=1 WHERE version=?", (version,))
        seq = db.publish(actor, "BUNDLE", changes, {"activated": version, "previous": previous})
        store_dir.mkdir(parents=True, exist_ok=True)
        tmp = store_dir / "ACTIVE.tmp"
        tmp.write_text((version or "") + "\n", encoding="utf-8")
        os.replace(tmp, store_dir / "ACTIVE")
        db.audit(actor, "BUNDLE_ACTIVATED", "bundle_version", version or "(base)", previous=previous)
    return {"active": version, "previous": previous, "catalog_version": seq,
            "bundle_dir": str(resolve_bundle_dir(store_dir, Path("policy-bundle")))}
