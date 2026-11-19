"""Django rewrite contract 1.0: handshake, scoped uploads, prepare_catalog jobs,
organization-scope isolation and scoped catalog reads. Synthetic fixtures only."""
from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from regintel import automation, registry
from regintel.admin_api import PREFIX as ADMIN, create_admin_app
from regintel.orgscope import HEADER
from regintel.sources import registry as sources
from ..conftest import BUNDLE, OPA_TOKEN
from . import support as s
from .test_automation import pipeline_llm

CATALOG = "/api/v1/catalog"
SCOPE_A = "a" * 64
SCOPE_B = "b" * 64

ACT_REVIEW_ONLY = """<html><body>
<h1>SYNTHETIC TEST FIXTURE - Synthetic review act (not a real regulation)</h1>
<h2>Article 9 Reviews</h2>
<p>Operators shall review privileged access rights periodically.</p>
""" + s.FILLER + "</body></html>"
REVIEW_QUOTE = "Operators shall review privileged access rights periodically."


def credentials(tmp_path: Path):
    entries, headers = [], {}
    for name, scopes in [
        ("deploy", ["catalog:read", "catalog:operate", "catalog:review", "catalog:publish", "catalog:automate",
                    "evaluate"]),
        ("intruder", ["catalog:read", "catalog:operate", "catalog:automate"]),
    ]:
        secret = "synthetic-test-secret-" + name
        headers[name] = {"Authorization": f"Bearer {name}.{secret}"}
        entries.append({"key_id": name, "secret_sha256": hashlib.sha256(secret.encode()).hexdigest(),
                        "scopes": scopes, "tenants": ["acme"], "enabled": True})
    path = tmp_path / "clients.json"
    path.write_text(json.dumps({"clients": entries}))
    return path, headers


class Env:
    def __init__(self, admin, public, db, jobs, headers):
        self.admin, self.public, self.db, self.jobs, self.headers = admin, public, db, jobs, headers

    def h(self, scope=None, who="deploy"):
        return {**self.headers[who], **({HEADER: scope} if scope else {})}

    def upload(self, content: bytes, *, scope, key, framework_id="", filename="act.html", **extra):
        params = {"filename": filename, "provenance": "Synthetic fixture uploaded for the rewrite contract tests.",
                  "license_note": "synthetic fixture", "jurisdictions": json.dumps(["EU"]),
                  "request_key": key, "framework_id": framework_id, **extra}
        return self.admin.post(ADMIN + "/uploads", params=params, content=content, headers=self.h(scope))

    def prepare(self, *, scope, key, mode="import", **body):
        return self.admin.post(ADMIN + "/jobs", headers=self.h(scope),
                               json={"action": "prepare_catalog", "mode": mode, "jurisdictions": ["EU"],
                                     "request_key": key, **body})

    def run_all(self, limit=10):
        for _ in range(limit):
            if not self.jobs.run_once():
                return


@pytest.fixture
def env(tmp_path, monkeypatch):
    db = s.make_db(tmp_path)
    path, headers = credentials(tmp_path)
    common = dict(api_clients_file=path, catalog_db_path=Path(db.path), policy_bundle_dir=BUNDLE)
    admin = create_admin_app(Settings(**common, catalog_jobs_db_path=tmp_path / "jobs.db",
                                      catalog_upload_dir=tmp_path / "uploads"), start_worker=False)
    public = create_app(Settings(**common, opa_url="http://127.0.0.1:9", opa_token=OPA_TOKEN,
                                 db_path=tmp_path / "opm.db", log_level="WARNING", trust_proxy_headers=False,
                                 opa_connect_timeout_seconds=0.5))
    from regintel import __main__ as cli
    monkeypatch.setattr(cli, "_llm", lambda: nullcontext(pipeline_llm()))
    with TestClient(admin) as a, TestClient(public) as p:
        yield Env(a, p, db, admin.state.jobs, headers)
    db.close()


def test_handshake_scope_binding_and_validation(env):
    health = env.admin.get(ADMIN + "/health", headers=env.h()).json()
    assert health["rewrite_contract_version"] == "1.0"
    assert health["capabilities"] == {
        "prepare_catalog_v1": True,
        "scoped_imports_v1": True,
        "scoped_catalog_v1": True,
        "bounded_rule_generation_v1": True,
    }
    assert health["rule_generation"]["supported"] is True
    assert health["rule_generation"]["compiler_version"] == "pam-rulespec-compiler-1.0"
    # a malformed scope header is rejected, a short one too
    bad = env.admin.post(ADMIN + "/jobs", headers=env.h("short"), json={
        "action": "prepare_catalog", "mode": "discovery", "jurisdictions": ["EU"], "request_key": "rw-key-bad"})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "INVALID_SCOPE"
    # the scope header is mandatory for prepare_catalog
    none = env.admin.post(ADMIN + "/jobs", headers=env.h(), json={
        "action": "prepare_catalog", "mode": "discovery", "jurisdictions": ["EU"], "request_key": "rw-key-noscope"})
    assert none.status_code == 422 and none.json()["error"]["code"] == "SCOPE_REQUIRED"
    # first use binds the scope to the credential; another credential is locked out
    r = env.upload(b"<html><body>synthetic</body></html>", scope=SCOPE_A, key="rw-up-bind")
    assert r.status_code == 201, r.text
    stolen = env.admin.get(ADMIN + "/jobs", headers=env.h(SCOPE_A, "intruder"))
    assert stolen.status_code == 403 and stolen.json()["error"]["code"] == "SCOPE_FORBIDDEN"


def test_scoped_upload_idempotency_and_response(env):
    content = s.ACT_EN_V1.encode()
    first = env.upload(content, scope=SCOPE_A, key="rw-upload-1")
    assert first.status_code == 201, first.text
    body = first.json()
    assert body["organization_scope"] == SCOPE_A
    assert body["source_origin"] == "UPLOADED_DOCUMENT"
    assert body["content_sha256"] == hashlib.sha256(content).hexdigest()
    assert len(body["document_ids"]) == 1  # parsed immediately: Django gets real ids
    # idempotent replay: 200, same ids; changed bytes under the same key: 409
    again = env.upload(content, scope=SCOPE_A, key="rw-upload-1")
    assert again.status_code == 200 and again.json()["document_ids"] == body["document_ids"]
    changed = env.upload(s.ACT_EN_V2.encode(), scope=SCOPE_A, key="rw-upload-1")
    assert changed.status_code == 409 and changed.json()["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    # request_key and jurisdictions are mandatory in the scoped workflow
    assert env.upload(content, scope=SCOPE_A, key=None).status_code == 422
    assert env.upload(content, scope=SCOPE_A, key="rw-upload-2", jurisdictions="not json").status_code == 422
    # the 5 MiB limit applies
    assert env.upload(b"x" * (5 * 1024 * 1024 + 1), scope=SCOPE_A, key="rw-upload-3").status_code == 413
    # uploaded material never becomes globally visible
    unscoped = env.public.get(CATALOG + "/coverage", headers=env.h()).json()
    assert unscoped["metrics"]["official_sources_configured"]["total"] == 0


def test_import_mode_prepares_publishes_and_stays_isolated(env):
    content = s.ACT_EN_V1.encode()
    document_ids = env.upload(content, scope=SCOPE_A, key="rw-imp-up").json()["document_ids"]
    submitted = env.prepare(scope=SCOPE_A, key="rw-imp-1", document_ids=document_ids)
    assert submitted.status_code == 202, submitted.text
    assert submitted.json()["organization_scope"] == SCOPE_A
    job_id = submitted.json()["job"]["id"]
    # dedup + conflicting payload under the same key
    assert env.prepare(scope=SCOPE_A, key="rw-imp-1", document_ids=document_ids).json()["job"]["id"] == job_id
    assert env.prepare(scope=SCOPE_A, key="rw-imp-1", document_ids=document_ids, translate=False).status_code == 409
    env.run_all()
    job = env.admin.get(ADMIN + f"/jobs/{job_id}", headers=env.h(SCOPE_A)).json()["job"]
    assert job["status"] in ("SUCCEEDED", "PARTIAL"), (job["status"], job["error"])
    result = job["result"]
    assert result["organization_scope"] == SCOPE_A and result["outcome"] == "PREPARED"
    fw_id = result["frameworks"][0]["framework_id"]
    assert fw_id.startswith("ORG-")  # no registered framework matched: scoped record, never official
    assert result["counts"]["requirements_published"] == 2
    assert result["counts"]["mappings_prepared"] == 2  # rotation + session recording signals
    assert result["readiness"][0]["readiness"] == "READY"

    # scoped catalog reads: templates, requirements, plan - with the scope header
    templates = env.public.get(CATALOG + "/evaluation-templates", headers=env.h(SCOPE_A)).json()
    assert templates["organization_scope"] == SCOPE_A
    item = next(i for i in templates["items"] if i["framework_id"] == fw_id)
    assert item["source_origin"] == "UPLOADED_DOCUMENT"
    assert item["assessable_requirements"] == item["automated_requirements"] == 2
    assert item["updated_at"]
    reqs = env.public.get(CATALOG + "/requirements", params={"framework_id": fw_id}, headers=env.h(SCOPE_A)).json()
    assert reqs["organization_scope"] == SCOPE_A and len(reqs["items"]) == 2
    assert all(r["original_text"] for r in reqs["items"])  # the org sees its own uploaded text
    plan = env.public.get(CATALOG + f"/evaluation-templates/{fw_id}/plan", params={"tenant_id": "acme"},
                          headers=env.h(SCOPE_A))
    assert plan.status_code == 200 and plan.json()["organization_scope"] == SCOPE_A
    assert plan.json()["readiness"] == "READY" and len(plan.json()["executions"]) == 2

    # isolation: without the header, and under another scope, none of it exists
    assert fw_id not in {i["framework_id"] for i in
                         env.public.get(CATALOG + "/evaluation-templates", headers=env.h()).json()["items"]}
    assert env.public.get(CATALOG + f"/frameworks/{fw_id}", headers=env.h()).status_code == 404
    assert env.public.get(CATALOG + f"/frameworks/{fw_id}", headers=env.h(SCOPE_B)).status_code == 404
    assert env.public.get(CATALOG + f"/evaluation-templates/{fw_id}/plan", params={"tenant_id": "acme"},
                          headers=env.h(SCOPE_B)).status_code == 404
    unscoped_reqs = env.public.get(CATALOG + "/requirements", headers=env.h()).json()
    assert unscoped_reqs["items"] == []
    changes = env.public.get(CATALOG + "/changes", headers=env.h()).json()
    assert all(c["entity_type"] not in ("requirement", "mapping") for c in changes["items"])
    # scoped job ids cannot be probed from another scope or without a scope mismatch
    assert env.admin.get(ADMIN + f"/jobs/{job_id}", headers=env.h(SCOPE_B)).status_code == 404
    assert env.admin.get(ADMIN + "/jobs", headers=env.h(SCOPE_B)).json()["items"] == []
    # cross-scope document ids in a submission look exactly like unknown ones
    other = env.prepare(scope=SCOPE_B, key="rw-imp-steal", document_ids=document_ids)
    assert other.status_code == 404 and other.json()["error"]["code"] == "UNKNOWN_DOCUMENT"

    # retries do not duplicate: a new key converges with nothing new
    rerun = env.prepare(scope=SCOPE_A, key="rw-imp-2", document_ids=document_ids)
    env.run_all()
    job2 = env.admin.get(ADMIN + f"/jobs/{rerun.json()['job']['id']}", headers=env.h(SCOPE_A)).json()["job"]
    assert job2["result"]["counts"]["requirements_published"] == 0
    assert job2["result"]["counts"]["mappings_prepared"] == 0
    assert job2["result"]["outcome"] == "NOTHING_NEW"


def test_zero_executable_checks_remains_selectable(env):
    def llm():
        def script(system, prompt):
            if system == automation.SYSTEM_REVIEW:
                return {"verdict": "APPROVE", "reasons": [],
                        "checks": {"quote_supported": True, "obligation_type_correct": True,
                                   "thresholds_grounded": True, "domains_relevant": True}}
            out = []
            if REVIEW_QUOTE in prompt:
                out.append(s.candidate(REVIEW_QUOTE, domains=("access_reviews",)))
            return {"requirements": out}
        return s.FakeLlm(script)

    from regintel import __main__ as cli
    import regintel
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(cli, "_llm", lambda: nullcontext(llm()))
        document_ids = env.upload(ACT_REVIEW_ONLY.encode(), scope=SCOPE_A, key="rw-zero-up",
                                  filename="review.html").json()["document_ids"]
        env.prepare(scope=SCOPE_A, key="rw-zero-1", document_ids=document_ids)
        env.run_all()
    job = env.admin.get(ADMIN + "/jobs", headers=env.h(SCOPE_A)).json()["items"][0]
    result = job["result"]
    assert result["counts"]["requirements_published"] == 1
    assert result["counts"]["mappings_prepared"] == 0 and result["counts"]["unmapped_requirements"] == 1
    assert any(g["code"] == "UNSUPPORTED_RULE" for g in result["gaps"])  # a structured gap, not invented content
    fw_id = result["frameworks"][0]["framework_id"]
    # why: PAM-REVIEW-001 exists in the bundle, but the PAM bridge supplies no evidence for it
    unsupported = next(g for g in result["gaps"] if g["code"] == "UNSUPPORTED_RULE")
    assert unsupported["mapping_gap_codes"] == ["COLLECTOR_MISSING"]
    [entry] = result["mapping_gaps"]
    assert entry["status"] == "UNMAPPED" and entry["gaps"][0]["rule_id"] == "PAM-REVIEW-001"
    assert result["counts"]["mapping_gaps_by_code"] == {"COLLECTOR_MISSING": 1}
    live = env.admin.get(f"{ADMIN}/frameworks/{fw_id}/mapping-gaps", headers=env.h(SCOPE_A)).json()
    assert live["items"] == result["mapping_gaps"] and "PAM-SESSREC-001" in live["bridge_collected_rules"]
    other = env.admin.get(f"{ADMIN}/frameworks/{fw_id}/mapping-gaps", headers=env.h(SCOPE_B)).json()
    assert other["items"] == []  # another organization's scoped requirements are invisible
    item = next(i for i in env.public.get(CATALOG + "/evaluation-templates", headers=env.h(SCOPE_A)).json()["items"]
                if i["framework_id"] == fw_id)
    assert item["readiness"] == "NOT_READY" and item["published_requirements"] == 1  # still selectable for gap reports
    plan = env.public.get(CATALOG + f"/evaluation-templates/{fw_id}/plan", params={"tenant_id": "acme"},
                          headers=env.h(SCOPE_A)).json()
    assert plan["requirements"][0]["assessment"] == "UNMAPPED" and plan["executions"] == []


def test_discovery_mode_uses_registered_sources_and_reports_gaps(env, monkeypatch):
    s.setup_synthetic(env.db, verify=False)  # registered authority + frameworks + PROPOSED official source
    registry.verify_framework(env.db, "SYN-EU-ACT", reviewer="bob")  # framework identity stays a human input
    real_sync = sources.sync_source
    monkeypatch.setattr(automation, "sync_source", lambda db_, sid, **kw: real_sync(
        db_, sid, **{**kw, "transport": s.transport({f"https://{s.DOMAIN}/act/en": s.ACT_EN_V1}),
                     "sleep": lambda t: None}))
    submitted = env.prepare(scope=SCOPE_A, key="rw-disc-1", mode="discovery", include_inherited=False,
                            requested_framework_ids=["SYN-EU-ACT"])
    assert submitted.status_code == 202, submitted.text
    env.run_all()
    job = env.admin.get(ADMIN + f"/jobs/{submitted.json()['job']['id']}", headers=env.h(SCOPE_A)).json()["job"]
    assert job["status"] in ("SUCCEEDED", "PARTIAL"), (job["status"], job["error"])
    result = job["result"]
    assert result["counts"]["requirements_published"] == 2
    # official-discovery results live in the shared global catalog: visible without any scope
    reqs = env.public.get(CATALOG + "/requirements", params={"framework_id": "SYN-EU-ACT"}, headers=env.h()).json()
    assert len(reqs["items"]) == 2
    templates = {i["framework_id"]: i for i in
                 env.public.get(CATALOG + "/evaluation-templates", headers=env.h()).json()["items"]}
    assert templates["SYN-EU-ACT"]["source_origin"] == "OFFICIAL_DISCOVERY"
    # a jurisdiction with nothing registered is an honest gap, not invented content
    nothing = env.prepare(scope=SCOPE_A, key="rw-disc-sg", mode="discovery", jurisdictions=["SG"],
                          include_inherited=False)
    env.run_all()
    job = env.admin.get(ADMIN + f"/jobs/{nothing.json()['job']['id']}", headers=env.h(SCOPE_A)).json()["job"]
    assert job["status"] == "FAILED"
    assert job["result"]["gaps"][0]["code"] == "SOURCE_CONFIGURATION_REQUIRED"
    assert "never searches the open internet" in job["result"]["gaps"][0]["message"]
