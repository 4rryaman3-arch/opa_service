"""Job progress API: per-step counters, measured / reference rates and ETA with reason codes."""
from __future__ import annotations

import json
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone

from regintel import automation, progress as pm
from regintel.admin_api import PREFIX
from regintel.jobs import Jobs
from regintel.sources import registry as sources
from . import support as s
from .test_automation import EN_URL, auth, env, pipeline_llm  # noqa: F401  (env is a fixture)

T0 = datetime(2026, 11, 16, 9, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self):
        self.now = T0

    def __call__(self):
        return self.now

    def tick(self, seconds):
        self.now += timedelta(seconds=seconds)


def running_job(tmp_path, action="prepare_catalog"):
    jobs = Jobs(tmp_path / "jobs.db", tmp_path / "catalog.db")
    clock = Clock()
    jobs.clock = clock
    job = jobs.submit("op", "k1", {"action": action})
    with jobs.connect() as c:
        c.execute("UPDATE job SET status='RUNNING', started_at=? WHERE id=?", (pm._iso(T0), job["id"]))
    return jobs, clock, job["id"]


def view(jobs, job_id):
    return jobs.estimate(jobs.get(job_id))


def test_measured_step_rate_gives_a_step_and_job_eta(tmp_path):
    jobs, clock, jid = running_job(tmp_path)
    jobs.set_progress(jid, "resolve", mode="discovery")
    assert view(jobs, jid)["eta"]["reason"] == pm.NOT_COUNTED
    fw = {"framework_id": "FW", "framework": "1/1"}
    jobs.set_progress(jid, "candidate_review", **fw, candidate="1/21", done=0, total=20, unit="candidate")
    first = view(jobs, jid)
    assert first["step"]["reason"] == pm.INSUFFICIENT_SAMPLES and first["eta"]["seconds"] is None
    clock.tick(50)
    jobs.set_progress(jid, "candidate_review", **fw, candidate="6/21", done=5, total=20, unit="candidate")
    clock.tick(4)  # time since the last marker is subtracted
    out = view(jobs, jid)
    assert out["step"]["seconds_per_unit"] == 10.0 and out["step"]["basis"] == "measured"
    assert out["step"]["eta_seconds"] == 146.0 and out["step"]["percent"] == 25.0
    assert out["eta"]["seconds"] == 146.0 and out["eta"]["at"] == pm._iso(clock.now + timedelta(seconds=146))
    assert out["seconds_since_update"] == 4.0 and out["elapsed_seconds"] == 54.0


def test_rule_generation_progress_has_detail_and_an_eta(tmp_path):
    jobs, clock, jid = running_job(tmp_path)
    cur = {"requirement_id": 354, "section_ref": "page 107", "control_id": "AU-14", "clause": "a"}
    base = {"total": 40, "unit": "requirements", "orchestration_stage": "propose_missing_rules"}
    jobs.set_progress(jid, "propose_missing_rules", **base, done=0, substep="propose", current=cur, outcomes={})
    clock.tick(300)
    jobs.set_progress(jid, "propose_missing_rules", **base, done=2, substep="test", current=cur,
                      outcomes={"NO_RULE_PROPOSED": 2}, rules_activated=0, seconds_per_requirement=150.0)
    out = view(jobs, jid)
    assert out["step"]["seconds_per_unit"] == 150.0 and out["eta"]["seconds"] == 38 * 150.0
    rg = out["rule_generation"]
    assert rg["substep"] == "test" and rg["current"]["requirement_id"] == 354 and rg["done"] == 2
    assert rg["outcomes"] == {"NO_RULE_PROPOSED": 2} and out["orchestration_stage"] == "propose_missing_rules"
    jobs.set_progress(jid, "readiness")
    assert view(jobs, jid)["rule_generation"] is None


def test_more_frameworks_or_versions_leave_the_job_eta_open(tmp_path):
    jobs, clock, jid = running_job(tmp_path)
    for done in (1, 5):
        jobs.set_progress(jid, "extract", framework_id="A", framework="1/2", version_id=7, version="1/1",
                          section=f"{done}/40", done=done, total=40, unit="section", drafted=done)
        clock.tick(20)
    out = view(jobs, jid)
    assert out["step"]["eta_seconds"] is not None
    assert out["eta"]["seconds"] is None and out["eta"]["reason"] == pm.MORE_WORK_UNKNOWN


def test_extract_projects_review_time_from_reference_rates(tmp_path):
    jobs, clock, jid = running_job(tmp_path)
    for done in (1, 5):  # 4 sections in 20 s -> 5 s/section, 1 draft per section so far
        jobs.set_progress(jid, "extract", framework_id="A", framework="1/1", version_id=7, version="1/1",
                          section=f"{done}/10", done=done, total=10, unit="section", drafted=done)
        if done == 1:
            clock.tick(20)
    assert view(jobs, jid)["eta"]["reason"] == pm.NO_REFERENCE_RATE
    # a finished job with a 3 s/candidate review becomes the reference
    prior = {"stage": "publish", "at": pm._iso(T0), "timing": {"history": [
        {"stage": "candidate_review", "unit": "candidate", "done": 10, "total": 10, "seconds_per_unit": 3.0}]}}
    with jobs.connect() as c:
        c.execute("INSERT INTO job (id,actor,request_key,payload,status,created_at,progress) "
                  "VALUES ('old','op','k0','{}','SUCCEEDED',?,?)", (pm._iso(T0), json.dumps(prior)))
    out = view(jobs, jid)
    # 5 sections left * 5 s + 10 projected candidates * 3 s
    assert out["eta"] == {**out["eta"], "seconds": 55.0, "basis": "projected", "projected_candidates": 10}


def test_queued_and_finished_jobs(tmp_path):
    jobs, clock, jid = running_job(tmp_path)
    queued = jobs.submit("op", "k2", {"action": "sync"})
    out = view(jobs, queued["id"])
    assert out["queue_position"] == 2 and out["eta"]["reason"] == pm.QUEUED
    with jobs.connect() as c:
        c.execute("UPDATE job SET status='SUCCEEDED', finished_at=? WHERE id=?", (pm._iso(T0), jid))
    done = view(jobs, jid)
    assert done["eta"]["seconds"] == 0 and done["eta"]["percent"] == 100.0


def test_progress_endpoint_end_to_end(env, monkeypatch):  # noqa: F811
    client, db, tokens, jobs = env
    from regintel import registry, __main__ as cli
    registry.verify_framework(db, 'SYN-EU-ACT', reviewer='bob')
    monkeypatch.setattr(cli, '_llm', lambda: nullcontext(pipeline_llm()))
    real_sync = sources.sync_source
    monkeypatch.setattr(automation, 'sync_source', lambda db_, sid, **kw: real_sync(
        db_, sid, **{**kw, 'transport': s.transport({EN_URL: s.ACT_EN_V1}), 'sleep': lambda t: None}))
    scoped = {**auth(tokens, 'automated'), 'X-Securden-Organization-Scope': 'org-progress-test'}
    submitted = client.post(PREFIX + '/jobs', headers=scoped, json={
        'action': 'prepare_catalog', 'mode': 'discovery', 'jurisdictions': ['EU'],
        'requested_framework_ids': ['SYN-EU-ACT'], 'request_key': 'progress-key'})
    assert submitted.status_code == 202, submitted.text
    job_id = submitted.json()['job']['id']
    queued = client.get(PREFIX + f'/jobs/{job_id}/progress', headers=scoped).json()
    assert queued['progress']['status'] == 'QUEUED' and queued['progress']['queue_position'] == 1
    assert pm.QUEUED in queued['eta_reasons']
    assert jobs.run_once()
    body = client.get(PREFIX + f'/jobs/{job_id}/progress', headers=scoped).json()['progress']
    assert body['status'] == 'SUCCEEDED' and body['eta']['seconds'] == 0
    counted = {st['stage']: st for st in body['completed_steps'] if st.get('unit')}
    assert counted['extract']['unit'] == 'section' and counted['extract']['framework_id'] == 'SYN-EU-ACT'
    assert client.get(PREFIX + '/jobs/nope/progress', headers=auth(tokens, 'automated')).status_code == 404
