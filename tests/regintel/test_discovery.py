"""Jurisdiction-triggered regulatory intelligence: discover jobs, coverage,
next_actions and persisted LLM processing attempts. Synthetic fixtures only."""
from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from regintel import catalog, discovery, extraction
from regintel.admin_api import PREFIX, create_admin_app
from regintel.llm import LlmError
from . import support as s


@pytest.fixture
def env(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, verify=False)  # syn-gazette stays PROPOSED: a human checkpoint
    entries = []
    tokens = {}
    for name, scopes in [('operator', ['catalog:operate', 'catalog:review', 'catalog:publish']),
                         ('reader', ['catalog:read'])]:
        secret = 'synthetic-test-secret-' + name
        tokens[name] = f'{name}.{secret}'
        entries.append({'key_id': name, 'secret_sha256': hashlib.sha256(secret.encode()).hexdigest(),
                        'scopes': scopes, 'tenants': ['acme'], 'enabled': True})
    (tmp_path / 'clients.json').write_text(json.dumps({'clients': entries}))
    from ..conftest import BUNDLE
    settings = Settings(api_clients_file=tmp_path / 'clients.json', catalog_db_path=db.path,
                        catalog_jobs_db_path=tmp_path / 'jobs.db', catalog_upload_dir=tmp_path / 'uploads',
                        policy_bundle_dir=BUNDLE)
    app = create_admin_app(settings, start_worker=False)
    with TestClient(app) as client:
        yield client, db, tokens, app.state.jobs
    db.close()


def auth(tokens, name='operator'):
    return {'Authorization': 'Bearer ' + tokens[name]}


def submit_discover(client, tokens, jurisdiction, key, **extra):
    return client.post(PREFIX + '/jobs', headers=auth(tokens),
                       json={'action': 'discover', 'jurisdiction': jurisdiction, 'request_key': key, **extra})


def run_all(jobs, limit=10):
    for _ in range(limit):
        if not jobs.run_once():
            return


def test_discover_validates_jurisdiction_and_scope(env):
    client, db, tokens, jobs = env
    response = submit_discover(client, tokens, 'ZZ', 'discover-key-unknown')
    assert response.status_code == 404 and response.json()['error']['code'] == 'UNKNOWN_JURISDICTION'
    assert jobs.list() == []  # nothing was queued
    assert client.get(PREFIX + '/jurisdictions/ZZ/coverage', headers=auth(tokens)).status_code == 404
    assert submit_discover(client, tokens, 'DE', 'k', ).status_code == 422  # request_key too short
    assert client.get(PREFIX + '/jurisdictions/DE/coverage', headers=auth(tokens, 'reader')).status_code == 403


def test_discover_without_configured_sources_is_an_actionable_blocker(env):
    client, db, tokens, jobs = env
    # FR alone (no inheritance) has no configured sources: the job fails with
    # instructions, instead of pretending an empty search means no obligations.
    body = submit_discover(client, tokens, 'FR', 'discover-key-fr', include_inherited=False).json()
    assert body['job']['status'] == 'QUEUED'
    run_all(jobs)
    job = jobs.get(body['job']['id'])
    assert job['status'] == 'FAILED'
    assert job['error'].startswith('SOURCE_CONFIGURATION_REQUIRED')
    blocker = job['result']['blockers'][0]
    assert blocker['code'] == 'SOURCE_CONFIGURATION_REQUIRED'
    assert set(blocker['supply']) == {'register_authority', 'register_framework', 'register_source', 'upload_document'}
    assert job['result']['outcome'] == 'SOURCE_CONFIGURATION_REQUIRED'
    # US with inheritance: still nothing configured anywhere in its scope.
    body = submit_discover(client, tokens, 'US', 'discover-key-us').json()
    run_all(jobs)
    assert jobs.get(body['job']['id'])['status'] == 'FAILED'


def test_discover_inherited_scope_pauses_at_source_verification(env):
    client, db, tokens, jobs = env
    # DE itself has nothing; the EU source applies through membership and is PROPOSED.
    body = submit_discover(client, tokens, 'DE', 'discover-key-de').json()
    run_all(jobs)
    job = jobs.get(body['job']['id'])
    assert job['status'] == 'SUCCEEDED', job['error']
    result = job['result']
    assert result['outcome'] == 'AWAITING_HUMAN_REVIEW' and result['sync_jobs'] == []
    scope = {e['code']: e for e in result['scope']}
    assert scope['DE']['via'] == 'SELF' and scope['DE']['inherited'] is False
    assert scope['EU']['via'] == 'MEMBER:DE' and scope['EU']['inherited'] is True
    assert scope['EU']['membership']['member'] == 'DE' and scope['EU']['membership']['valid_from']
    assert result['sources']['proposed'] == ['syn-gazette']
    first = result['next_actions'][0]
    assert first['action'] == 'verify_source' and first['source_ids']['ids'] == ['syn-gazette']
    assert first['required_scope'] == 'catalog:review'
    # Exact-only scope for DE finds nothing: registration/membership is not coverage.
    body = submit_discover(client, tokens, 'DE', 'discover-key-de-exact', include_inherited=False).json()
    run_all(jobs)
    exact = jobs.get(body['job']['id'])
    assert exact['status'] == 'FAILED' and exact['result']['outcome'] == 'SOURCE_CONFIGURATION_REQUIRED'
    assert [e['code'] for e in exact['result']['scope']] == ['DE']


def test_discover_triggers_sync_and_exposes_the_pipeline(env, monkeypatch):
    client, db, tokens, jobs = env
    up = client.post(PREFIX + '/uploads', params={
        'framework_id': 'SYN-EU-ACT', 'filename': 'synthetic.html', 'language': 'en',
        'provenance': 'Synthetic test document generated for integration verification only.',
        'license_note': 'Synthetic fixture; test use permitted'},
        content=s.ACT_EN_V1.encode(), headers=auth(tokens)).json()
    source_id = up['source_id']
    assert client.post(PREFIX + f'/sources/{source_id}/verify', headers=auth(tokens),
                       json={'outcome': 'VERIFIED',
                             'evidence': 'Fixture provenance reviewed; synthetic file from the test itself.'}).status_code == 200

    # Duplicate request keys do not duplicate work; a different payload is a conflict.
    first = submit_discover(client, tokens, 'EU', 'discover-key-eu').json()['job']
    again = submit_discover(client, tokens, 'EU', 'discover-key-eu').json()['job']
    assert first['id'] == again['id']
    conflict = submit_discover(client, tokens, 'DE', 'discover-key-eu')
    assert conflict.status_code == 409 and conflict.json()['error']['code'] == 'IDEMPOTENCY_CONFLICT'

    assert jobs.run_once()  # the discover job itself
    job = jobs.get(first['id'])
    assert job['status'] == 'SUCCEEDED' and job['result']['outcome'] == 'SYNC_TRIGGERED'
    syncs = job['result']['sync_jobs']
    assert [x['source_id'] for x in syncs] == [source_id]  # only the human-verified source
    assert 'syn-gazette' in job['result']['sources']['proposed']
    run_all(jobs)  # the child sync
    child = jobs.get(syncs[0]['job_id'])
    assert child['status'] == 'SUCCEEDED' and child['result']['versions'][0]['sections'] == 3
    version = child['result']['versions'][0]['version_id']

    # Retrieved content is visible in management reads; nothing is auto-approved.
    docs = client.get(PREFIX + '/documents', headers=auth(tokens)).json()['items']
    assert docs[0]['status'] == 'AWAITING_REVIEW'
    cov = client.get(PREFIX + '/jurisdictions/EU/coverage', headers=auth(tokens)).json()
    eu = next(item for item in cov['items'] if item['code'] == 'EU')
    assert eu['documents']['awaiting_review'] == 1 and eu['sources'] == {
        'proposed': 1, 'verified': 1, 'rejected': 0, 'disabled': 0}
    assert eu['stage'] == 'DOCUMENTS_RETRIEVED' and eu['fully_supported'] is None
    actions = {a['action']: a for a in cov['next_actions']}
    assert actions['review_document']['version_ids']['ids'] == [version]
    assert 'verify_source' in actions and cov['statement']

    assert client.post(PREFIX + f'/documents/{version}/review', headers=auth(tokens),
                       json={'decision': 'APPROVED', 'comment': 'Reviewed complete synthetic text.'}).status_code == 200
    cov = client.get(PREFIX + '/jurisdictions/EU/coverage', headers=auth(tokens)).json()
    actions = {a['action']: a for a in cov['next_actions']}
    assert actions['submit_extract_job']['version_ids']['ids'] == [version]

    from regintel import __main__ as cli
    monkeypatch.setattr(cli, '_llm', lambda: nullcontext(s.good_llm()))
    extract = client.post(PREFIX + '/jobs', headers=auth(tokens),
                          json={'action': 'extract', 'version_id': version,
                                'request_key': 'discover-extract-key'}).json()['job']
    run_all(jobs)
    result = jobs.get(extract['id'])
    assert result['status'] == 'SUCCEEDED' and result['result']['drafted'] == 2

    # The LLM processing trail is readable, raw != approved, and scoped.
    attempts = client.get(PREFIX + f'/documents/{version}/attempts', headers=auth(tokens)).json()
    assert client.get(PREFIX + f'/documents/{version}/attempts', headers=auth(tokens, 'reader')).status_code == 403
    assert client.get(PREFIX + '/documents/999999/attempts', headers=auth(tokens)).status_code == 404
    assert 'never approved' in attempts['note']
    by_section = {a['section']['section_ref']: a for a in attempts['items']}
    art7 = by_section['#2 Article 7 Privileged credentials']
    assert art7['kind'] == 'EXTRACTION' and art7['status'] == 'SUCCEEDED'
    assert art7['job_id'] == extract['id'] and art7['model'] == 'fake-multilingual:test'
    assert art7['model_version'] == 'sha256:fixture-weights' and art7['prompt_version'] == extraction.PROMPT_VERSION
    assert art7['started_at'] and art7['finished_at'] and art7['raw_truncated'] is False
    assert json.loads(art7['raw_response']) == art7['parsed_json']
    assert len(art7['validated_json']['requirements']) == 2 == len(art7['accepted_requirement_ids'])
    assert art7['validation_errors'] == [] and art7['rejected_candidates'] == []
    assert art7['section']['text'] and s.ROTATION_QUOTE in art7['section']['text']
    filtered = client.get(PREFIX + f'/documents/{version}/attempts', params={'kind': 'TRANSLATION'},
                          headers=auth(tokens)).json()
    assert filtered['items'] == []  # English source: no translation attempts
    paged = client.get(PREFIX + f'/documents/{version}/attempts', params={'limit': 1}, headers=auth(tokens)).json()
    assert len(paged['items']) == 1 and paged['has_more'] is True and paged['next_cursor']

    # Viewing attempts approved nothing: drafts are still drafts, publication is explicit.
    assert db.scalar("SELECT COUNT(*) FROM regulatory_requirement WHERE status!='DRAFT'") == 0
    processing = client.get(PREFIX + f'/documents/{version}/processing', headers=auth(tokens)).json()
    assert processing['attempt_counts'] == {'SUCCEEDED': 3}
    for row in db.q("SELECT id FROM regulatory_requirement"):
        assert client.post(PREFIX + f"/reviews/requirement/{row['id']}", headers=auth(tokens),
                           json={'decision': 'APPROVED', 'comment': 'Synthetic fixture approved for test only.'}).status_code == 200
    assert client.post(PREFIX + '/publish', headers=auth(tokens)).status_code == 200
    cov = client.get(PREFIX + '/jurisdictions/EU/coverage', headers=auth(tokens)).json()
    eu = next(item for item in cov['items'] if item['code'] == 'EU')
    assert eu['requirements']['published'] == 2 and eu['stage'] == 'REQUIREMENTS_PUBLISHED'
    actions = {a['action']: a for a in cov['next_actions']}
    assert len(actions['draft_mapping']['requirement_ids']['ids']) == 2
    template = next(t for t in cov['evaluation_templates']['items'] if t['framework_id'] == 'SYN-EU-ACT')
    assert template['readiness'] == 'NOT_READY' or template['readiness'] == 'PARTIAL'


def test_attempts_persist_failures_with_raw_output(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db)
    s.sync(db, {f'https://{s.DOMAIN}/act/en': s.ACT_EN_V1}, tmp_path)
    vid = db.scalar('SELECT MAX(id) FROM regulatory_document_version')
    catalog.review_document_version(db, vid, reviewer='bob', decision='APPROVED')

    def script(system, prompt):
        if s.ROTATION_QUOTE in prompt:
            return '{"requirements": [{"quote": "Operators shall'  # malformed / truncated-looking
        if 'review privileged access' in prompt:
            return {'requirements': [s.candidate('Financial entities shall rotate keys at least every 12 months, always.')]}
        raise LlmError('gpu out of memory')

    stats = extraction.extract_version(db, vid, s.FakeLlm(script), job_id='job-fixture-1')
    assert stats['drafted'] == 0 and stats['llm_errors'] == 2  # one crash, one malformed
    rows = {r['section_id']: r for r in db.q('SELECT * FROM extraction_attempt WHERE version_id=?', (vid,))}
    by_status = {r['status'] for r in rows.values()}
    assert by_status == {'LLM_ERROR', 'MALFORMED_OUTPUT', 'VALIDATION_FAILED'}
    for r in rows.values():
        assert r['job_id'] == 'job-fixture-1' and r['started_at'] <= r['finished_at']
    crash = next(r for r in rows.values() if r['status'] == 'LLM_ERROR')
    assert crash['raw_response'] is None and 'failed before any output' in crash['raw_unavailable_reason']
    assert crash['error'].startswith('LlmError')
    malformed = next(r for r in rows.values() if r['status'] == 'MALFORMED_OUTPUT')
    assert malformed['raw_response'].startswith('{"requirements"') and malformed['parsed_json'] is None
    assert 'invalid JSON' in malformed['error']
    invalid = next(r for r in rows.values() if r['status'] == 'VALIDATION_FAILED')
    assert invalid['parsed_json']['requirements'] and invalid['validated_json'] == {'requirements': []}
    err = invalid['validation_errors'][0]
    assert err['path'] == 'requirements[0].quote' and err['code'] == 'UNGROUNDED_QUOTE'
    assert invalid['rejected_candidates'][0]['candidate']['quote'].startswith('Financial entities')


def test_translation_attempts_are_recorded(tmp_path):
    db = s.make_db(tmp_path)
    s.setup_synthetic(db, languages=('de',))
    s.sync(db, {f'https://{s.DOMAIN}/act/de': s.ACT_DE}, tmp_path)
    vid = db.scalar('SELECT MAX(id) FROM regulatory_document_version')
    catalog.review_document_version(db, vid, reviewer='bob', decision='APPROVED')

    def script(system, prompt):
        if system == extraction.SYSTEM_TRANSLATE:
            return 'nicht json'  # translation output the runtime returned malformed
        if s.ROTATION_QUOTE_DE in prompt:
            return {'requirements': [s.candidate(s.ROTATION_QUOTE_DE, thresholds=['90 Tage'])]}
        return {'requirements': []}

    stats = extraction.extract_version(db, vid, s.FakeLlm(script))
    assert stats['drafted'] == 1 and stats['translation_failures'] == 1
    t = db.one("SELECT * FROM extraction_attempt WHERE kind='TRANSLATION'")
    assert t['status'] == 'MALFORMED_OUTPUT' and t['raw_response'] == 'nicht json'
    assert t['requirement_id'] == stats['requirement_ids'][0]
    assert t['prompt_version'] == extraction.TRANSLATE_PROMPT_VERSION
    req = db.one('SELECT translation_en, translation_status FROM regulatory_requirement WHERE id=?',
                 (t['requirement_id'],))
    assert req['translation_en'] is None and req['translation_status'] == 'UNREVIEWED'


def test_resolve_scope_exact_only(tmp_path):
    db = s.make_db(tmp_path)
    scope = discovery.resolve_scope(db, 'DE', False, '2026-01-01')
    assert [e['code'] for e in scope] == ['DE'] and scope[0]['inherited'] is False
    inherited = discovery.resolve_scope(db, 'DE', True, '2026-01-01')
    assert {'DE', 'EU'} <= {e['code'] for e in inherited}
