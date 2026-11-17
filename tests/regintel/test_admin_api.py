"""Real HTTP upload/review/publication workflow with synthetic documents only."""
from __future__ import annotations

import hashlib
import json
from contextlib import nullcontext

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from regintel.admin_api import PREFIX, create_admin_app
from regintel.db import CatalogDb
from regintel.jobs import Jobs
from . import support as s


@pytest.fixture
def env(tmp_path):
    db=s.make_db(tmp_path)
    s.setup_synthetic(db)
    entries=[]
    tokens={}
    for name,scopes in [('uploader',['catalog:operate','catalog:review']),('reviewer',['catalog:review']),
                        ('publisher',['catalog:publish']),('reader',['catalog:read'])]:
        secret='synthetic-test-secret-'+name
        tokens[name]=f'{name}.{secret}'
        entries.append({'key_id':name,'secret_sha256':hashlib.sha256(secret.encode()).hexdigest(),
                        'scopes':scopes,'tenants':['acme'],'enabled':True})
    credentials=tmp_path/'clients.json'
    credentials.write_text(json.dumps({'clients':entries}))
    settings=Settings(api_clients_file=credentials,catalog_db_path=db.path,
                      catalog_jobs_db_path=tmp_path/'jobs.db',catalog_upload_dir=tmp_path/'uploads')
    app=create_admin_app(settings,start_worker=False)
    with TestClient(app) as client:
        yield client,db,tokens,app.state.jobs
    db.close()


def auth(tokens,name):
    return {'Authorization':'Bearer '+tokens[name]}


def upload(client,tokens,**params):
    query={'framework_id':'SYN-EU-ACT','filename':'synthetic.html','language':'en',
           'provenance':'Synthetic test document obtained from an authorized test repository.',
           'license_note':'Synthetic fixture; test use permitted',**params}
    return client.post(PREFIX+'/uploads',params=query,content=s.ACT_EN_V1.encode(),headers=auth(tokens,'uploader'))


def test_upload_review_extract_publish_roundtrip(env,monkeypatch):
    client,db,tokens,jobs=env
    response=upload(client,tokens)
    assert response.status_code==201,response.text
    source_id=response.json()['source_id']
    assert db.scalar('SELECT status FROM source WHERE id=?',(source_id,))=='PROPOSED'
    verify={'outcome':'VERIFIED','evidence':'Reviewer checked synthetic provenance and the complete test file.'}
    # Caller cannot replace the authenticated identity.
    assert client.post(PREFIX+f'/sources/{source_id}/verify',json={**verify,'actor':'another-user'},headers=auth(tokens,'reviewer')).status_code==422
    assert client.post(PREFIX+f'/sources/{source_id}/verify',json=verify,headers=auth(tokens,'reviewer')).status_code==200
    request={'action':'sync','source_id':source_id,'request_key':'upload-sync-key'}
    first=client.post(PREFIX+'/jobs',json=request,headers=auth(tokens,'uploader')).json()['job']
    again=client.post(PREFIX+'/jobs',json=request,headers=auth(tokens,'uploader')).json()['job']
    assert first['id']==again['id']
    assert jobs.run_once()
    assert jobs.get(first['id'])['status']=='SUCCEEDED'
    docs=client.get(PREFIX+'/documents',headers=auth(tokens,'reviewer')).json()['items']
    version=docs[0]['id']
    details=client.get(PREFIX+f'/documents/{version}',headers=auth(tokens,'reviewer')).json()
    assert details['document']['status']=='AWAITING_REVIEW' and details['items']
    decision={'decision':'APPROVED','comment':'Reviewed complete synthetic text.'}
    assert client.post(PREFIX+f'/documents/{version}/review',json=decision,headers=auth(tokens,'reviewer')).status_code==200
    from regintel import __main__ as cli
    monkeypatch.setattr(cli,'_llm',lambda:nullcontext(s.good_llm()))
    job=client.post(PREFIX+'/jobs',json={'action':'extract','version_id':version,'request_key':'extract-test-key'},
                    headers=auth(tokens,'uploader')).json()['job']
    assert jobs.run_once() and jobs.get(job['id'])['status']=='SUCCEEDED'
    drafts=client.get(PREFIX+'/requirements',headers=auth(tokens,'reviewer')).json()['items']
    assert len(drafts)>=2
    # The remote service can show what the model produced, with the text it was produced from.
    result=client.get(PREFIX+f"/jobs/{job['id']}",headers=auth(tokens,'reviewer')).json()['job']['result']
    assert result['requirement_ids']==[d['id'] for d in drafts] and result['model'] and result['runtime']
    processed=client.get(PREFIX+f'/documents/{version}/processing',headers=auth(tokens,'reviewer')).json()
    assert processed['requirement_counts']=={'DRAFT':len(drafts)} and processed['sections']>0
    assert {j['payload']['action'] for j in processed['jobs']}=={'sync','extract'}
    assert processed['models'][0]['model']==result['model'] and processed['models'][0]['requirements']==len(drafts)
    for item in processed['items']:
        assert item['original_text'] in item['section']['text'] and item['extraction']['method']=='LOCAL_LLM'
    assert client.get(PREFIX+f'/documents/{version}/processing',headers=auth(tokens,'reader')).status_code==403
    detail=client.get(PREFIX+f"/requirements/{drafts[0]['id']}",headers=auth(tokens,'reviewer')).json()
    assert detail['requirement']['section']['text'] and detail['document']['source_id']==source_id and detail['reviews']==[]
    assert client.get(PREFIX+'/requirements/999999',headers=auth(tokens,'reviewer')).status_code==404
    assert db.scalar('SELECT COUNT(*) FROM regulatory_requirement WHERE published_seq IS NOT NULL')==0
    for draft in drafts:
        response=client.post(PREFIX+f"/reviews/requirement/{draft['id']}",json=decision,headers=auth(tokens,'reviewer'))
        assert response.status_code==200,response.text
    response=client.post(PREFIX+'/publish',headers=auth(tokens,'publisher'))
    assert response.status_code==200,response.text
    assert db.scalar('SELECT COUNT(*) FROM regulatory_requirement WHERE published_seq IS NOT NULL')==len(drafts)
    assert db.scalar("SELECT COUNT(*) FROM review_approval WHERE reviewer='reviewer'")>0


def test_permissions_and_upload_validation(env):
    client,db,tokens,_=env
    assert client.get(PREFIX+'/documents').status_code==401
    assert client.get(PREFIX+'/documents',headers=auth(tokens,'reader')).status_code==403
    assert client.post(PREFIX+'/publish',headers=auth(tokens,'reviewer')).status_code==403
    assert upload(client,tokens,filename='../escape.html').status_code==422
    assert upload(client,tokens,filename='bad.exe').status_code==422
    assert upload(client,tokens,filename='bad.pdf').status_code==422
    assert client.post(PREFIX+'/uploads',params={'framework_id':'SYN-EU-ACT','filename':'empty.txt','language':'en',
                       'provenance':'A sufficiently long description for this synthetic test','license_note':'test'},
                       content=b'',headers=auth(tokens,'uploader')).status_code==422
    assert db.scalar("SELECT COUNT(*) FROM source WHERE id LIKE 'upload-%'")==0


def test_job_restart_and_request_key_conflict(env):
    _,_,_,jobs=env
    first=jobs.submit('uploader','key-test-1',{'action':'sync','source_id':'missing'})
    with pytest.raises(Exception,match='IDEMPOTENCY_CONFLICT'):
        jobs.submit('uploader','key-test-1',{'action':'sync','source_id':'different'})
    assert jobs.run_once()
    assert jobs.get(first['id'])['status']=='FAILED'
    second=jobs.submit('uploader','key-test-2',{'action':'sync','source_id':'missing'})
    with jobs.connect() as connection:
        connection.execute("UPDATE job SET status='RUNNING' WHERE id=?",(second['id'],))
    recovered=Jobs(jobs.path,jobs.catalog_path)
    assert recovered.get(second['id'])['status']=='INTERRUPTED'


def test_remote_framework_registration_and_conflicts(env):
    client,db,tokens,_=env
    authority={'id':'new-authority','name':'Synthetic additional authority','jurisdiction':'INT',
               'official_domains':['example.test'],'languages':['en']}
    response=client.post(PREFIX+'/authorities',json=authority,headers=auth(tokens,'uploader'))
    assert response.status_code==201,response.text
    assert client.post(PREFIX+'/authorities',json=authority,headers=auth(tokens,'uploader')).status_code==409
    framework={'id':'NEW-STANDARD','title':'Synthetic standard','kind':'STANDARD','adoption':'VOLUNTARY',
               'jurisdiction':'INT','authority_id':'new-authority'}
    assert client.post(PREFIX+'/frameworks',json=framework,headers=auth(tokens,'reviewer')).status_code==403
    assert client.post(PREFIX+'/frameworks',json=framework,headers=auth(tokens,'uploader')).status_code==201
    assert db.scalar("SELECT verification_status FROM regulatory_framework WHERE id='NEW-STANDARD'")=='UNVERIFIED'
    assert upload(client,tokens,framework_id='NEW-STANDARD').status_code==201


def test_upload_limit(env):
    client,_,tokens,_=env
    client.app.state.settings.max_body_bytes=10
    assert upload(client,tokens).status_code==413


def test_pdf_upload_with_no_text_cannot_be_approved(env):
    import io
    pypdf=pytest.importorskip('pypdf')
    client,db,tokens,jobs=env
    writer=pypdf.PdfWriter()
    writer.add_blank_page(width=100,height=100)
    stream=io.BytesIO()
    writer.write(stream)
    query={'framework_id':'SYN-EU-ACT','filename':'scan.pdf','language':'en',
           'provenance':'Synthetic empty PDF fixture from an authorized test repository.', 'license_note':'Synthetic test use'}
    response=client.post(PREFIX+'/uploads',params=query,content=stream.getvalue(),headers=auth(tokens,'uploader'))
    assert response.status_code==201,response.text
    source_id=response.json()['source_id']
    assert client.post(PREFIX+f'/sources/{source_id}/verify',json={'outcome':'VERIFIED','evidence':query['provenance']},
                       headers=auth(tokens,'reviewer')).status_code==200
    job=jobs.submit('uploader','pdf-parse-key',{'action':'sync','source_id':source_id})
    jobs.run_once()
    assert jobs.get(job['id'])['status']=='SUCCEEDED'
    version=db.scalar('SELECT MAX(id) FROM regulatory_document_version')
    assert db.scalar('SELECT complete FROM regulatory_document_version WHERE id=?',(version,))==0
    response=client.post(PREFIX+f'/documents/{version}/review',json={'decision':'APPROVED','comment':'Complete document.'},
                         headers=auth(tokens,'reviewer'))
    assert response.json()['error']['code']=='DOCUMENT_INCOMPLETE'


@pytest.mark.parametrize('operation',['upload','review'])
def test_client_does_not_replay_management_mutations(operation):
    import httpx
    from client.securden_opm_client import OpmClient,OpmTransientError,RetryPolicy
    calls=[]
    def handler(request):
        calls.append(request)
        return httpx.Response(503,json={'error':{'code':'UNAVAILABLE','message':'test'}})
    client=OpmClient.__new__(OpmClient)
    client.retry=RetryPolicy(max_attempts=4)
    client._http=httpx.Client(base_url='https://example.test',transport=httpx.MockTransport(handler))
    with client,pytest.raises(OpmTransientError):
        if operation=='upload':
            client.catalog_upload(b'test',framework_id='TEST',filename='test.txt',language='en',
                                  provenance='test provenance',license_note='test')
        else:
            client.catalog_admin_action('publish')
    assert len(calls)==1


def test_registered_framework_approve_or_reject_with_findings(env):
    client,db,tokens,_=env
    authority={'id':'new-authority','name':'Synthetic additional authority','jurisdiction':'INT','official_domains':['example.test']}
    framework={'id':'NEW-STANDARD','title':'Synthetic standard','kind':'STANDARD','adoption':'VOLUNTARY',
               'jurisdiction':'INT','authority_id':'new-authority'}
    assert client.post(PREFIX+'/authorities',json=authority,headers=auth(tokens,'uploader')).status_code==201
    assert client.post(PREFIX+'/frameworks',json=framework,headers=auth(tokens,'uploader')).status_code==201
    get=lambda: client.get(PREFIX+'/frameworks/NEW-STANDARD',headers=auth(tokens,'reviewer')).json()
    assert get()['framework']['review_status']=='PENDING' and get()['framework']['last_review'] is None
    post=lambda body,who='reviewer': client.post(PREFIX+'/frameworks/NEW-STANDARD/verify',json=body,headers=auth(tokens,who))
    assert post({'decision':'APPROVED'},'publisher').status_code==403
    missing=post({'decision':'REJECTED'})
    assert missing.status_code==422 and missing.json()['error']['code']=='FINDINGS_REQUIRED'
    rejected=post({'decision':'REJECTED','findings':'Title does not match the official publication.'})
    assert rejected.status_code==200 and rejected.json()['status']=='REJECTED'
    state=get()
    assert state['framework']['review_status']=='REJECTED' and state['framework']['verification_status']=='UNVERIFIED'
    assert state['framework']['last_review']['findings']=='Title does not match the official publication.'
    # Dates and lifecycle still need a reviewed official document; a plain approval does not.
    dated=post({'decision':'APPROVED','lifecycle':'IN_FORCE','effective_from':'2024-01-01'})
    assert dated.status_code==409 and dated.json()['error']['code']=='EVIDENCE_NOT_REVIEWED'
    approved=post({'decision':'APPROVED','findings':'Identity and issuing authority confirmed.'})
    assert approved.status_code==200 and approved.json()['status']=='APPROVED' and approved.json()['publication']>0
    state=get()
    assert state['framework']['review_status']=='APPROVED' and state['framework']['lifecycle']=='UNKNOWN'
    assert state['framework']['verified_by']=='reviewer' and [r['decision'] for r in state['reviews']]==['APPROVED','REJECTED']
    listed={f['id']:f for f in client.get(PREFIX+'/frameworks',headers=auth(tokens,'reviewer')).json()['items']}
    assert listed['NEW-STANDARD']['review_status']=='APPROVED' and listed['NEW-STANDARD']['last_review']['reviewer']=='reviewer'
    assert client.get(PREFIX+'/frameworks/NOPE',headers=auth(tokens,'reviewer')).status_code==404
    assert post({'decision':'REJECTED','findings':'Withdrawn after a second look.'}).status_code==200
    assert get()['framework']['verification_status']=='UNVERIFIED'


def test_remote_region_registration(env):
    client,db,tokens,_=env
    region={'code':'ZZR','kind':'SUPRANATIONAL','name':'Synthetic regional body'}
    assert client.post(PREFIX+'/jurisdictions',json=region,headers=auth(tokens,'reviewer')).status_code==403
    response=client.post(PREFIX+'/jurisdictions',json=region,headers=auth(tokens,'uploader'))
    assert response.status_code==201,response.text
    assert db.scalar("SELECT registry_source FROM jurisdiction WHERE code='ZZR'")=='manual:uploader'
    assert client.post(PREFIX+'/jurisdictions',json=region,headers=auth(tokens,'uploader')).status_code==409
    bad=client.post(PREFIX+'/jurisdictions',json={**region,'code':'zzr'},headers=auth(tokens,'uploader'))
    assert bad.status_code==422 and bad.json()['error']['code']=='INVALID_CODE'
    assert client.post(PREFIX+'/jurisdictions',json={**region,'code':'ZZS','kind':'REGION'},
                       headers=auth(tokens,'uploader')).status_code==422
    orphan=client.post(PREFIX+'/jurisdictions',json={**region,'code':'ZZS','parent_code':'QQ'},headers=auth(tokens,'uploader'))
    assert orphan.status_code==404 and orphan.json()['error']['code']=='UNKNOWN_JURISDICTION'
    member={'group':'ZZR','member':'DE','valid_from':'2020-01-01'}
    assert client.post(PREFIX+'/jurisdictions/memberships',json=member,headers=auth(tokens,'uploader')).status_code==201
    assert client.post(PREFIX+'/jurisdictions/memberships',json=member,headers=auth(tokens,'uploader')).status_code==409
    assert client.post(PREFIX+'/jurisdictions/memberships',json={**member,'valid_from':'2021-01-01','valid_to':'2020-06-01'},
                       headers=auth(tokens,'uploader')).status_code==422
    # A framework can now be registered for the new region.
    authority={'id':'zzr-authority','name':'Synthetic regional authority','jurisdiction':'ZZR','official_domains':['example.test']}
    assert client.post(PREFIX+'/authorities',json=authority,headers=auth(tokens,'uploader')).status_code==201


def test_error_statuses_and_envelopes(env):
    client,_,tokens,_=env
    probe=client.get(PREFIX+'/health',headers=auth(tokens,'uploader')).json()
    assert probe['status']=='ok' and probe['key_id']=='uploader' and probe['schema_version']
    assert probe['scopes']==['catalog:operate','catalog:review']
    verify={'outcome':'VERIFIED','evidence':'Reviewer checked synthetic provenance and the complete test file.'}
    for response,status,code in [
        (client.post(PREFIX+'/sources/upload-missing/verify',json=verify,headers=auth(tokens,'reviewer')),404,'UNKNOWN_SOURCE'),
        (client.get(PREFIX+'/jobs/missing',headers=auth(tokens,'reviewer')),404,'UNKNOWN_JOB'),
        (client.get(PREFIX+'/documents/999999',headers=auth(tokens,'reviewer')),404,'NOT_FOUND'),
        (client.post(PREFIX+'/documents/999999/review',json={'decision':'APPROVED','comment':'Complete.'},
                     headers=auth(tokens,'reviewer')),404,'NOT_FOUND'),
        (client.get(PREFIX+'/no-such-resource',headers=auth(tokens,'reviewer')),404,'NOT_FOUND'),
        (client.get(PREFIX+'/publish',headers=auth(tokens,'publisher')),405,'METHOD_NOT_ALLOWED'),
        (upload(client,tokens,framework_id='NO-SUCH-FRAMEWORK'),422,'FRAMEWORK_AUTHORITY_REQUIRED'),
    ]:
        assert response.status_code==status,response.text
        body=response.json()
        assert body['error']['code']==code and body['correlation_id']


def test_malformed_source_config_is_rejected_not_a_server_error(env):
    client,db,tokens,_=env
    authority=db.one('SELECT * FROM regulatory_authority ORDER BY id LIMIT 1')
    def source(discovery,adapter='static_list'):
        return {'id':'remote-proposed','adapter_type':adapter,'name':'Synthetic proposal','authority_id':authority['id'],
                'jurisdiction':authority['jurisdiction_code'],'languages':['en'],
                'config':{'allowed_domains':authority['official_domains'][:1],'formats':['html'],'discovery':discovery,
                          'version_identification':'content_sha256','change_detection':'content_sha256',
                          'licensing':{'license':'Synthetic fixture'},'verification_method':'HUMAN_ATTESTATION'}}
    for body in [source({'method':'static_list','documents':[{'url':'https://x.example/a','language':'en'}]}),
                 source({'method':'static_list','documents':['not-an-object']}),
                 source({'method':'index_page','index_url':'https://x.example/','link_pattern':'(','language':'en'},'index_page')]:
        response=client.post(PREFIX+'/sources',json=body,headers=auth(tokens,'uploader'))
        assert response.status_code==422,response.text
        assert response.json()['error']['code']=='INVALID_SOURCE_CONFIG'
    # file_drop reads host paths, so it is only reachable through /uploads.
    assert client.post(PREFIX+'/sources',json=source({'method':'file_drop','directory':'C:/'},'file_drop'),
                       headers=auth(tokens,'uploader')).status_code==422
    assert db.scalar("SELECT COUNT(*) FROM source WHERE id='remote-proposed'")==0


def test_document_listing_filters(env):
    client,db,tokens,jobs=env
    source_id=upload(client,tokens).json()['source_id']
    other=upload(client,tokens,filename='second.txt').json()['source_id']
    verify={'outcome':'VERIFIED','evidence':'Reviewer checked synthetic provenance and the complete test file.'}
    for index,identifier in enumerate((source_id,other)):
        assert client.post(PREFIX+f'/sources/{identifier}/verify',json=verify,headers=auth(tokens,'reviewer')).status_code==200
        jobs.submit('uploader',f'filter-key-{index}',{'action':'sync','source_id':identifier})
        assert jobs.run_once()
    listing=lambda **q: client.get(PREFIX+'/documents',params=q,headers=auth(tokens,'reviewer'))
    assert len(listing().json()['items'])==2
    mine=listing(source_id=source_id).json()['items']
    assert [row['source_id'] for row in mine]==[source_id]

    assert listing(source_id=source_id,status='REVIEWED').json()['items']==[]
    assert listing(status='BOGUS').status_code==422


def test_uploader_with_review_scope_can_verify_its_own_upload(env):
    client,db,tokens,_=env
    source_id=upload(client,tokens).json()['source_id']
    verify={'outcome':'VERIFIED','evidence':'Uploader checked synthetic provenance and the complete test file.'}
    assert client.post(PREFIX+f'/sources/{source_id}/verify',json=verify,headers=auth(tokens,'uploader')).status_code==200
    row=db.one('SELECT verifier FROM source_verification WHERE source_id=?',(source_id,))
    assert row['verifier']=='uploader' and db.scalar('SELECT proposed_by FROM source WHERE id=?',(source_id,))=='uploader'


def test_workflow_visibility(env,monkeypatch):
    """Each pipeline step answers 'what happened and what do I do next' without DB access."""
    client,db,tokens,jobs=env
    health=client.get(PREFIX+'/health',headers=auth(tokens,'reviewer')).json()
    assert 'policy_bundle_version' in health  # comparable with the evaluator's /api/v1/version
    body=upload(client,tokens).json()
    assert body['source_id'] and body['next_step']  # upload names the next required action
    source_id=body['source_id']
    verify={'outcome':'VERIFIED','evidence':'Reviewer checked synthetic provenance and the complete test file.'}
    verified=client.post(PREFIX+f'/sources/{source_id}/verify',json=verify,headers=auth(tokens,'reviewer')).json()
    assert verified['source_id']==source_id and 'sync' in verified['next_step']
    jobs.submit('uploader','visibility-sync',{'action':'sync','source_id':source_id})
    assert jobs.run_once()
    job=client.get(PREFIX+'/jobs',headers=auth(tokens,'reviewer')).json()['items'][0]
    assert job['started_at'] and job['finished_at'] and job['status']=='SUCCEEDED'
    result=job['result']
    # Sync names every produced version with completeness, so parsing failures are visible.
    assert result['versions'] and result['versions'][0]['outcome']=='NEW'
    v=result['versions'][0]
    assert v['version_id'] and v['complete'] is True and v['sections']>0 and v['content_sha256']
    assert result['versions_unchanged']==0 and result['warnings']==[]
    # jobs listing: status filter and pagination fields
    page=client.get(PREFIX+'/jobs',params={'status':'FAILED'},headers=auth(tokens,'reviewer')).json()
    assert page['items']==[] and page['has_more'] is False and page['next_cursor'] is None
    jobs.submit('uploader','visibility-sync-2',{'action':'sync','source_id':source_id})
    assert jobs.run_once()
    first=client.get(PREFIX+'/jobs',params={'limit':1},headers=auth(tokens,'reviewer')).json()
    assert len(first['items'])==1 and first['has_more'] is True and first['next_cursor']
    rest=client.get(PREFIX+'/jobs',params={'limit':1,'after':first['next_cursor']},headers=auth(tokens,'reviewer')).json()
    assert len(rest['items'])==1 and rest['items'][0]['id']!=first['items'][0]['id']
    # a repeat sync of identical content is reported as UNCHANGED, not silently dropped
    newest=first['items'][0]  # newest first: the second sync
    assert newest['result']['versions_unchanged']==1 and newest['result']['versions'][0]['outcome']=='UNCHANGED'
    assert rest['items'][0]['result']['versions'][0]['outcome']=='NEW'
    from contextlib import nullcontext
    from regintel import __main__ as cli
    monkeypatch.setattr(cli,'_llm',lambda:nullcontext(s.good_llm()))
    # job failures keep the full error (code and message), not just an exception class name
    jobs.submit('uploader','visibility-crash',{'action':'extract','version_id':999999})
    assert jobs.run_once()
    failed=client.get(PREFIX+'/jobs',params={'status':'FAILED'},headers=auth(tokens,'reviewer')).json()['items'][0]
    assert failed['error'].startswith('UNKNOWN_DOCUMENT_VERSION')
    # requirements listing: framework filter plus section and publication state on each row
    version=client.get(PREFIX+'/documents',headers=auth(tokens,'reviewer')).json()['items'][0]['id']
    decision={'decision':'APPROVED','comment':'Reviewed complete synthetic text.'}
    assert client.post(PREFIX+f'/documents/{version}/review',json=decision,headers=auth(tokens,'reviewer')).status_code==200
    jobs.submit('uploader','visibility-extract',{'action':'extract','version_id':version})
    assert jobs.run_once()
    rows=client.get(PREFIX+'/requirements',params={'framework_id':'SYN-EU-ACT'},headers=auth(tokens,'reviewer')).json()['items']
    assert rows and all(r['framework_id']=='SYN-EU-ACT' and r['section_ref'] and r['published_seq'] is None for r in rows)
    assert client.get(PREFIX+'/requirements',params={'framework_id':'SYN-STD'},headers=auth(tokens,'reviewer')).json()['items']==[]
    # publication failures are structured: details.problems lists each blocked entity
    db.x("UPDATE regulatory_requirement SET status='APPROVED' WHERE id=?",(rows[0]['id'],))  # approval without review record
    blocked=client.post(PREFIX+'/publish',headers=auth(tokens,'publisher'))
    assert blocked.status_code==409 and blocked.json()['error']['code']=='PUBLICATION_BLOCKED'
    problems=blocked.json()['error']['details']['problems']
    assert any('no approval record' in p for p in problems)


def test_empty_extraction_is_flagged_not_silent(env,monkeypatch):
    client,db,tokens,jobs=env
    source_id=upload(client,tokens).json()['source_id']
    verify={'outcome':'VERIFIED','evidence':'Reviewer checked synthetic provenance and the complete test file.'}
    assert client.post(PREFIX+f'/sources/{source_id}/verify',json=verify,headers=auth(tokens,'reviewer')).status_code==200
    jobs.submit('uploader','empty-sync',{'action':'sync','source_id':source_id})
    assert jobs.run_once()
    version=client.get(PREFIX+'/documents',headers=auth(tokens,'reviewer')).json()['items'][0]['id']
    decision={'decision':'APPROVED','comment':'Reviewed complete synthetic text.'}
    assert client.post(PREFIX+f'/documents/{version}/review',json=decision,headers=auth(tokens,'reviewer')).status_code==200
    from contextlib import nullcontext
    from regintel import __main__ as cli
    monkeypatch.setattr(cli,'_llm',lambda:nullcontext(s.FakeLlm(lambda system,prompt:{'requirements':[]})))
    job=jobs.submit('uploader','empty-extract',{'action':'extract','version_id':version})
    assert jobs.run_once()
    finished=jobs.get(job['id'])
    assert finished['result']['drafted']==0
    assert finished['result']['warnings'] and 'not evidence of compliance' in finished['result']['warnings'][0]


def test_client_admin_pagination_and_none_parameters():
    import httpx
    from client.securden_opm_client import OpmClient,RetryPolicy
    seen=[]
    def handler(request):
        seen.append(dict(request.url.params))
        first='after' not in request.url.params
        return httpx.Response(200,json={'schema_version':'1.0','catalog_version':0,'items':[1,2] if first else [3],
                                        'has_more':first,'next_cursor':'2' if first else None})
    client=OpmClient.__new__(OpmClient)
    client.retry=RetryPolicy(max_attempts=1)
    client._http=httpx.Client(base_url='https://example.test',transport=httpx.MockTransport(handler))
    with client:
        assert list(client.catalog_admin_iter('requirements',status='DRAFT',version_id=None))==[1,2,3]
    assert seen==[{'limit':'200','status':'DRAFT'},{'limit':'200','after':'2','status':'DRAFT'}]
