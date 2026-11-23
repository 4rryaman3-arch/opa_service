"""Host-side management API. Never mounted in the read-only evaluation app."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from contextlib import asynccontextmanager
from datetime import date
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, ConfigDict, Field
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import Settings
from app.errors import (ServiceError, http_error_handler, service_error_handler, unhandled_error_handler,
                        validation_error_handler)
from app.metrics import Metrics
from app.middleware import ServiceMiddleware
from app.security import ApiKeyStore, Principal, TokenBucketLimiter, authenticate, authorize_tenant, require_scope
from . import SCHEMA_VERSION, automation, catalog, coverage, discovery, generated_rules, mapping_policy, orgscope, registry
from . import plan as planning
from . import policy_contexts as pctx
from . import progress as progress_mod
from .db import CatalogDb, CatalogError, digest_of, now_iso
from .jobs import Jobs
from .pam_configuration import PamConfigurationIn
from .sources import registry as sources
from .sources.base import SourceConfig

PREFIX = '/api/v1/catalog/admin'
operate = require_scope('catalog:operate')
reviewer = require_scope('catalog:review')
publisher = require_scope('catalog:publish')


class Model(BaseModel):
    model_config = ConfigDict(extra='forbid')


# CatalogError codes that are not workflow conflicts (409 is the default).
UNPROCESSABLE = frozenset({'EVIDENCE_REQUIRED','DOMAIN_NOT_REGISTERED','UNSUPPORTED_FORMAT','UNSUPPORTED_DISCOVERY',
                           'NO_ALLOWLIST','LANGUAGE_REQUIRED','REASON_REQUIRED','FINDINGS_REQUIRED',
                           'UNKNOWN_RULE','RULE_VERSION_UNAVAILABLE','EVIDENCE_TYPE_MISMATCH',
                           'UNKNOWN_EVIDENCE_TYPE','UNVERIFIED_CONFIGURATION'})


def catalog_error_status(code: str) -> int:
    """HTTP status for a CatalogError; callers should still branch on error.code."""
    if code in UNPROCESSABLE or code.startswith(('INVALID_','MISSING_')):
        return 422
    if code == 'NOT_FOUND' or code.startswith('UNKNOWN_'):
        return 404
    if code == 'QUEUE_FULL':
        return 503
    return 409


class JurisdictionCreate(Model):
    code: str = Field(min_length=2, max_length=7)
    kind: Literal['COUNTRY_OR_TERRITORY','SUBDIVISION','SUPRANATIONAL','INTERNATIONAL']
    name: str = Field(min_length=1, max_length=300)
    parent_code: str | None = Field(default=None, max_length=10)


class MembershipCreate(Model):
    group: str = Field(max_length=10)
    member: str = Field(max_length=10)
    valid_from: date
    valid_to: date | None = None


class MappingCreate(Model):
    requirement_id: int = Field(gt=0)
    assessment: Literal['AUTOMATED','MANUAL']
    rationale: str = Field(min_length=20, max_length=4000)
    limitations: str = Field(min_length=10, max_length=4000)
    pam_control_id: str | None = Field(default=None, max_length=64)
    control_reference: str | None = Field(default=None, min_length=1, max_length=200)
    # AUTOMATED only
    rule_id: str | None = Field(default=None, max_length=100)
    rule_version_min: str | None = Field(default=None, pattern=r"^\d{1,3}\.\d{1,3}$")
    rule_version_max: str | None = Field(default=None, pattern=r"^\d{1,3}\.\d{1,3}$")
    evidence_type: str | None = Field(default=None, max_length=64)
    parameters: dict[str, bool | int] = Field(default_factory=dict, max_length=50)
    override_constraints: dict[str, dict[str, int | list[bool]]] = Field(default_factory=dict, max_length=50)
    coverage: Literal['FULL','PARTIAL'] | None = None


class Withdrawal(Model):
    reason: str = Field(min_length=10, max_length=4000)


class SourceReview(Model):
    outcome: Literal['VERIFIED', 'REJECTED']
    evidence: str = Field(min_length=30, max_length=4000)


class AuthorityCreate(Model):
    id: str = Field(max_length=100)
    name: str = Field(min_length=1,max_length=300)
    jurisdiction: str = Field(max_length=10)
    official_domains: list[str] = Field(max_length=20)
    languages: list[str] = Field(default_factory=list,max_length=50)


class FrameworkCreate(Model):
    id: str = Field(max_length=48)
    title: str = Field(min_length=1,max_length=300)
    kind: Literal['LAW','REGULATION','DIRECTIVE','STANDARD','GUIDELINE','INDUSTRY_FRAMEWORK']
    adoption: Literal['STATUTORY','VOLUNTARY','CONTRACTUAL']
    jurisdiction: str = Field(max_length=10)
    authority_id: str = Field(max_length=100)
    industries: list[str] = Field(default_factory=list,max_length=100)
    cross_border: bool = False


class SourceCreate(Model):
    id: str = Field(max_length=100)
    adapter_type: Literal['eurlex','static_list','index_page']
    name: str = Field(min_length=1,max_length=300)
    authority_id: str = Field(max_length=100)
    jurisdiction: str = Field(max_length=10)
    config: SourceConfig
    languages: list[str] = Field(min_length=1,max_length=50)


class Decision(Model):
    decision: Literal['APPROVED', 'REJECTED']
    comment: str = Field(min_length=3, max_length=4000)
    reviewed_in_original_language: bool = False


class DocumentReview(Decision):
    published_on: date | None = None
    effective_from: date | None = None
    effective_to: date | None = None
    supersede_previous: bool = False


class FrameworkReview(Model):
    decision: Literal['APPROVED','REJECTED'] = 'APPROVED'
    findings: str = Field(default='', max_length=4000)
    # Optional: only needed to record lifecycle/dates, which must be confirmed from a reviewed document.
    evidence_version_id: int | None = Field(default=None, gt=0)
    lifecycle: Literal['NOT_YET_IN_FORCE','IN_FORCE','REPEALED','SUPERSEDED'] | None = None
    published_on: date | None = None
    effective_from: date | None = None
    effective_to: date | None = None
    superseded_by: str | None = Field(default=None, max_length=48)


class TranslationReview(Model):
    decision: Literal['REVIEWED','REJECTED']
    corrected_translation: str | None = Field(default=None, max_length=8000)


class Sync(Model):
    action: Literal['sync']
    source_id: str = Field(min_length=1, max_length=100)
    request_key: str = Field(min_length=8, max_length=100)


class Extract(Model):
    action: Literal['extract']
    version_id: int = Field(gt=0)
    translate: bool = True
    request_key: str = Field(min_length=8, max_length=100)


class Discover(Model):
    """Start Regulatory Intelligence for one selected jurisdiction. Runs on the
    worker: inventories configured authorities/frameworks/sources for the scope,
    submits child sync jobs for human-verified sources and reports the human
    review checkpoints as next_actions. Never fetches arbitrary URLs."""

    action: Literal['discover']
    jurisdiction: str = Field(min_length=2, max_length=7)
    include_inherited: bool = True
    as_of: date | None = None  # membership date for inherited scope; defaults to today
    request_key: str = Field(min_length=8, max_length=100)


class PrepareCatalog(Model):
    """Django rewrite contract 1.0: one-shot automated preparation. 'discovery'
    runs the automated pipeline over every approved framework registered for the
    requested jurisdictions (OPM's own authority/source registry - never the
    open internet). 'import' processes previously uploaded, organization-scoped
    documents, identifying their framework first. Requires catalog:automate and
    the X-Securden-Organization-Scope header."""

    action: Literal['prepare_catalog']
    mode: Literal['discovery','import']
    jurisdictions: list[str] = Field(min_length=1, max_length=20)
    industry: str | None = Field(default=None, max_length=64)
    requested_framework_ids: list[str] = Field(default_factory=list, max_length=20)
    include_inherited: bool = True
    document_ids: list[int] | None = Field(default=None, max_length=100)  # import mode: scoped upload documents
    # collector handshake / policy / PAM configuration owner for LLM-assisted mapping (defaults to the
    # organization's single declared tenant)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r'^[A-Za-z0-9._:-]+$')
    llm_mapping: bool = True
    # bounded rule generation (DJANGO_CONTRACT §5.4): validated RuleSpec proposals for requirements no existing
    # rule covers; activation additionally needs auto_publish_validated_rules and the pinned handshake digest
    auto_rule_generation: bool = False
    auto_publish_validated_rules: bool = False
    collector_capability_digest: str | None = Field(default=None, pattern=r'^sha256:[0-9a-f]{64}$')
    translate: bool = True
    as_of: date | None = None
    languages: list[Annotated[str, Field(pattern=r'^[a-z]{2,3}$')]] | None = Field(default=None, max_length=10)
    screening: Literal['none','pam-keyword-screen-v1'] | None = None
    request_key: str = Field(min_length=8, max_length=100)


class GenerateRules(Model):
    """Rule generation only (DJANGO_CONTRACT §5.4): for requirements already published in the caller's scope,
    existing-rule matching then propose / validate / compile / test / activate, without retrieving or re-extracting
    documents. Same gates as prepare_catalog's auto_rule_generation; monitor with GET /jobs/{id}/progress."""

    action: Literal['generate_rules']
    requested_framework_ids: list[str] = Field(min_length=1, max_length=20)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128, pattern=r'^[A-Za-z0-9._:-]+$')
    auto_rule_generation: Literal[True] = True  # implied; lets check_rule_generation apply unchanged
    llm_mapping: Literal[True] = True
    auto_publish_validated_rules: bool = False
    collector_capability_digest: str | None = Field(default=None, pattern=r'^sha256:[0-9a-f]{64}$')
    request_key: str = Field(min_length=8, max_length=100)


OPTIONAL_JOB_FIELDS = ('languages', 'screening')  # omitted from the stored payload when unset (stable dedup)
DEFAULTED_JOB_FIELDS = {'tenant_id': None, 'llm_mapping': True, 'auto_rule_generation': False,
                        'auto_publish_validated_rules': False, 'collector_capability_digest': None}


def envelope(db, **data):
    return {'schema_version': SCHEMA_VERSION, 'catalog_version': db.catalog_version(), **data}


def database(request: Request):
    db = CatalogDb(request.app.state.settings.catalog_db_path)
    try:
        yield db
    finally:
        db.close()


def framework_view(db, row):
    # Review outcome for display: PENDING (never decided), APPROVED or REJECTED, plus the last findings.
    last=db.one("SELECT decision,reviewer,comment AS findings,decided_at FROM review_approval "
                "WHERE entity_type='framework' AND entity_id=? ORDER BY id DESC LIMIT 1",(row['id'],))
    rejected=bool(last) and last['decision']=='REJECTED'
    row['review_status']='APPROVED' if row['verification_status']=='VERIFIED' else 'REJECTED' if rejected else 'PENDING'
    row['last_review']=last
    return row


def request_scope(request: Request, db, principal: Principal) -> str | None:
    """Validated, credential-bound organization scope of this request, or None."""
    try:
        return orgscope.validate_and_bind(db, request.headers.get(orgscope.HEADER), principal.key_id)
    except orgscope.ScopeError as exc:
        raise ServiceError(exc.status, exc.code, exc.message) from exc


def admin_reader(principal: Principal = Depends(authenticate)):
    if not principal.scopes.intersection({'catalog:operate','catalog:review','catalog:publish','catalog:automate'}):
        raise ServiceError(403,'FORBIDDEN','Catalog management permission required')
    return principal


def create_admin_app(settings: Settings | None = None, *, start_worker=True):
    settings = settings or Settings()
    jobs = Jobs(settings.catalog_jobs_db_path, settings.catalog_db_path, bundle_dir=settings.policy_bundle_dir,
                rule_store_path=settings.db_path)

    @asynccontextmanager
    async def lifespan(app):
        if start_worker:
            jobs.start()
        try:
            yield
        finally:
            if start_worker:
                jobs.close()

    app = FastAPI(title='OPM catalog management', lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings, app.state.jobs = settings, jobs
    CatalogDb(settings.catalog_db_path).close()  # create / migrate the schema before the read-only API needs it
    try:  # rule catalog of the policy bundle, used to validate execution mappings
        from app.engine.catalog import Catalog
        engine = Catalog.load(settings.policy_bundle_dir)
    except (OSError, KeyError, ValueError, RuntimeError):
        engine = None
    app.state.engine = engine
    app.state.metrics = Metrics()
    app.state.api_keys = ApiKeyStore.from_file(settings.api_clients_file)
    app.state.rate_limiter = TokenBucketLimiter(settings.rate_limit_per_minute, settings.rate_limit_burst)
    app.state.auth_failure_limiter = TokenBucketLimiter(settings.auth_failure_limit_per_minute, settings.auth_failure_limit_per_minute)
    app.add_exception_handler(ServiceError, service_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)

    app.add_exception_handler(StarletteHTTPException, http_error_handler)

    @app.exception_handler(CatalogError)
    async def workflow_error(request, exc):
        headers={'Retry-After':'30'} if exc.code=='QUEUE_FULL' else None
        return await service_error_handler(request, ServiceError(catalog_error_status(exc.code),exc.code,exc.message,
                                                                 details=getattr(exc,'details',None),headers=headers))

    @app.exception_handler(sqlite3.OperationalError)
    async def busy(request, exc):
        # Typically "database is locked": the worker or another request holds the write lock.
        return await service_error_handler(request,ServiceError(503,'CATALOG_BUSY',
            'The catalog database is busy; check current state before repeating the request',
            headers={'Retry-After':'5'}))

    @app.exception_handler(sqlite3.IntegrityError)
    async def conflict(request, exc):
        return await service_error_handler(request,ServiceError(409,'CATALOG_CONFLICT',
            'The identifier already exists or a referenced catalog entity is missing'))

    app.add_middleware(ServiceMiddleware, max_body_bytes=settings.max_body_bytes, metrics=app.state.metrics)

    @app.get('/health')
    def liveness():
        return {'status':'ok'}

    @app.get(PREFIX+'/health')
    def health(db=Depends(database), principal: Principal = Depends(admin_reader)):
        # Lets a remote caller confirm routing, the credential and which management actions it may perform.
        # policy_bundle_version lets operators confirm this process loaded the same bundle as the evaluator.
        enabled=automation.AUTOMATION_SCOPE in principal.scopes
        return envelope(db,status='ok',key_id=principal.key_id,
                        scopes=sorted(s for s in principal.scopes if s.startswith('catalog:')),
                        policy_bundle_version=engine.bundle_version if engine else None,
                        # Capability advertisement: Django shows the automated trigger only when
                        # 'catalog:automate' is in scopes; the policy version identifies the decision rules.
                        automation={'scope':automation.AUTOMATION_SCOPE,
                                    'policy_version':automation.POLICY_VERSION,
                                    'enabled':enabled},
                        # Django-rewrite handshake (contract 1.0). The scoped workflow runs under
                        # catalog:automate, so the capabilities are advertised with that permission.
                        rewrite_contract_version=orgscope.REWRITE_CONTRACT_VERSION,
                        capabilities={name: (enabled and value) for name, value in orgscope.CAPABILITIES.items()},
                        rule_generation={
                            'supported': True,
                            'auto_rule_generation': generated_rules.generation_enabled(),
                            'auto_publish_validated_rules': generated_rules.publish_enabled(),
                            'compiler_version': generated_rules.COMPILER_VERSION,
                            'spec_version': generated_rules.SPEC_VERSION,
                        })

    @app.get(PREFIX+'/sources')
    def source_list(db=Depends(database), _: Principal = Depends(admin_reader)):
        return envelope(db, items=db.q('SELECT * FROM source ORDER BY id'))

    @app.get(PREFIX+'/frameworks')
    def frameworks(db=Depends(database), _: Principal = Depends(admin_reader)):
        return envelope(db,items=[framework_view(db,row) for row in db.q('SELECT * FROM regulatory_framework ORDER BY id')])

    @app.get(PREFIX+'/frameworks/{framework_id}')
    def framework(framework_id: str, db=Depends(database), _: Principal = Depends(admin_reader)):
        row=db.one('SELECT * FROM regulatory_framework WHERE id=?',(framework_id,))
        if row is None:
            raise ServiceError(404,'UNKNOWN_FRAMEWORK','Framework not found')
        history=db.q("SELECT id,decision,reviewer,comment AS findings,attestations,decided_at FROM review_approval "
                     "WHERE entity_type='framework' AND entity_id=? ORDER BY id DESC",(framework_id,))
        return envelope(db,framework=framework_view(db,row),reviews=history)

    @app.get(PREFIX+'/frameworks/{framework_id}/mapping-gaps')
    def framework_mapping_gaps(framework_id: str, request: Request, db=Depends(database),
                               principal: Principal = Depends(admin_reader)):
        """Per published requirement: executable rules bound to it and structured gap codes
        (mapping_policy.GAP_CODES), computed live. Global requirements plus the caller's own scope."""
        if db.one('SELECT id FROM regulatory_framework WHERE id=?',(framework_id,)) is None:
            raise ServiceError(404,'UNKNOWN_FRAMEWORK','Framework not found')
        scope=request_scope(request,db,principal)
        ids=[r['id'] for r in db.q(
            "SELECT id FROM regulatory_requirement WHERE framework_id=? AND status='APPROVED' "
            "AND published_seq IS NOT NULL AND (organization_scope IS NULL"+(" OR organization_scope=?" if scope else "")
            +") ORDER BY id",(framework_id,*([scope] if scope else [])))]
        items=automation.requirement_mapping_gaps(db,engine,ids,scope=scope)
        extra={'organization_scope':scope} if scope else {}
        return envelope(db,framework_id=framework_id,items=items,engine_available=engine is not None,
                        bridge_collected_rules=list(mapping_policy.bridge_collected_rules()),
                        gap_codes=list(mapping_policy.GAP_CODES),
                        **extra)

    @app.get(PREFIX+'/authorities')
    def authorities(db=Depends(database), _: Principal = Depends(admin_reader)):
        return envelope(db,items=db.q('SELECT * FROM regulatory_authority ORDER BY id'))

    @app.post(PREFIX+'/jurisdictions',status_code=201)
    def create_jurisdiction(body: JurisdictionCreate,db=Depends(database),principal: Principal=Depends(operate)):
        registry.add_jurisdiction(db,**body.model_dump(),actor=principal.key_id)
        return envelope(db,code=body.code,status='REGISTERED')

    @app.post(PREFIX+'/jurisdictions/memberships',status_code=201)
    def create_membership(body: MembershipCreate,db=Depends(database),principal: Principal=Depends(operate)):
        if body.valid_to is not None and body.valid_to<=body.valid_from:
            raise ServiceError(422,'INVALID_DATE','valid_to is exclusive and must be after valid_from')
        registry.add_membership(db,**body.model_dump(mode='json'),actor=principal.key_id)
        return envelope(db,group=body.group,member=body.member,status='REGISTERED')

    @app.post(PREFIX+'/authorities',status_code=201)
    def create_authority(body: AuthorityCreate,db=Depends(database),principal: Principal=Depends(operate)):
        registry.add_authority(db,**body.model_dump(),actor=principal.key_id)
        return envelope(db,id=body.id,status='UNVERIFIED')

    @app.post(PREFIX+'/frameworks',status_code=201)
    def create_framework(body: FrameworkCreate,db=Depends(database),principal: Principal=Depends(operate)):
        registry.add_framework(db,**body.model_dump(),actor=principal.key_id)
        return envelope(db,id=body.id,status='UNVERIFIED')

    @app.post(PREFIX+'/sources',status_code=201)
    def create_source(body: SourceCreate,db=Depends(database),principal: Principal=Depends(operate)):
        sources.propose_source(db,**body.model_dump(),actor=principal.key_id)
        return envelope(db,id=body.id,status='PROPOSED')

    @app.get(PREFIX+'/documents')
    def documents(after: int = Query(0,ge=0), limit: int = Query(100,ge=1,le=500),
                  source_id: str | None = Query(None,max_length=100),
                  status: str | None = Query(None,pattern='^(AWAITING_REVIEW|REVIEWED|REJECTED|SUPERSEDED)$'),
                  db=Depends(database), _: Principal = Depends(admin_reader)):
        rows = db.q('SELECT v.*,d.title,d.framework_id,d.language,d.source_id,d.external_id FROM regulatory_document_version v '
                    'JOIN regulatory_document d ON d.id=v.document_id WHERE v.id>? AND (? IS NULL OR d.source_id=?) '
                    'AND (? IS NULL OR v.status=?) ORDER BY v.id LIMIT ?',
                    (after,source_id,source_id,status,status,limit+1))
        return envelope(db,items=rows[:limit],has_more=len(rows)>limit,next_cursor=str(rows[limit-1]['id']) if len(rows)>limit else None)

    @app.get(PREFIX+'/documents/{version_id}')
    def document(version_id: int, after: int = Query(0,ge=0), limit: int = Query(100,ge=1,le=500),
                 db=Depends(database), _: Principal = Depends(admin_reader)):
        row=db.one('SELECT v.*,d.framework_id,d.language,d.source_id,d.title,d.url FROM regulatory_document_version v '
                   'JOIN regulatory_document d ON d.id=v.document_id WHERE v.id=?',(version_id,))
        if row is None:
            raise ServiceError(404,'NOT_FOUND','Document version not found')
        sections=db.q('SELECT * FROM document_section WHERE version_id=? AND ordinal>? ORDER BY ordinal LIMIT ?',
                      (version_id,after,limit+1))
        return envelope(db,document=row,items=sections[:limit],has_more=len(sections)>limit,
                        next_cursor=str(sections[limit-1]['ordinal']) if len(sections)>limit else None)

    @app.get(PREFIX+'/requirements')
    def requirements(status: str = Query('DRAFT',pattern='^(DRAFT|APPROVED|REJECTED|WITHDRAWN|SUPERSEDED|REPEALED)$'),
                     version_id: int | None = None, framework_id: str | None = Query(None,max_length=48),
                     after: int = Query(0,ge=0),limit: int = Query(100,ge=1,le=500),
                     db=Depends(database), _: Principal = Depends(admin_reader)):
        rows=db.q('SELECT * FROM regulatory_requirement WHERE status=? AND id>? AND (? IS NULL OR document_version_id=?) '
                  'AND (? IS NULL OR framework_id=?) ORDER BY id LIMIT ?',
                  (status,after,version_id,version_id,framework_id,framework_id,limit+1))
        return envelope(db,items=rows[:limit],has_more=len(rows)>limit,next_cursor=str(rows[limit-1]['id']) if len(rows)>limit else None)

    def with_content(db, rows):
        """Attach the source section (the text the model was shown) to requirement rows."""
        for row in rows:
            row['section']=db.one('SELECT id,ordinal,section_ref,heading,text FROM document_section WHERE id=?',
                                  (row['section_id'],))
        return rows

    @app.get(PREFIX+'/requirements/{requirement_id}')
    def requirement(requirement_id: int, db=Depends(database), _: Principal = Depends(admin_reader)):
        row=db.one('SELECT * FROM regulatory_requirement WHERE id=?',(requirement_id,))
        if row is None:
            raise ServiceError(404,'NOT_FOUND','Requirement not found')
        document=db.one('SELECT v.id,v.version_label,v.status,v.complete,v.content_sha256,d.title,d.framework_id,d.language,'
                        'd.source_id FROM regulatory_document_version v JOIN regulatory_document d ON d.id=v.document_id '
                        'WHERE v.id=?',(row['document_version_id'],))
        history=db.q("SELECT * FROM review_approval WHERE entity_type IN ('requirement','translation') AND entity_id=? "
                     'ORDER BY id',(str(requirement_id),))
        return envelope(db,requirement=with_content(db,[row])[0],document=document,reviews=history)

    @app.get(PREFIX+'/documents/{version_id}/processing')
    def processing(version_id: int, after: int = Query(0,ge=0), limit: int = Query(100,ge=1,le=500),
                   status: str | None = Query(None,pattern='^(DRAFT|APPROVED|REJECTED|WITHDRAWN|SUPERSEDED|REPEALED)$'),
                   db=Depends(database), _: Principal = Depends(admin_reader)):
        # What processing produced for one document version: jobs, model details and the drafted
        # requirements with the section text each was extracted from.
        row=db.one('SELECT v.*,d.framework_id,d.language,d.source_id,d.title,d.url FROM regulatory_document_version v '
                   'JOIN regulatory_document d ON d.id=v.document_id WHERE v.id=?',(version_id,))
        if row is None:
            raise ServiceError(404,'NOT_FOUND','Document version not found')
        counts={r['status']:r['n'] for r in db.q('SELECT status,COUNT(*) AS n FROM regulatory_requirement '
                                                 'WHERE document_version_id=? GROUP BY status',(version_id,))}
        models=db.q("SELECT json_extract(extraction,'$.model') AS model,json_extract(extraction,'$.model_version') AS model_version,"
                    "json_extract(extraction,'$.runtime') AS runtime,json_extract(extraction,'$.prompt_version') AS prompt_version,"
                    'COUNT(*) AS requirements FROM regulatory_requirement WHERE document_version_id=? GROUP BY 1,2,3,4',(version_id,))
        rows=db.q('SELECT * FROM regulatory_requirement WHERE document_version_id=? AND id>? AND (? IS NULL OR status=?) '
                  'ORDER BY id LIMIT ?',(version_id,after,status,status,limit+1))
        attempt_counts={r['status']:r['n'] for r in db.q('SELECT status,COUNT(*) AS n FROM extraction_attempt '
                                                         'WHERE version_id=? GROUP BY status',(version_id,))}
        return envelope(db,document=row,
                        sections=db.scalar('SELECT COUNT(*) FROM document_section WHERE version_id=?',(version_id,)),
                        jobs=jobs.related(version_id,row['source_id']),requirement_counts=counts,models=models,
                        attempt_counts=attempt_counts,
                        items=with_content(db,rows[:limit]),has_more=len(rows)>limit,
                        next_cursor=str(rows[limit-1]['id']) if len(rows)>limit else None)

    ATTEMPT_NOTE=('raw_response is the model’s generated output exactly as returned (it may be malformed or '
                  'truncated) and is never approved content; approval exists only on requirement rows. Prompts and '
                  'internal model material are not stored. Render all values as escaped text.')

    @app.get(PREFIX+'/documents/{version_id}/attempts')
    def attempts(version_id: int, after: int = Query(0,ge=0), limit: int = Query(50,ge=1,le=200),
                 kind: str | None = Query(None,pattern='^(EXTRACTION|TRANSLATION|REVIEW|TRANSLATION_REVIEW)$'),
                 status: str | None = Query(None,pattern='^(SUCCEEDED|PARTIAL|VALIDATION_FAILED|MALFORMED_OUTPUT|LLM_ERROR)$'),
                 db=Depends(database), _: Principal = Depends(admin_reader)):
        # Every LLM call made for this document version, success or failure, with raw /
        # parsed / validated output kept strictly apart from human-approved content.
        if db.one('SELECT 1 FROM regulatory_document_version WHERE id=?',(version_id,)) is None:
            raise ServiceError(404,'NOT_FOUND','Document version not found')
        rows=db.q('SELECT * FROM extraction_attempt WHERE version_id=? AND id>? AND (? IS NULL OR kind=?) '
                  'AND (? IS NULL OR status=?) ORDER BY id LIMIT ?',
                  (version_id,after,kind,kind,status,status,limit+1))
        items=rows[:limit]
        for row in items:
            row['raw_truncated']=bool(row['raw_truncated'])
            if row['raw_response'] is None and not row['raw_unavailable_reason']:
                row['raw_unavailable_reason']='raw output was not retained for this attempt'
            row['section']=db.one('SELECT id,ordinal,section_ref,heading,text FROM document_section WHERE id=?',
                                  (row['section_id'],)) if row['section_id'] else None
        return envelope(db,items=items,has_more=len(rows)>limit,
                        next_cursor=str(items[-1]['id']) if len(rows)>limit else None,note=ATTEMPT_NOTE)

    @app.get(PREFIX+'/jurisdictions/{code}/coverage')
    def jurisdiction_coverage(code: str, include_inherited: bool = True, as_of: date | None = None,
                              db=Depends(database), _: Principal = Depends(admin_reader)):
        # Evidence-based coverage for one selected jurisdiction: its own content plus,
        # with include_inherited, parent/group content marked with its origin. Computed
        # from the same catalog database that the public reads and plans use.
        when=(as_of or date.today()).isoformat()
        scope=discovery.resolve_scope(db,code,include_inherited,when)  # 404 UNKNOWN_JURISDICTION
        items=[{**entry,**coverage.coverage_detail(db,entry['code'])} for entry in scope]
        codes=[e['code'] for e in scope]
        via={e['code']:e['via'] for e in scope}
        templates=[]
        readiness={'READY':0,'PARTIAL':0,'NOT_READY':0}
        if engine is not None:
            frameworks=db.q(f"SELECT * FROM regulatory_framework WHERE jurisdiction_code IN ({','.join('?'*len(codes))}) "
                            'ORDER BY id',codes)
            for fw in frameworks:
                summary=planning.template_summary(planning.build_plan(db,fw,when,engine))
                summary['jurisdiction_match']='EXACT' if fw['jurisdiction_code']==code else 'INHERITED'
                summary['jurisdiction_path']=via.get(fw['jurisdiction_code'])
                readiness[summary['readiness']]+=1
                templates.append(summary)
        return envelope(db,jurisdiction=code,as_of=when,include_inherited=include_inherited,items=items,
                        evaluation_templates={'items':templates,'by_readiness':readiness,
                                              'engine_available':engine is not None},
                        next_actions=discovery.next_actions(db,codes),statement=coverage.STATEMENT)

    def mapping_view(db, row):
        row['mapping_version']=row.pop('version')
        row['parameters']=row.pop('rule_parameters')
        row['assessment']=row['assessment'] or 'CONTROL_REFERENCE'
        requirement=db.one('SELECT framework_id,section_ref,status FROM regulatory_requirement WHERE id=?',(row['requirement_id'],))
        row.update(framework_id=requirement['framework_id'],section_ref=requirement['section_ref'],
                   requirement_status=requirement['status'])
        row['last_review']=db.one("SELECT decision,reviewer,comment,decided_at FROM review_approval WHERE entity_type='mapping' "
                                  'AND entity_id=? ORDER BY id DESC LIMIT 1',(str(row['id']),))
        return row

    @app.post(PREFIX+'/mappings',status_code=201)
    def create_mapping(body: MappingCreate, db=Depends(database), principal: Principal=Depends(operate)):
        if body.assessment=='AUTOMATED' and engine is None:
            raise ServiceError(503,'RULE_CATALOG_UNAVAILABLE','The policy bundle is not readable by the management process')
        identifier=catalog.create_mapping(db,**body.model_dump(),actor=principal.key_id,
                                          engine_rules=engine.rules if engine else None)
        row=db.one('SELECT * FROM framework_control_mapping WHERE id=?',(identifier,))
        return envelope(db,mapping=mapping_view(db,row),status='DRAFT',
                        next_step='Review with POST /reviews/mapping/{id}, then POST /publish')

    @app.get(PREFIX+'/mappings')
    def mappings(framework_id: str | None = Query(None,max_length=48), requirement_id: int | None = Query(None,ge=1),
                 status: str | None = Query(None,pattern='^(DRAFT|APPROVED|REJECTED|WITHDRAWN)$'),
                 after: int = Query(0,ge=0), limit: int = Query(100,ge=1,le=500),
                 db=Depends(database), _: Principal = Depends(admin_reader)):
        rows=db.q('SELECT m.* FROM framework_control_mapping m JOIN regulatory_requirement r ON r.id=m.requirement_id '
                  'WHERE m.id>? AND (? IS NULL OR r.framework_id=?) AND (? IS NULL OR m.requirement_id=?) '
                  'AND (? IS NULL OR m.status=?) ORDER BY m.id LIMIT ?',
                  (after,framework_id,framework_id,requirement_id,requirement_id,status,status,limit+1))
        return envelope(db,items=[mapping_view(db,row) for row in rows[:limit]],has_more=len(rows)>limit,
                        next_cursor=str(rows[limit-1]['id']) if len(rows)>limit else None)

    @app.get(PREFIX+'/mappings/{mapping_id}')
    def mapping(mapping_id: int, db=Depends(database), _: Principal = Depends(admin_reader)):
        row=db.one('SELECT * FROM framework_control_mapping WHERE id=?',(mapping_id,))
        if row is None:
            raise ServiceError(404,'NOT_FOUND','Mapping not found')
        history=db.q("SELECT id,decision,reviewer,comment,decided_at FROM review_approval WHERE entity_type='mapping' "
                     'AND entity_id=? ORDER BY id DESC',(str(mapping_id),))
        return envelope(db,mapping=mapping_view(db,row),reviews=history)

    @app.post(PREFIX+'/mappings/{mapping_id}/withdraw')
    def withdraw_mapping(mapping_id: int, body: Withdrawal, db=Depends(database), principal: Principal=Depends(publisher)):
        result=catalog.withdraw(db,'mapping',mapping_id,actor=principal.key_id,reason=body.reason)
        return envelope(db,status='WITHDRAWN',result=result)

    @app.get(PREFIX+'/rule-catalog')
    def rule_catalog(request: Request, db=Depends(database), principal: Principal = Depends(admin_reader)):
        # Rules a mapping may reference, with the parameters that must be stated. With the organization scope
        # header, that organization's generated rules (origin GENERATED, with provenance) are listed too.
        if engine is None:
            raise ServiceError(503,'RULE_CATALOG_UNAVAILABLE','The policy bundle is not readable by the management process')
        from . import generated_rules as gr
        scope=request_scope(request,db,principal)
        view=gr.engine_for(db,engine,scope)
        provenance=getattr(view,'generated',{})
        controls={r['rule_id']:r['pam_control_id'] for r in db.q('SELECT rule_id,pam_control_id FROM opa_rule_definition')}
        items=[{'rule_id':rule_id,'pam_control_id':controls.get(rule_id),
                'origin':'GENERATED' if rule_id.startswith('PAM-GEN-') else next(
                    (spec.public()['origin'] for spec in versions.values()),'BUILT_IN'),
                'versions':[{**spec.public(),**({'generated_rule':provenance[(rule_id,v)]}
                                                if (rule_id,v) in provenance else {})}
                            for v,spec in sorted(versions.items())]}
               for rule_id,versions in sorted(view.rules.items())]
        return envelope(db,policy_bundle_version=engine.bundle_version,items=items)

    @app.get(PREFIX+'/pending')
    def pending(db=Depends(database), _: Principal = Depends(admin_reader)):
        return envelope(db,pending=catalog.pending_publication(db))

    @app.get(PREFIX+'/reviews')
    def reviews(after: int = Query(0,ge=0), limit: int = Query(100,ge=1,le=500),
                db=Depends(database), _: Principal = Depends(admin_reader)):
        rows=db.q('SELECT * FROM review_approval WHERE id>? ORDER BY id LIMIT ?',(after,limit+1))
        return envelope(db,items=rows[:limit],has_more=len(rows)>limit,next_cursor=str(rows[limit-1]['id']) if len(rows)>limit else None)

    UPLOAD_LIMIT_V1=5*1024*1024

    @app.post(PREFIX+'/uploads',status_code=201)
    async def upload(request: Request, response: Response, framework_id: str = Query(default='',max_length=48),
                     filename: str = Query(min_length=1,max_length=150,pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]*\.(pdf|html|txt|json)$'),
                     language: str = Query(default='en',pattern=r'^[a-z]{2,3}(-[A-Za-z0-9]{2,8})?$'),
                     provenance: str = Query(min_length=30,max_length=2000),
                     license_note: str = Query(min_length=3,max_length=300),
                     jurisdictions: str | None = Query(default=None,max_length=200),
                     request_key: str | None = Query(default=None,min_length=8,max_length=100),
                     principal: Principal = Depends(operate), db=Depends(database)):
        scope=request_scope(request,db,principal)
        v1=scope is not None
        if v1 and not request_key:
            raise ServiceError(422,'REQUEST_KEY_REQUIRED','Scoped uploads need a caller-generated request_key')
        codes:list[str]=[]
        if v1:
            try:
                codes=json.loads(jurisdictions or '[]')
                assert isinstance(codes,list) and all(isinstance(c,str) for c in codes) and codes
            except (ValueError,AssertionError):
                raise ServiceError(422,'INVALID_JURISDICTIONS','jurisdictions must be a non-empty JSON array of codes')
            for code in codes:
                registry.require_jurisdiction(db,code)
        fw=None
        if framework_id:
            fw=db.one('SELECT * FROM regulatory_framework WHERE id=?',(framework_id,))
            if fw is None or not orgscope.visible(fw,scope):
                raise ServiceError(404 if v1 else 422,
                                   'UNKNOWN_FRAMEWORK' if v1 else 'FRAMEWORK_AUTHORITY_REQUIRED',
                                   'Framework is not registered'+(' in this scope.' if v1 else ' with an authority'))
        if not v1 and (fw is None or not fw['authority_id']):
            raise ServiceError(422,'FRAMEWORK_AUTHORITY_REQUIRED','Choose a registered framework with an authority')
        limit=min(settings.max_body_bytes,UPLOAD_LIMIT_V1) if v1 else settings.max_body_bytes
        content=bytearray()
        async for chunk in request.stream():
            content.extend(chunk)
            if len(content)>limit:
                raise ServiceError(413,'PAYLOAD_TOO_LARGE','Upload exceeds the 5 MiB limit' if v1 else
                                   'Upload exceeds configured body limit')
        if not content:
            raise ServiceError(422,'EMPTY_UPLOAD','The uploaded document is empty')
        fmt=filename.rsplit('.',1)[1]
        if fmt=='pdf' and not content.startswith(b'%PDF-'):
            raise ServiceError(422,'INVALID_PDF','Uploaded bytes are not a PDF')
        if fmt=='json':
            from . import textproc
            check=textproc.parse_oscal_catalog(bytes(content))
            if not check.sections:
                raise ServiceError(422,'INVALID_OSCAL',f'JSON uploads must be OSCAL catalogs: {check.incomplete_reason}')
        digest=hashlib.sha256(content).hexdigest()
        params=digest_of({'filename':filename,'language':language,'provenance':provenance,
                                  'license_note':license_note,'jurisdictions':codes,'framework_id':framework_id})
        if v1:  # idempotency per (actor, scope, request_key); changed bytes or metadata are rejected
            prior=db.one('SELECT * FROM upload_request WHERE actor=? AND organization_scope=? AND request_key=?',
                         (principal.key_id,scope,request_key))
            if prior is not None:
                if prior['content_sha256']!=digest or prior['params_digest']!=params:
                    raise ServiceError(409,'IDEMPOTENCY_CONFLICT',
                                       'This request key was used for different content or metadata')
                response.status_code=200
                return envelope(db,organization_scope=scope,document_ids=prior['document_ids'],
                                content_sha256=prior['content_sha256'],source_id=prior['source_id'],
                                source_origin='UPLOADED_DOCUMENT')
        source_id='upload-'+uuid.uuid4().hex
        directory=settings.catalog_upload_dir.resolve()/source_id
        directory.mkdir(parents=True)
        path=directory/(digest+'.'+fmt)
        path.write_bytes(content)
        if v1 and fw is None:
            authority_id='org-upload-'+digest_of(scope)[:12]  # per-scope holder of uploaded material
            if db.one('SELECT 1 FROM regulatory_authority WHERE id=?',(authority_id,)) is None:
                db.insert('regulatory_authority',id=authority_id,name='Organization uploads (scoped, not an authority)',
                          jurisdiction_code=codes[0],official_domains=[],languages=[],created_at=now_iso())
            auth_id,jur=authority_id,codes[0]
        else:
            auth_id,jur=fw['authority_id'],fw['jurisdiction_code']  # type: ignore[index]
        config={'allowed_domains':[], 'formats':[fmt], 'discovery':{'method':'file_drop','directory':str(directory),
            'documents':[{'file':path.name,'external_id':'UPL-'+digest[:20], 'framework_id':framework_id or None,
                          'language':language,'title':filename}],
            **({'jurisdictions':codes} if codes else {})}, 'version_identification':'content_sha256',
            'change_detection':'content_sha256', 'rate_limit':{'min_interval_seconds':0},
            'licensing':{'license':license_note,'redistribute_text':False,'notes':provenance},
            'verification_method':'HUMAN_FILE_PROVENANCE_REVIEW' if not v1 else 'SCOPED_UPLOAD_PROVENANCE_RECORD'}
        try:
            sources.propose_source(db,source_id,'file_drop',filename,auth_id,jur,
                                   config,languages=[language],actor=principal.key_id)
        except Exception:
            path.unlink(missing_ok=True)
            directory.rmdir()
            raise
        if not v1:
            return envelope(db,source_id=source_id,status='PROPOSED',sha256=digest,bytes=len(content),
                            next_step='Verify provenance (catalog:review), then submit a sync job')
        with db.tx():
            db.x('UPDATE source SET organization_scope=? WHERE id=?',(scope,source_id))
        # The scoped upload is parsed now so Django immediately gets document ids. Verification here is a
        # recorded AUTOMATED policy decision: the material is organization-scoped working input, never
        # globally visible and never labelled official (source_origin stays UPLOADED_DOCUMENT).
        sources.verify_source(db,source_id,verifier=automation.engine_actor(principal.key_id),outcome='VERIFIED',
                              evidence=f'AUTOMATED ({automation.POLICY_VERSION}): organization-scoped upload; '
                                       f'uploader-recorded provenance and licensing retained; content sha256 {digest}. '
                                       'Scoped material is isolated to its namespace and never labelled official.',
                              origin='AUTOMATED',policy_version=automation.POLICY_VERSION)
        sources.sync_source(db,source_id,blob_dir=settings.catalog_db_path.parent/'documents',
                            actor=automation.engine_actor(principal.key_id))
        with db.tx():
            db.x('UPDATE regulatory_document SET organization_scope=? WHERE source_id=?',(scope,source_id))
        document_ids=[r['id'] for r in db.q('SELECT id FROM regulatory_document WHERE source_id=? ORDER BY id',(source_id,))]
        db.insert('upload_request',actor=principal.key_id,organization_scope=scope,request_key=request_key,
                  params_digest=params,content_sha256=digest,source_id=source_id,document_ids=document_ids,
                  created_at=now_iso())
        return envelope(db,organization_scope=scope,document_ids=document_ids,content_sha256=digest,
                        source_id=source_id,source_origin='UPLOADED_DOCUMENT')

    @app.post(PREFIX+'/sources/{source_id}/verify')
    def verify_source(source_id: str, body: SourceReview, db=Depends(database), principal: Principal=Depends(reviewer)):
        sources.verify_source(db,source_id,verifier=principal.key_id,**body.model_dump())
        next_step=('Submit a sync job (POST jobs with action "sync") to retrieve and parse the documents'
                   if body.outcome=='VERIFIED' else 'Source rejected; propose a corrected source if needed')
        return envelope(db,status=body.outcome,source_id=source_id,next_step=next_step)

    @app.post(PREFIX+'/documents/{version_id}/review')
    def review_document(version_id: int, body: DocumentReview, db=Depends(database), principal: Principal=Depends(reviewer)):
        values=body.model_dump(mode='json',exclude={'reviewed_in_original_language'})
        catalog.review_document_version(db,version_id,reviewer=principal.key_id,**values)
        return envelope(db,status=body.decision)

    @app.post(PREFIX+'/frameworks/{framework_id}/verify')
    def verify_framework(framework_id: str, body: FrameworkReview, db=Depends(database), principal: Principal=Depends(reviewer)):
        seq=registry.verify_framework(db,framework_id,reviewer=principal.key_id,**body.model_dump(mode='json'))
        return envelope(db,status=body.decision,publication=seq)

    @app.post(PREFIX+'/requirements/{requirement_id}/translation-review')
    def translation(requirement_id: int, body: TranslationReview, db=Depends(database), principal: Principal=Depends(reviewer)):
        catalog.review_translation(db,requirement_id,reviewer=principal.key_id,**body.model_dump())
        return envelope(db,status=body.decision)

    @app.post(PREFIX+'/reviews/{kind}/{identifier}')
    def review(kind: Literal['requirement','mapping','evidence_requirement','applicability_criteria','remediation'],
               identifier: int, body: Decision, db=Depends(database), principal: Principal=Depends(reviewer)):
        catalog.review(db,kind,identifier,reviewer=principal.key_id,decision=body.decision,comment=body.comment,
                       attestations={'reviewed_in_original_language':body.reviewed_in_original_language})
        return envelope(db,status=body.decision)

    @app.post(PREFIX+'/publish')
    def publish(db=Depends(database), principal: Principal=Depends(publisher)):
        return envelope(db,publication=catalog.publish_catalog(db,principal.key_id))

    def check_rule_generation(db, body: 'PrepareCatalog', scope: str) -> None:
        """Generation and activation are each behind a service flag AND an explicit job field; activation is
        bound to one tenant and to the collector declaration the caller reviewed (pinned digest)."""
        from . import generated_rules as gr
        if body.auto_publish_validated_rules and not body.auto_rule_generation:
            raise ServiceError(422,'INVALID_RULE_GENERATION','auto_publish_validated_rules requires auto_rule_generation')
        if body.collector_capability_digest is not None and not body.auto_rule_generation:
            raise ServiceError(422,'INVALID_RULE_GENERATION','collector_capability_digest is only used with '
                                   'auto_rule_generation')
        if body.auto_rule_generation:
            if not gr.generation_enabled():
                raise ServiceError(422,'RULE_GENERATION_DISABLED',f'automatic rule generation is disabled on this '
                                       f'service ({gr.FLAG_GENERATE}=false)')
            if not body.llm_mapping:
                raise ServiceError(422,'INVALID_RULE_GENERATION','auto_rule_generation runs after llm_mapping; '
                                       'llm_mapping must be true')
        if body.auto_publish_validated_rules:
            if not gr.publish_enabled():
                raise ServiceError(422,'RULE_PUBLICATION_DISABLED',f'automatic activation of generated rules is '
                                       f'disabled on this service ({gr.FLAG_PUBLISH}=false)')
            if body.tenant_id is None:
                raise ServiceError(422,'TENANT_REQUIRED','auto_publish_validated_rules needs an explicit tenant_id')
            if body.collector_capability_digest is None:
                raise ServiceError(422,'CAPABILITY_DIGEST_REQUIRED','auto_publish_validated_rules needs the '
                                       'collector_capability_digest the caller reviewed')
            current=pctx.capabilities(db,scope,body.tenant_id)
            if current.get('source')!='HANDSHAKE' or current.get('digest')!=body.collector_capability_digest:
                raise ServiceError(409,'STALE_CAPABILITY_DIGEST','collector_capability_digest is not the current '
                                       'collector declaration of this tenant; re-read GET .../collector-capabilities')

    @app.post(PREFIX+'/jobs',status_code=202)
    def submit(request: Request,
               body: Annotated[Sync | Extract | Discover | PrepareCatalog | GenerateRules, Field(discriminator='action')],
               db=Depends(database), principal: Principal=Depends(authenticate)):
        # Per-action permission: the automated pipelines need their own engine-defined scope so that
        # holding catalog:operate alone never silently enables automated approval and publication.
        required = automation.AUTOMATION_SCOPE if isinstance(body,(PrepareCatalog,GenerateRules)) else 'catalog:operate'
        if required not in principal.scopes:
            raise ServiceError(403,'FORBIDDEN',f"Credential lacks required scope '{required}'.")
        if isinstance(body,Discover):
            registry.require_jurisdiction(db,body.jurisdiction)  # 404 UNKNOWN_JURISDICTION before anything is queued
        payload=body.model_dump(mode='json',exclude={'request_key'})
        for key in OPTIONAL_JOB_FIELDS:
            if key in payload and payload[key] is None:
                del payload[key]
        for key,default in DEFAULTED_JOB_FIELDS.items():  # added in later contract revisions: keep old dedup digests
            if key in payload and payload[key]==default:
                del payload[key]
        scope=request_scope(request,db,principal)
        if isinstance(body,GenerateRules):
            if scope is None:
                raise ServiceError(422,'SCOPE_REQUIRED',f'generate_rules requires the {orgscope.HEADER} header.')
            for fid in body.requested_framework_ids:
                fw=db.one('SELECT organization_scope FROM regulatory_framework WHERE id=?',(fid,))
                if fw is None or not orgscope.visible(fw,scope):
                    raise ServiceError(404,'UNKNOWN_FRAMEWORK',f"Framework '{fid}' is not registered in this scope.")
            if body.tenant_id is not None:
                policy_scope(request,db,principal,body.tenant_id)
            check_rule_generation(db,body,scope)
            for implied in ('auto_rule_generation','llm_mapping'):
                payload.pop(implied,None)
            payload['organization_scope']=scope
        if isinstance(body,PrepareCatalog):
            if scope is None:
                raise ServiceError(422,'SCOPE_REQUIRED',
                                   f'prepare_catalog requires the {orgscope.HEADER} header.')
            for code in body.jurisdictions:
                registry.require_jurisdiction(db,code)
            for fid in body.requested_framework_ids:
                fw=db.one('SELECT organization_scope FROM regulatory_framework WHERE id=?',(fid,))
                if fw is None or not orgscope.visible(fw,scope):
                    raise ServiceError(404,'UNKNOWN_FRAMEWORK',f"Framework '{fid}' is not registered in this scope.")
            if body.mode=='import':
                if not body.document_ids:
                    raise ServiceError(422,'DOCUMENTS_REQUIRED','import mode needs document_ids from a scoped upload')
                rows=db.q(f"SELECT id,organization_scope FROM regulatory_document WHERE id IN "
                          f"({','.join('?'*len(body.document_ids))})",list(body.document_ids))
                owned={r['id'] for r in rows if r['organization_scope']==scope}
                missing=sorted(set(body.document_ids)-owned)  # cross-scope ids look exactly like unknown ones
                if missing:
                    raise ServiceError(404,'UNKNOWN_DOCUMENT',f'Documents not found in this organization scope: {missing}')
            if body.tenant_id is not None:
                policy_scope(request,db,principal,body.tenant_id)  # the caller must be authorized for the tenant
            check_rule_generation(db,body,scope)
            payload['organization_scope']=scope  # server-derived: dedup and execution are per scope
        job=jobs.submit(principal.key_id,body.request_key,payload)
        extra={'organization_scope':scope} if scope else {}
        return envelope(db,job=job,**extra)

    def job_visible(row, scope):
        return scope is None or (row.get('payload') or {}).get('organization_scope')==scope

    @app.get(PREFIX+'/jobs')
    def list_jobs(request: Request, status: str | None = Query(None,pattern='^(QUEUED|RUNNING|SUCCEEDED|PARTIAL|FAILED|INTERRUPTED)$'),
                  after: int | None = Query(None,ge=1), limit: int = Query(100,ge=1,le=500),
                  db=Depends(database), principal: Principal=Depends(admin_reader)):
        scope=request_scope(request,db,principal)
        rows=[row for row in jobs.list(limit=(limit+1) if scope is None else 500,status=status,after=after)
              if job_visible(row,scope)]
        extra={'organization_scope':scope} if scope else {}
        return envelope(db,items=rows[:limit],has_more=len(rows)>limit,
                        next_cursor=str(rows[limit-1]['seq']) if len(rows)>limit else None,**extra)

    @app.get(PREFIX+'/jobs/{identifier}')
    def job(identifier: str, request: Request, db=Depends(database), principal: Principal=Depends(admin_reader)):
        row=jobs.get(identifier)
        scope=request_scope(request,db,principal)
        if not job_visible(row,scope):  # a scoped caller cannot see or probe other scopes' jobs
            raise ServiceError(404,'UNKNOWN_JOB','Job not found')
        extra={'organization_scope':scope} if scope else {}
        return envelope(db,job=row,**extra)

    # ---- organization policy contexts (CUSTOMER_POLICY): user-declared, active on save
    def policy_scope(request: Request, db, principal: Principal, tenant_id: str) -> str:
        authorize_tenant(principal, tenant_id)
        scope=request_scope(request,db,principal)
        if scope is None:
            raise ServiceError(422,'SCOPE_REQUIRED',f'Policy contexts are organization-owned; send {orgscope.HEADER}.')
        return scope

    def policy_saved(db, request, response: Response, row, created: bool, scope: str):
        response.status_code=201 if created else 200
        view=pctx.version_view(db,row,engine=request.app.state.engine)
        return envelope(db,organization_scope=scope,created=created,policy_version=view)

    @app.post(PREFIX+'/policy-contexts',status_code=201)
    def create_policy_context(request: Request, response: Response, body: pctx.PolicyVersionIn,
                              db=Depends(database), principal: Principal=Depends(operate)):
        """Create a policy context and its version 1 (idempotent per request_key)."""
        scope=policy_scope(request,db,principal,body.tenant_id)
        row,created=pctx.create_context(db,scope=scope,actor=principal.key_id,body=body)
        return policy_saved(db,request,response,row,created,scope)

    @app.post(PREFIX+'/policy-contexts/{context_id}/versions',status_code=201)
    def add_policy_version(context_id: str, request: Request, response: Response, body: pctx.PolicyVersionNext,
                           db=Depends(database), principal: Principal=Depends(operate)):
        """Save the next immutable version; ``supersedes_version`` must be the current latest."""
        scope=policy_scope(request,db,principal,body.tenant_id)
        row,created=pctx.add_version(db,context_id,scope=scope,actor=principal.key_id,body=body)
        return policy_saved(db,request,response,row,created,scope)

    @app.put(PREFIX+'/collector-capabilities')
    def declare_collector_capabilities(request: Request, body: pctx.CollectorCapabilitiesIn,
                                       db=Depends(database), principal: Principal=Depends(operate)):
        """Collector capability handshake: the evidence schema versions this organization's
        collector produces. Controls become end-to-end assessable only for declared, compatible types."""
        scope=policy_scope(request,db,principal,body.tenant_id)
        view,changed=pctx.declare_capabilities(db,scope=scope,actor=principal.key_id,body=body)
        return envelope(db,organization_scope=scope,changed=changed,collector_capabilities=view)

    @app.put(PREFIX+'/pam-configuration',status_code=201)
    def declare_pam_configuration(request: Request, body: PamConfigurationIn,
                                  db=Depends(database), principal: Principal=Depends(operate)):
        """Collector-verified PAM configuration snapshot (provenance CUSTOMER_POLICY / PAM_CONFIGURATION).
        A parameter source for automated mappings of this organization only; never a regulatory threshold."""
        from . import pam_configuration
        scope=policy_scope(request,db,principal,body.tenant_id)
        if engine is None:
            raise ServiceError(503,'ENGINE_UNAVAILABLE','The policy bundle is not loaded')
        snapshot=pam_configuration.declare(db,scope=scope,actor=principal.key_id,body=body,engine=engine)
        return envelope(db,organization_scope=scope,pam_configuration=snapshot)

    @app.get(PREFIX+'/pam-configuration')
    def pam_configuration_latest(request: Request, tenant_id: str = Query(min_length=1,max_length=128),
                                 db=Depends(database), principal: Principal=Depends(admin_reader)):
        from . import pam_configuration
        scope=policy_scope(request,db,principal,tenant_id)
        snap=pam_configuration.latest(db,scope,tenant_id)
        if snap is None:
            raise ServiceError(404,'NO_PAM_CONFIGURATION','No PAM configuration snapshot for this organization')
        return envelope(db,organization_scope=scope,pam_configuration=snap)

    @app.get(PREFIX+'/jobs/{identifier}/progress')
    def job_progress(identifier: str, request: Request, db=Depends(database),
                     principal: Principal=Depends(admin_reader)):
        """Current step, counters and ETA of one job (null ETA with a reason code when not determinable)."""
        row=jobs.get(identifier)
        scope=request_scope(request,db,principal)
        if not job_visible(row,scope):
            raise ServiceError(404,'UNKNOWN_JOB','Job not found')
        extra={'organization_scope':scope} if scope else {}
        return envelope(db,progress=jobs.estimate(row),eta_reasons=list(progress_mod.ETA_REASONS),**extra)

    return app


def app_factory():
    return create_admin_app()
