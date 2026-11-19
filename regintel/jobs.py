"""Persistent, single-worker catalog ingestion queue for the separate admin service."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

from datetime import datetime, timezone

from . import progress as progress_mod
from .db import CatalogDb, CatalogError, canonical, now_iso


class Jobs:
    def __init__(self, path: Path, catalog_path: Path, bundle_dir: Path | None = None,
                 rule_store_path: Path | None = None):
        self.path, self.catalog_path, self.bundle_dir = path, catalog_path, bundle_dir
        self.rule_store_path = rule_store_path  # the evaluator's tenant rule store (generated rules are activated there)
        self.clock = lambda: datetime.now(timezone.utc)  # injectable for tests
        path.parent.mkdir(parents=True, exist_ok=True)
        self.stop_event = threading.Event()
        with self.connect() as connection:
            connection.execute("CREATE TABLE IF NOT EXISTS job (id TEXT PRIMARY KEY, actor TEXT NOT NULL, "
                "request_key TEXT NOT NULL, payload TEXT NOT NULL, status TEXT NOT NULL, created_at TEXT NOT NULL, "
                "finished_at TEXT, result TEXT, error TEXT, UNIQUE(actor,request_key))")
            connection.execute("UPDATE job SET status='INTERRUPTED', error='Worker restarted; submit a new job after checking results' "
                               "WHERE status='RUNNING'")
            for ddl in ("started_at TEXT",  # additive migrations
                        "progress TEXT"):   # {"stage", "at", ...}: the running job's current stage
                try:
                    connection.execute(f"ALTER TABLE job ADD COLUMN {ddl}")
                except sqlite3.OperationalError:
                    pass  # column already exists

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def submit(self, actor, key, payload):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT * FROM job WHERE actor=? AND request_key=?", (actor,key)).fetchone()
            if existing:
                if existing['payload'] != canonical(payload):
                    raise CatalogError("IDEMPOTENCY_CONFLICT", "This request key was used for a different operation")
                return self.decode(existing)
            if connection.execute("SELECT COUNT(*) FROM job WHERE status IN ('QUEUED','RUNNING')").fetchone()[0] >= 100:
                raise CatalogError("QUEUE_FULL", "The catalog processing queue is full")
            identifier = uuid.uuid4().hex
            connection.execute("INSERT INTO job (id,actor,request_key,payload,status,created_at) VALUES (?,?,?,?,?,?)",
                               (identifier,actor,key,canonical(payload),'QUEUED',now_iso()))
        return self.get(identifier)

    @staticmethod
    def decode(row):
        if row is None:
            raise CatalogError("UNKNOWN_JOB", "Job not found")
        result = dict(row)
        for key in ('payload','result','progress'):
            if result.get(key):
                result[key] = json.loads(result[key])
        return result

    def set_progress(self, job_id, stage, **info):
        """Durable stage marker so pollers see where a running job is; keeps per-step timing for the ETA."""
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT progress FROM job WHERE id=?", (job_id,)).fetchone()
            previous = json.loads(row['progress']) if row and row['progress'] else None
            marker = progress_mod.advance(previous, stage, info, self.clock())
            connection.execute("UPDATE job SET progress=? WHERE id=?", (canonical(marker), job_id))

    def estimate(self, job):
        """Progress view with ETA for one decoded job row (see regintel.progress)."""
        position = None
        with self.connect() as connection:
            if job['status'] == 'QUEUED':
                position = connection.execute(
                    "SELECT COUNT(*) FROM job WHERE status='RUNNING' OR (status='QUEUED' AND created_at<=?)",
                    (job['created_at'],)).fetchone()[0]
            recent = [json.loads(r['progress']) for r in connection.execute(
                "SELECT progress FROM job WHERE status IN ('SUCCEEDED','PARTIAL') AND progress IS NOT NULL "
                "ORDER BY rowid DESC LIMIT 20")]
        return progress_mod.estimate(job, now=self.clock(), queue_position=position,
                                     rates=progress_mod.reference_rates(recent))

    def get(self, identifier):
        with self.connect() as connection:
            return self.decode(connection.execute("SELECT * FROM job WHERE id=?", (identifier,)).fetchone())

    def list(self, limit=100, status=None, after=None):
        """Newest first. ``seq`` on each row is the cursor for ``after`` (rows with seq < after)."""
        with self.connect() as connection:
            return [self.decode(row) for row in connection.execute(
                "SELECT rowid AS seq, * FROM job WHERE (? IS NULL OR status=?) AND (? IS NULL OR rowid<?) "
                "ORDER BY rowid DESC LIMIT ?", (status,status,after,after,limit))]

    def related(self, version_id, source_id, limit=50):
        """Newest jobs that processed one document version: its extractions and its source's syncs."""
        with self.connect() as connection:
            rows = [self.decode(row) for row in connection.execute("SELECT * FROM job ORDER BY created_at DESC")]
        return [job for job in rows if job['payload'].get('version_id') == version_id
                or (job['payload'].get('action') == 'sync' and job['payload'].get('source_id') == source_id)][:limit]

    def execute(self, actor, payload, job_id=None):
        from . import automation, discovery, extraction
        from .__main__ import _llm
        from .sources.registry import sync_source

        db = CatalogDb(self.catalog_path)
        try:
            if payload['action'] == 'sync':
                return sync_source(db, payload['source_id'], blob_dir=self.catalog_path.parent/'documents', actor=actor)
            if payload['action'] == 'discover':
                return discovery.discover(db, self, actor=actor, jurisdiction=payload['jurisdiction'],
                                          include_inherited=payload.get('include_inherited', True),
                                          as_of=payload.get('as_of'), job_id=job_id)
            if payload['action'] == 'prepare_catalog':
                from . import preparation
                engine = None
                if self.bundle_dir is not None:
                    try:
                        from app.engine.catalog import Catalog
                        engine = Catalog.load(self.bundle_dir)
                    except (OSError, KeyError, ValueError, RuntimeError):
                        engine = None
                progress = (lambda stage, **info: self.set_progress(job_id, stage, **info)) if job_id else None
                with _llm() as llm:
                    return preparation.prepare_catalog(
                        db, actor=actor, scope=payload['organization_scope'], mode=payload['mode'],
                        jurisdictions=payload.get('jurisdictions') or [], llm=llm,
                        blob_dir=self.catalog_path.parent/'documents', engine=engine,
                        industry=payload.get('industry'),
                        requested_framework_ids=payload.get('requested_framework_ids'),
                        include_inherited=payload.get('include_inherited', True),
                        document_ids=payload.get('document_ids'), translate=payload.get('translate', True),
                        as_of=payload.get('as_of'), job_id=job_id, progress=progress,
                        languages=payload.get('languages'), screening=payload.get('screening'),
                        tenant_id=payload.get('tenant_id'), llm_mapping=payload.get('llm_mapping', True),
                        auto_rule_generation=payload.get('auto_rule_generation', False),
                        auto_publish_validated_rules=payload.get('auto_publish_validated_rules', False),
                        collector_capability_digest=payload.get('collector_capability_digest'),
                        bundle_dir=self.bundle_dir, rule_store_path=self.rule_store_path)
            if payload['action'] == 'generate_rules':  # rule generation only, for already published requirements
                from . import preparation
                from app.engine.catalog import Catalog
                engine = Catalog.load(self.bundle_dir) if self.bundle_dir is not None else None
                progress = (lambda stage, **info: self.set_progress(job_id, stage, **info)) if job_id else None
                with _llm() as llm:
                    return preparation.generate_rules(
                        db, actor=actor, scope=payload['organization_scope'],
                        framework_ids=payload['requested_framework_ids'], llm=llm, engine=engine,
                        tenant_id=payload.get('tenant_id'), publish=payload.get('auto_publish_validated_rules', False),
                        collector_capability_digest=payload.get('collector_capability_digest'), job_id=job_id,
                        progress=progress, bundle_dir=self.bundle_dir, rule_store_path=self.rule_store_path)
            if payload['action'] == 'build_framework':  # removed action; only a job queued before the upgrade
                raise CatalogError('ACTION_REMOVED', "build_framework was removed; use prepare_catalog")
            def on_section(index, total):
                if job_id and (index == 1 or index % 5 == 0 or index == total):
                    self.set_progress(job_id, 'extract', version_id=payload['version_id'],
                                      section=f"{index}/{total}", done=index, total=total, unit='section')
            with _llm() as llm:
                return extraction.extract_version(db, payload['version_id'], llm, actor=actor,
                                                   translate=payload.get('translate', True), job_id=job_id,
                                                   on_section=on_section)
        finally:
            db.close()

    def run_once(self):
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM job WHERE status='QUEUED' ORDER BY created_at LIMIT 1").fetchone()
            if row is None:
                return False
            connection.execute("UPDATE job SET status='RUNNING', started_at=? WHERE id=?",(now_iso(),row['id']))
        try:
            result = self.execute(row['actor'], json.loads(row['payload']), job_id=row['id'])
            inner = result.get('status')
            if inner == 'FAILED':  # e.g. a sync that retrieved nothing; details are in result.errors
                status, error = 'FAILED', result.get('error') or 'The operation completed without a usable result; see result'
            else:
                status = 'PARTIAL' if result.get('llm_errors') or inner == 'PARTIAL' else 'SUCCEEDED'
                error = None
        except Exception as exc:
            result, status = None, 'FAILED'
            error = (f"{exc.code}: {exc.message}" if isinstance(exc, CatalogError)
                     else f"{type(exc).__name__}: {exc}"[:500])  # keep the message, bounded
        with self.connect() as connection:
            connection.execute("UPDATE job SET status=?,finished_at=?,result=?,error=? WHERE id=?",
                               (status,now_iso(),canonical(result),error,row['id']))
        return True

    def start(self):
        def work():
            while not self.stop_event.is_set():
                if not self.run_once():
                    self.stop_event.wait(0.5)
        self.thread = threading.Thread(target=work, daemon=True, name='catalog-worker')
        self.thread.start()

    def close(self):
        self.stop_event.set()
        if getattr(self, "thread", None) is not None:
            self.thread.join(timeout=2)
