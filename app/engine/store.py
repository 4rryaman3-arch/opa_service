"""Tenant-scoped persistent rule registry (SQLite on a Docker volume).

Every query is keyed by tenant_id; there is no API that lists or reads rules
across tenants. Rule versions are immutable once created: only their status
changes (DRAFT -> ACTIVE <-> INACTIVE). Every change is recorded in
``rule_events`` for auditability.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..errors import ServiceError

SCHEMA = """
CREATE TABLE IF NOT EXISTS custom_rules (
    tenant_id       TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    version         TEXT NOT NULL,
    status          TEXT NOT NULL CHECK (status IN ('DRAFT','ACTIVE','INACTIVE')),
    definition_json TEXT NOT NULL,
    compiled_json   TEXT NOT NULL,
    digest          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    created_by      TEXT NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (tenant_id, rule_id, version)
);
CREATE TABLE IF NOT EXISTS predefined_activation (
    tenant_id  TEXT NOT NULL,
    rule_id    TEXT NOT NULL,
    active     INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY (tenant_id, rule_id)
);
CREATE TABLE IF NOT EXISTS rule_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    rule_id   TEXT NOT NULL,
    version   TEXT,
    action    TEXT NOT NULL,
    actor     TEXT NOT NULL,
    at        TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class RuleStore:
    def __init__(self, path: Path) -> None:
        if str(path) != ":memory:":
            path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def ping(self) -> bool:
        try:
            with self._lock:
                self._conn.execute("SELECT 1").fetchone()
            return True
        except sqlite3.Error:
            return False

    def _event(self, tenant_id: str, rule_id: str, version: str | None, action: str, actor: str) -> None:
        self._conn.execute(
            "INSERT INTO rule_events (tenant_id, rule_id, version, action, actor, at) VALUES (?,?,?,?,?,?)",
            (tenant_id, rule_id, version, action, actor, _now()),
        )

    # -- custom rules -----------------------------------------------------
    def create_custom(
        self, tenant_id: str, definition: dict[str, Any], compiled: dict[str, Any], digest: str, actor: str
    ) -> dict[str, Any]:
        now = _now()
        with self._lock:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                self._conn.execute(
                    "INSERT INTO custom_rules VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (
                        tenant_id, definition["rule_id"], definition["version"], "DRAFT",
                        json.dumps(definition, sort_keys=True), json.dumps(compiled, sort_keys=True),
                        digest, now, actor, now,
                    ),
                )
                self._event(tenant_id, definition["rule_id"], definition["version"], "CREATE", actor)
                self._conn.execute("COMMIT")
            except sqlite3.IntegrityError as exc:
                self._conn.execute("ROLLBACK")
                raise ServiceError(
                    409, "RULE_VERSION_EXISTS",
                    "This rule version already exists; rule versions are immutable. Create a new version.",
                ) from exc
        return self.get_custom(tenant_id, definition["rule_id"], definition["version"])  # type: ignore[return-value]

    def get_custom(self, tenant_id: str, rule_id: str, version: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM custom_rules WHERE tenant_id=? AND rule_id=? AND version=?",
                (tenant_id, rule_id, version),
            ).fetchone()
        return self._row(row) if row else None

    def list_custom(self, tenant_id: str, rule_id: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT * FROM custom_rules WHERE tenant_id=?"
        args: tuple = (tenant_id,)
        if rule_id is not None:
            sql += " AND rule_id=?"
            args += (rule_id,)
        sql += " ORDER BY rule_id, version"
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        return [self._row(r) for r in rows]

    def set_custom_status(self, tenant_id: str, rule_id: str, version: str, status: str, actor: str) -> dict[str, Any]:
        if status not in ("ACTIVE", "INACTIVE"):
            raise ValueError(status)
        now = _now()
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT status FROM custom_rules WHERE tenant_id=? AND rule_id=? AND version=?",
                    (tenant_id, rule_id, version),
                ).fetchone()
                if row is None:
                    raise ServiceError(404, "RULE_NOT_FOUND", "Rule version not found for this tenant.")
                if status == "ACTIVE":
                    # Only one ACTIVE version per rule: deactivate the others.
                    self._conn.execute(
                        "UPDATE custom_rules SET status='INACTIVE', updated_at=? "
                        "WHERE tenant_id=? AND rule_id=? AND status='ACTIVE' AND version<>?",
                        (now, tenant_id, rule_id, version),
                    )
                self._conn.execute(
                    "UPDATE custom_rules SET status=?, updated_at=? WHERE tenant_id=? AND rule_id=? AND version=?",
                    (status, now, tenant_id, rule_id, version),
                )
                self._event(tenant_id, rule_id, version, status, actor)
                self._conn.execute("COMMIT")
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
        return self.get_custom(tenant_id, rule_id, version)  # type: ignore[return-value]

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "tenant_id": row["tenant_id"],
            "rule_id": row["rule_id"],
            "version": row["version"],
            "status": row["status"],
            "definition": json.loads(row["definition_json"]),
            "compiled": json.loads(row["compiled_json"]),
            "digest": row["digest"],
            "created_at": row["created_at"],
            "created_by": row["created_by"],
            "updated_at": row["updated_at"],
        }

    # -- predefined rule activation ---------------------------------------
    def predefined_active(self, tenant_id: str, rule_id: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT active FROM predefined_activation WHERE tenant_id=? AND rule_id=?",
                (tenant_id, rule_id),
            ).fetchone()
        return True if row is None else bool(row["active"])

    def set_predefined_active(self, tenant_id: str, rule_id: str, active: bool, actor: str) -> None:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                "INSERT INTO predefined_activation VALUES (?,?,?,?,?) "
                "ON CONFLICT(tenant_id, rule_id) DO UPDATE SET active=excluded.active, "
                "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                (tenant_id, rule_id, int(active), _now(), actor),
            )
            self._event(tenant_id, rule_id, None, "ACTIVATE" if active else "DEACTIVATE", actor)
            self._conn.execute("COMMIT")
