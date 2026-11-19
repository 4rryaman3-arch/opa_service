"""Organization-scope isolation for the Django rewrite workflow (contract 1.0).

A scope is an opaque namespace string Django derives (SHA-256-based) from the
server-owned OPM tenant and the authenticated PAM organization, sent as the
``X-Securden-Organization-Scope`` header. It is never taken from browser input
on the Django side, and on the OPM side it is:

  * validated against a strict pattern (opaque token, no path/sql characters);
  * bound to the first credential (key_id) that uses it - any other credential
    presenting the same scope gets 403 ``SCOPE_FORBIDDEN``;
  * attached to every record the scoped workflow creates (sources, documents,
    requirements, mappings, frameworks, jobs, uploads).

Visibility rule: a scoped request sees GLOBAL rows (``organization_scope IS
NULL`` - the shared official catalog) plus its OWN scope's rows, never another
scope's. Legacy requests without the header see only global rows on public
reads; management reads without the header keep their historical behaviour
(the deployment credential is server-owned; browsers never reach these APIs).

Uploaded material is always scoped: it never becomes globally visible and is
never labelled official (``source_origin: UPLOADED_DOCUMENT``).
"""
from __future__ import annotations

import re

from .db import CatalogDb, now_iso

HEADER = "X-Securden-Organization-Scope"
REWRITE_CONTRACT_VERSION = "1.0"
CAPABILITIES = {
    "prepare_catalog_v1": True,
    "scoped_imports_v1": True,
    "scoped_catalog_v1": True,
    "bounded_rule_generation_v1": True,
}
_SCOPE_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


class ScopeError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        self.status, self.code, self.message = status, code, message
        super().__init__(message)


def validate_and_bind(db: CatalogDb, scope: str | None, key_id: str) -> str | None:
    """Validate the header value and bind it to the credential on first use."""
    if scope is None:
        return None
    if not _SCOPE_RE.match(scope):
        raise ScopeError(422, "INVALID_SCOPE",
                         "X-Securden-Organization-Scope must be an opaque token of 16-128 characters [A-Za-z0-9_-].")
    row = db.one("SELECT key_id FROM organization_scope_binding WHERE scope=?", (scope,))
    if row is None:
        with db.tx():
            # re-check inside the transaction; another request may have bound it
            row = db.one("SELECT key_id FROM organization_scope_binding WHERE scope=?", (scope,))
            if row is None:
                db.insert("organization_scope_binding", scope=scope, key_id=key_id, created_at=now_iso())
                db.audit(key_id, "SCOPE_BOUND", "organization_scope", scope)
                return scope
    if row["key_id"] != key_id:
        raise ScopeError(403, "SCOPE_FORBIDDEN", "This organization scope is bound to a different credential.")
    return scope


def clause(alias: str, scope: str | None) -> tuple[str, list[str]]:
    """SQL predicate for scope visibility on ``alias.organization_scope``."""
    col = f"{alias}.organization_scope" if alias else "organization_scope"
    if scope is None:
        return f"{col} IS NULL", []
    return f"({col} IS NULL OR {col}=?)", [scope]


def own(alias: str, scope: str) -> tuple[str, list[str]]:
    """SQL predicate for rows owned by exactly this scope."""
    col = f"{alias}.organization_scope" if alias else "organization_scope"
    return f"{col}=?", [scope]


def visible(row: dict | None, scope: str | None) -> bool:
    """Whether one fetched row may be shown to this request."""
    if row is None:
        return False
    row_scope = row.get("organization_scope")
    return row_scope is None or row_scope == scope


def source_origin(db: CatalogDb, framework_id: str, scope: str | None) -> str:
    """UPLOADED_DOCUMENT / OFFICIAL_DISCOVERY / MIXED for a template item:
    which kind of sources this framework's visible requirements cite."""
    pred, args = clause("r", scope)
    rows = db.q(
        "SELECT DISTINCT s.adapter_type, s.organization_scope FROM regulatory_requirement r "
        "JOIN regulatory_document_version v ON v.id=r.document_version_id "
        "JOIN regulatory_document d ON d.id=v.document_id JOIN source s ON s.id=d.source_id "
        f"WHERE r.framework_id=? AND {pred}", [framework_id, *args])
    kinds = {"UPLOADED_DOCUMENT" if (r["organization_scope"] is not None or r["adapter_type"] == "file_drop")
             else "OFFICIAL_DISCOVERY" for r in rows}
    if not kinds:
        return "OFFICIAL_DISCOVERY"
    return kinds.pop() if len(kinds) == 1 else "MIXED"
