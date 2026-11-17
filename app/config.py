"""Service configuration.

All settings come from environment variables prefixed ``OPM_``. Secrets are
never given defaults; each secret can be supplied either directly or (preferred)
via a mounted file referenced by the matching ``*_FILE`` variable.
"""

from __future__ import annotations

from functools import cached_property
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="OPM_", extra="ignore")

    # --- OPA -------------------------------------------------------------
    opa_url: str = "http://opa:8181"
    opa_token: str | None = Field(default=None, repr=False)
    opa_token_file: Path | None = None
    opa_connect_timeout_seconds: float = Field(default=2.0, gt=0, le=30)
    opa_timeout_seconds: float = Field(default=10.0, gt=0, le=120)

    # --- Storage / policy -----------------------------------------------
    policy_bundle_dir: Path = Path("/policies")
    db_path: Path = Path("/data/opm.db")
    api_clients_file: Path = Path("/run/secrets/api_clients.json")
    # Regulatory catalog (written by the regintel worker, opened read-only here).
    # If the file does not exist the catalog endpoints return 503; evaluation is unaffected.
    catalog_db_path: Path = Path("/data/regintel/catalog.db")
    catalog_upload_dir: Path = Path("data/regintel/uploads")
    catalog_jobs_db_path: Path = Path("data/regintel/jobs.db")

    # --- Limits ----------------------------------------------------------
    max_body_bytes: int = Field(default=5 * 1024 * 1024, ge=1024)
    max_records_per_evaluation: int = Field(default=10_000, ge=1)
    max_batch_items: int = Field(default=100, ge=1, le=1000)
    max_batch_total_records: int = Field(default=50_000, ge=1)
    batch_concurrency: int = Field(default=8, ge=1, le=64)
    evaluation_timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    max_evidence_references: int = Field(default=1_000, ge=1)

    # --- Rate limiting (per API client, token bucket) --------------------
    rate_limit_per_minute: int = Field(default=600, ge=1)
    rate_limit_burst: int = Field(default=100, ge=1)
    auth_failure_limit_per_minute: int = Field(default=30, ge=1)
    trust_proxy_headers: bool = True  # Caddy is the only ingress in the compose stack

    # --- Semantics -------------------------------------------------------
    historical_threshold_days: int = Field(default=35, ge=1)
    clock_skew_seconds: int = Field(default=300, ge=0, le=3600)

    # --- Misc ------------------------------------------------------------
    enable_docs: bool = False
    log_level: str = "INFO"

    @field_validator("opa_url")
    @classmethod
    def _strip_slash(cls, v: str) -> str:
        return v.rstrip("/")

    @cached_property
    def resolved_opa_token(self) -> str:
        token = self.opa_token
        if self.opa_token_file is not None:
            token = self.opa_token_file.read_text(encoding="utf-8").strip()
        if not token or len(token) < 32:
            raise RuntimeError(
                "OPA token missing or shorter than 32 characters "
                "(set OPM_OPA_TOKEN_FILE or OPM_OPA_TOKEN)"
            )
        return token
