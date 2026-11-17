"""Application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import __version__
from .config import Settings
from .engine.catalog import Catalog
from .engine.evaluator import Evaluator
from .engine.opa_client import OpaClient
from .engine.store import RuleStore
from .errors import (
    ServiceError,
    http_error_handler,
    service_error_handler,
    unhandled_error_handler,
    validation_error_handler,
)
from .logging_config import configure_logging
from .metrics import Metrics
from .middleware import ServiceMiddleware
from .routes import router
from .security import ApiKeyStore, TokenBucketLimiter


def create_app(
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    settings = settings or Settings()
    configure_logging(settings.log_level)
    metrics = Metrics()

    # Fail fast (refuse to start) on missing secrets or a broken bundle.
    catalog = Catalog.load(settings.policy_bundle_dir)
    api_keys = ApiKeyStore.from_file(settings.api_clients_file)
    opa_token = settings.resolved_opa_token

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store = RuleStore(settings.db_path)
        opa = OpaClient(
            settings.opa_url,
            opa_token,
            settings.opa_connect_timeout_seconds,
            settings.opa_timeout_seconds,
            max_connections=settings.batch_concurrency * 2,
            metrics=metrics,
            transport=opa_transport,
        )
        app.state.store = store
        app.state.opa = opa
        app.state.evaluator = Evaluator(settings, catalog, store, opa, metrics)
        try:
            yield
        finally:
            await opa.aclose()
            store.close()

    app = FastAPI(
        title="Securden Compliance Policy Evaluation Service",
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.settings = settings
    app.state.catalog = catalog
    app.state.api_keys = api_keys
    app.state.metrics = metrics
    app.state.rate_limiter = TokenBucketLimiter(settings.rate_limit_per_minute, settings.rate_limit_burst)
    app.state.auth_failure_limiter = TokenBucketLimiter(
        settings.auth_failure_limit_per_minute, settings.auth_failure_limit_per_minute
    )

    app.add_exception_handler(ServiceError, service_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(StarletteHTTPException, http_error_handler)
    app.add_exception_handler(Exception, unhandled_error_handler)
    app.include_router(router)
    from regintel.api import router as catalog_router  # read-only global regulatory catalog

    app.include_router(catalog_router)
    app.add_middleware(ServiceMiddleware, max_body_bytes=settings.max_body_bytes, metrics=metrics)
    return app


def app_factory() -> FastAPI:  # uvicorn --factory entry point
    return create_app()
