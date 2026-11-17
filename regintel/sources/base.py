"""Source-adapter contract and the allowlisted fetcher every adapter must use.

An adapter never opens its own connections. It receives a ``Fetcher`` that
enforces, for every hop including redirects: HTTPS with certificate
validation, host on the source's official-domain allowlist, the source's rate
limit, and a size cap. A response from any other host is an error, never
content.
"""

from __future__ import annotations

import hashlib
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, ClassVar, Iterable
from urllib.parse import urljoin, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator

USER_AGENT = "securden-regintel/1.0 (regulatory catalog synchronization)"
DOMAIN_PATTERN = r"^(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})+$"


class SourceError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


class RateLimit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    min_interval_seconds: float = Field(default=5.0, ge=0.0, le=3600)
    max_requests_per_run: int = Field(default=200, ge=1, le=10_000)


class Licensing(BaseModel):
    model_config = ConfigDict(extra="forbid")
    license: str = Field(min_length=3, max_length=300)
    # When false the catalog API returns citations only, never the passage text.
    redistribute_text: bool = False
    notes: str = ""


class SectionScreen(BaseModel):
    """Source-specific relevance screen for automated extraction (used instead of the
    generic PAM keyword screen when screening is on). ``include``: a section is sent to
    the model only if one pattern matches. ``excerpt``: when set, only the matched spans
    (joined in document order) are sent; grounding is still checked on the full section."""
    model_config = ConfigDict(extra="forbid")
    include: list[str] = Field(min_length=1, max_length=50)
    excerpt: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("include", "excerpt")
    @classmethod
    def _patterns(cls, v: list[str]) -> list[str]:
        import re

        for p in v:
            if not 1 <= len(p) <= 500:
                raise ValueError("each pattern must be 1-500 characters")
            try:
                re.compile(p)
            except re.error as exc:
                raise ValueError(f"invalid pattern {p!r}: {exc}") from exc
        return v


class SourceConfig(BaseModel):
    """What every adapter must declare (stored on the source row)."""

    model_config = ConfigDict(extra="forbid")

    allowed_domains: list[str] = Field(max_length=20)
    formats: list[str] = Field(min_length=1)
    discovery: dict[str, Any]
    version_identification: str
    change_detection: str
    rate_limit: RateLimit = Field(default_factory=RateLimit)
    licensing: Licensing
    verification_method: str = Field(min_length=3)
    max_document_bytes: int = Field(default=30_000_000, ge=1_000, le=200_000_000)
    section_screen: SectionScreen | None = None

    @field_validator("allowed_domains")
    @classmethod
    def _domains(cls, v: list[str]) -> list[str]:
        import re

        out = sorted({d.strip().lower() for d in v})
        for d in out:
            if not re.match(DOMAIN_PATTERN, d):
                raise ValueError(f"'{d}' is not a bare hostname (no scheme, path or wildcard)")
        return out


@dataclass(frozen=True)
class DocumentRef:
    external_id: str
    url: str
    language: str
    framework_id: str | None = None
    title: str | None = None
    format: str | None = None


@dataclass
class FetchedDocument:
    ref: DocumentRef
    content: bytes
    format: str
    retrieved_url: str
    etag: str | None = None
    last_modified: str | None = None
    declared_length: int | None = None
    charset: str | None = None
    version_label: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True)
class HttpResult:
    url: str
    headers: dict[str, str]
    content: bytes


class Fetcher:
    def __init__(self, config: SourceConfig, transport: httpx.BaseTransport | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> None:
        self.config = config
        self._client = httpx.Client(
            transport=transport, follow_redirects=False, timeout=httpx.Timeout(60.0, connect=15.0),
            headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip, deflate"},
        )
        self._sleep, self._clock = sleep, clock
        self._last: float | None = None
        self.requests = 0

    def close(self) -> None:
        self._client.close()

    def check_url(self, url: str) -> None:
        parts = urlsplit(url)
        if parts.scheme != "https":
            raise SourceError("INSECURE_URL", f"only https is allowed: {url}")
        if parts.username or parts.password:
            raise SourceError("FORBIDDEN_URL", "credentials in URLs are not allowed")
        host = (parts.hostname or "").lower()
        if host not in self.config.allowed_domains:
            raise SourceError("DOMAIN_NOT_ALLOWED", f"host '{host}' is not on this source's official-domain allowlist")

    def get(self, url: str, headers: dict[str, str] | None = None) -> "HttpResult":
        for _ in range(6):
            self.check_url(url)
            if self.requests >= self.config.rate_limit.max_requests_per_run:
                raise SourceError("RUN_BUDGET_EXCEEDED", "per-run request budget for this source is exhausted")
            if self._last is not None:
                wait = self.config.rate_limit.min_interval_seconds - (self._clock() - self._last)
                if wait > 0:
                    self._sleep(wait)
            self._last = self._clock()
            self.requests += 1
            try:
                with self._client.stream("GET", url, headers=headers) as resp:
                    if resp.status_code in (301, 302, 303, 307, 308):
                        url = urljoin(url, resp.headers.get("location", ""))
                        target = urlsplit(url)
                        if target.scheme == "http" and (target.hostname or "").lower() in self.config.allowed_domains:
                            # Some official sites redirect to http:// URLs. Never follow in
                            # plaintext: request the same allowlisted resource over TLS instead.
                            url = "https" + url[4:]
                        continue  # the next hop is re-checked against the allowlist
                    if resp.status_code == 429 or resp.status_code >= 500:
                        raise SourceError("SOURCE_UNAVAILABLE", f"HTTP {resp.status_code} from {urlsplit(url).hostname}")
                    if resp.status_code != 200:
                        # 202/204/206 etc. are not a complete document (e.g. bot-challenge pages).
                        raise SourceError("UNEXPECTED_STATUS", f"HTTP {resp.status_code} for {url}")
                    body = bytearray()
                    for chunk in resp.iter_bytes():
                        body.extend(chunk)
                        if len(body) > self.config.max_document_bytes:
                            raise SourceError("DOCUMENT_TOO_LARGE", f"document exceeds {self.config.max_document_bytes} bytes")
                    return HttpResult(str(resp.url), {k.lower(): v for k, v in resp.headers.items()}, bytes(body))
            except httpx.HTTPError as exc:
                raise SourceError("FETCH_FAILED", f"{type(exc).__name__} fetching {urlsplit(url).hostname}") from exc
        raise SourceError("TOO_MANY_REDIRECTS", "redirect limit exceeded")


class SourceAdapter(ABC):
    """Implement ``discover`` and (optionally) ``fetch``; register with ``@register``."""

    adapter_type: ClassVar[str]
    supported_formats: ClassVar[tuple[str, ...]] = ("html", "txt")
    discovery_methods: ClassVar[tuple[str, ...]]
    heading_classes: ClassVar[frozenset[str]] = frozenset()  # CSS classes that mark section headings
    requires_network: ClassVar[bool] = True

    def __init__(self, source: dict[str, Any], config: SourceConfig) -> None:
        self.source = source
        self.config = config
        unsupported = set(config.formats) - set(self.supported_formats)
        if unsupported:
            raise SourceError("UNSUPPORTED_FORMAT", f"{self.adapter_type} does not support {sorted(unsupported)}")
        if config.discovery.get("method") not in self.discovery_methods:
            raise SourceError("UNSUPPORTED_DISCOVERY", f"{self.adapter_type} supports discovery methods {self.discovery_methods}")
        if self.requires_network and not config.allowed_domains:
            raise SourceError("NO_ALLOWLIST", "a network source needs at least one official domain")
        self.validate_config()

    def validate_config(self) -> None:  # adapter-specific checks
        return None

    @abstractmethod
    def discover(self, fetcher: Fetcher) -> Iterable[DocumentRef]: ...

    def fetch(self, fetcher: Fetcher, ref: DocumentRef) -> FetchedDocument:
        resp = fetcher.get(ref.url)
        header = resp.headers.get("content-type", "")
        ctype = header.split(";")[0].strip().lower()
        charset = next((p.split("=", 1)[1].strip(" \"'") for p in header.split(";")[1:]
                        if p.strip().lower().startswith("charset=")), None)
        fmt = ref.format or {"text/html": "html", "application/xhtml+xml": "html", "text/plain": "txt",
                             "application/pdf": "pdf"}.get(ctype)
        if fmt is None or fmt not in self.config.formats:
            raise SourceError("UNSUPPORTED_FORMAT", f"content type '{ctype}' is not a format configured for this source")
        declared = resp.headers.get("content-length")
        encoded = "content-encoding" in resp.headers
        return FetchedDocument(
            ref=ref, content=resp.content, format=fmt, retrieved_url=resp.url,
            etag=resp.headers.get("etag"), last_modified=resp.headers.get("last-modified"),
            declared_length=int(declared) if declared and declared.isdigit() and not encoded else None,
            charset=charset,
        )


ADAPTERS: dict[str, type[SourceAdapter]] = {}


def register(cls: type[SourceAdapter]) -> type[SourceAdapter]:
    ADAPTERS[cls.adapter_type] = cls
    return cls
