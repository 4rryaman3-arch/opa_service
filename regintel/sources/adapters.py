"""Built-in source adapters. Add a jurisdiction by adding configuration (or a
new adapter class for an unusual publication system), not by changing the core.

  static_list  explicit document URLs on the official domain(s)
  index_page   an official index/gazette page whose links are followed
  eurlex       EUR-Lex texts addressed by CELEX number, per language
  file_drop    licensed documents an operator obtained from an authorized
               repository and placed in a local directory (ISO, PCI SSC, ...)
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.parse import urljoin, urlsplit

from .base import DocumentRef, FetchedDocument, Fetcher, SourceAdapter, SourceError, register

_EXT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")


def _ref(d: dict, default_lang: str | None = None) -> DocumentRef:
    lang = d.get("language") or default_lang
    if not lang:
        raise SourceError("LANGUAGE_REQUIRED", "every document must declare its language; it is never guessed")
    if not _EXT_RE.match(str(d["external_id"])):
        raise SourceError("INVALID_EXTERNAL_ID", str(d["external_id"]))
    return DocumentRef(str(d["external_id"]), d["url"], lang, d.get("framework_id"), d.get("title"), d.get("format"))


@register
class StaticListAdapter(SourceAdapter):
    adapter_type = "static_list"
    supported_formats = ("html", "txt", "pdf")  # e.g. standards published only as PDF on the authority's domain
    discovery_methods = ("static_list",)

    def validate_config(self) -> None:
        for d in self.config.discovery.get("documents", []):
            _ref(d)

    def discover(self, fetcher: Fetcher) -> Iterable[DocumentRef]:
        for d in self.config.discovery["documents"]:
            fetcher.check_url(d["url"])
            yield _ref(d)


class _Links(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href:
            self.links.append((self._href, " ".join("".join(self._text).split())))
            self._href = None


@register
class IndexPageAdapter(SourceAdapter):
    """Follows links on an official index page (gazette issue list, regulator
    publications page). Links leaving the allowlist are ignored, not followed."""

    adapter_type = "index_page"
    discovery_methods = ("index_page",)

    def validate_config(self) -> None:
        d = self.config.discovery
        for key in ("index_url", "link_pattern", "language"):
            if not d.get(key):
                raise SourceError("INVALID_CONFIG", f"index_page discovery needs '{key}'")
        re.compile(d["link_pattern"])

    def discover(self, fetcher: Fetcher) -> Iterable[DocumentRef]:
        d = self.config.discovery
        page = fetcher.get(d["index_url"])
        parser = _Links()
        parser.feed(page.content.decode("utf-8", errors="replace"))
        pattern = re.compile(d["link_pattern"])
        seen: set[str] = set()
        for href, text in parser.links:
            url = urljoin(page.url, href).split("#")[0]
            parts = urlsplit(url)
            if parts.scheme != "https" or (parts.hostname or "").lower() not in self.config.allowed_domains:
                continue
            if url in seen or not pattern.search(url):
                continue
            seen.add(url)
            ext = re.sub(r"[^A-Za-z0-9._:/-]", "_", parts.path.strip("/") + (f"?{parts.query}" if parts.query else ""))[:200]
            yield DocumentRef(ext or "index", url, d["language"], d.get("framework_id"), text[:300] or None)
            if len(seen) >= int(d.get("max_documents", 100)):
                break


@register
class EurLexAdapter(SourceAdapter):
    """EU law by CELEX number, through the Publications Office repository
    (Cellar) content-negotiation endpoint, one request per language. The
    interactive eur-lex.europa.eu pages answer automated clients with a
    challenge (HTTP 202) and are deliberately not used."""

    adapter_type = "eurlex"
    discovery_methods = ("cellar_celex",)
    supported_formats = ("html",)
    heading_classes = frozenset({"oj-ti-art", "ti-art"})  # article titles in Official Journal XHTML
    DOMAIN = "publications.europa.eu"
    URL = "https://publications.europa.eu/resource/celex/{celex}"
    _CELEX = re.compile(r"^[0-9A-Z]{1}[0-9]{4}[A-Z]{1,2}[0-9]{4}(\([0-9]{2}\))?(-[0-9]{8})?$")
    # BCP 47 -> the ISO 639-3 codes Cellar negotiates on (EU official languages)
    LANGUAGES = {"bg": "bul", "cs": "ces", "da": "dan", "de": "deu", "el": "ell", "en": "eng", "es": "spa", "et": "est",
                 "fi": "fin", "fr": "fra", "ga": "gle", "hr": "hrv", "hu": "hun", "it": "ita", "lt": "lit", "lv": "lav",
                 "mt": "mlt", "nl": "nld", "pl": "pol", "pt": "por", "ro": "ron", "sk": "slk", "sl": "slv", "sv": "swe"}

    def _languages(self) -> list[str]:
        return self.config.discovery.get("languages") or self.source["languages"]

    def validate_config(self) -> None:
        if self.config.allowed_domains != [self.DOMAIN]:
            raise SourceError("INVALID_CONFIG", f"the eurlex adapter is restricted to {self.DOMAIN}")
        for d in self.config.discovery.get("documents", []):
            if not self._CELEX.match(d.get("celex", "")):
                raise SourceError("INVALID_CONFIG", f"not a CELEX number: {d.get('celex')!r}")
        unknown = sorted(set(self._languages()) - set(self.LANGUAGES))
        if unknown:
            raise SourceError("INVALID_CONFIG", f"{unknown} are not EU official languages")

    def discover(self, fetcher: Fetcher) -> Iterable[DocumentRef]:
        for d in self.config.discovery["documents"]:
            for lang in self._languages():
                yield DocumentRef(d["celex"], self.URL.format(celex=d["celex"]), lang, d.get("framework_id"),
                                  d.get("title"), "html")

    def fetch(self, fetcher: Fetcher, ref: DocumentRef) -> FetchedDocument:
        resp = fetcher.get(ref.url, headers={"Accept": "application/xhtml+xml",
                                             "Accept-Language": self.LANGUAGES[ref.language]})
        ctype = resp.headers.get("content-type", "").split(";")[0].strip().lower()
        if ctype not in ("application/xhtml+xml", "text/html"):
            raise SourceError("UNSUPPORTED_FORMAT", f"unexpected content type '{ctype}' from Cellar")
        served = resp.headers.get("content-language")
        if served and served.split("-")[0].lower() not in (ref.language, self.LANGUAGES[ref.language]):
            raise SourceError("LANGUAGE_MISMATCH", f"asked for '{ref.language}' but the repository served '{served}'")
        return FetchedDocument(ref=ref, content=resp.content, format="html", retrieved_url=resp.url,
                               etag=resp.headers.get("etag"), last_modified=resp.headers.get("last-modified"),
                               charset="utf-8")


@register
class FileDropAdapter(SourceAdapter):
    """Licensed standards: nothing is downloaded. The operator attests where
    each file was obtained; licensing normally forbids redistributing text."""

    adapter_type = "file_drop"
    discovery_methods = ("file_drop",)
    supported_formats = ("html", "txt", "pdf", "json")
    requires_network = False

    def validate_config(self) -> None:
        d = self.config.discovery
        if not d.get("directory"):
            raise SourceError("INVALID_CONFIG", "file_drop discovery needs 'directory'")
        for doc in d.get("documents", []):
            if "/" in doc["file"] or "\\" in doc["file"] or doc["file"].startswith("."):
                raise SourceError("INVALID_CONFIG", "file names must be plain names inside the drop directory")
            _ref({**doc, "url": "file:"})

    def discover(self, fetcher: Fetcher) -> Iterable[DocumentRef]:
        for doc in self.config.discovery.get("documents", []):
            ext = Path(doc["file"]).suffix.lstrip(".").lower()
            fmt = doc.get("format") or {"htm": "html", "text": "txt"}.get(ext, ext)
            yield DocumentRef(str(doc["external_id"]), f"file:{doc['file']}", doc["language"], doc.get("framework_id"),
                              doc.get("title"), fmt)

    def fetch(self, fetcher: Fetcher, ref: DocumentRef) -> FetchedDocument:
        if ref.format not in self.config.formats:
            raise SourceError("UNSUPPORTED_FORMAT", f"format '{ref.format}' is not configured for this source")
        path = Path(self.config.discovery["directory"]) / ref.url.removeprefix("file:")
        try:
            content = path.read_bytes()
        except OSError as exc:
            raise SourceError("FILE_NOT_FOUND", f"{path.name} is not in the drop directory") from exc
        if len(content) > self.config.max_document_bytes:
            raise SourceError("DOCUMENT_TOO_LARGE", path.name)
        return FetchedDocument(ref=ref, content=content, format=ref.format, retrieved_url=ref.url)
