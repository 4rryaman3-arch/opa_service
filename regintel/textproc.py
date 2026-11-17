"""Document text extraction and sectioning (deterministic, no LLM).

Section references are produced here, from the document's own structure, and
are never taken from model output. That is what makes a citation trustworthy:
the passage, its section and its document are tied together by the parser.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from html.parser import HTMLParser

MAX_SECTION_CHARS = 6000
_BLOCK = {"p", "div", "li", "td", "th", "tr", "br", "table", "section", "article", "blockquote", "dd", "dt", "pre"}
_HEAD = {"h1", "h2", "h3", "h4", "h5", "h6"}
_SKIP = {"script", "style", "noscript", "template", "head", "nav", "footer", "svg"}


@dataclass(frozen=True)
class Section:
    ordinal: int
    section_ref: str
    heading: str | None
    text: str


@dataclass(frozen=True)
class Parsed:
    sections: list[Section]
    complete: bool
    incomplete_reason: str | None


def normalize(text: str) -> str:
    """Canonical form used for verbatim-quote matching: NFC, unified
    whitespace and quote marks. Never changes letters or digits."""
    text = unicodedata.normalize("NFC", text)
    text = text.translate({0x00A0: 0x20, 0x202F: 0x20, 0x2009: 0x20, 0x200B: None, 0x00AD: None,
                           0x2018: 0x27, 0x2019: 0x27, 0x201C: 0x22, 0x201D: 0x22})
    return " ".join(text.split())


class _Blocks(HTMLParser):
    """Flattens HTML to (is_heading, text) blocks. ``heading_classes`` lets an
    adapter mark elements that act as headings (e.g. article titles in a gazette)."""

    def __init__(self, heading_classes: frozenset[str]) -> None:
        super().__init__(convert_charrefs=True)
        self.heading_classes = heading_classes
        self.blocks: list[tuple[bool, str]] = []
        self._buf: list[str] = []
        self._heading = False
        self._skip = 0
        self.saw_html_end = False
        self.saw_html_start = False

    def _flush(self) -> None:
        text = normalize("".join(self._buf))
        self._buf = []
        if text:
            self.blocks.append((self._heading, text))
        self._heading = False

    def handle_starttag(self, tag, attrs):
        if tag == "html":
            self.saw_html_start = True
        if tag in _SKIP:
            self._skip += 1
            return
        if tag in _BLOCK or tag in _HEAD:
            self._flush()
            classes = set((dict(attrs).get("class") or "").split())
            self._heading = tag in _HEAD or bool(classes & self.heading_classes)

    def handle_endtag(self, tag):
        if tag == "html":
            self.saw_html_end = True
        if tag in _SKIP:
            self._skip = max(0, self._skip - 1)
            return
        if tag in _BLOCK or tag in _HEAD:
            self._flush()

    def handle_data(self, data):
        if not self._skip:
            self._buf.append(data)

    def close(self):
        super().close()
        self._flush()


def _sections_from_blocks(blocks: list[tuple[bool, str]]) -> list[Section]:
    sections: list[Section] = []
    heading: str | None = None
    body: list[str] = []
    part = 0

    def emit() -> None:
        nonlocal body, part
        text = "\n".join(body).strip()
        body = []
        if not text:
            return
        part += 1
        base = heading[:120] if heading else "(preamble)"
        ref = base if part == 1 else f"{base} [part {part}]"
        sections.append(Section(len(sections) + 1, f"#{len(sections) + 1} {ref}", heading, text))

    for is_heading, text in blocks:
        if is_heading:
            emit()
            heading, part = text, 0
            continue
        if sum(len(b) + 1 for b in body) + len(text) > MAX_SECTION_CHARS and body:
            emit()
        while len(text) > MAX_SECTION_CHARS:  # a single oversized block
            body.append(text[:MAX_SECTION_CHARS])
            emit()
            text = text[MAX_SECTION_CHARS:]
        body.append(text)
    emit()
    return sections


_META_CHARSET = re.compile(rb"<meta[^>]+charset\s*=\s*[\"']?\s*([A-Za-z0-9._-]{2,40})", re.I)


def decode_bytes(content: bytes, charset: str | None = None) -> tuple[str, bool]:
    """Strict decoding with the declared encoding (HTTP header, then <meta
    charset>, then UTF-8 / BOM-marked UTF-16). Never guesses: text that does
    not decode cleanly is reported so the document is treated as incomplete."""
    import codecs

    candidates = [charset]
    m = _META_CHARSET.search(content[:4096])
    candidates.append(m.group(1).decode("ascii") if m else None)
    candidates.append("utf-16" if content[:2] in (codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE) else "utf-8-sig")
    for enc in candidates:
        if not enc:
            continue
        try:
            codecs.lookup(enc)
            return content.decode(enc), True
        except (LookupError, UnicodeDecodeError):
            break  # the declared encoding is wrong: do not fall through to a guess
    return content.decode("utf-8", errors="replace"), False


def parse_document(content: bytes, fmt: str, *, declared_length: int | None = None, charset: str | None = None,
                   heading_classes: frozenset[str] = frozenset(), min_chars: int = 200) -> Parsed:
    """Returns sections plus a completeness verdict. An incomplete document is
    stored (for diagnosis) but can never be reviewed, extracted or cited."""
    reasons: list[str] = []
    if declared_length is not None and declared_length != len(content):
        reasons.append(f"received {len(content)} bytes but the server declared {declared_length}")
    if fmt == "pdf":
        try:
            from pypdf import PdfReader  # optional dependency
        except ImportError:
            return Parsed([], False, "PDF text extraction is not installed (pip install pypdf); document stored unparsed")
        import io

        try:
            reader = PdfReader(io.BytesIO(content))
            blocks = [(False, normalize(page.extract_text() or "")) for page in reader.pages]
        except Exception as exc:  # noqa: BLE001 - any parser failure means "incomplete"
            return Parsed([], False, f"PDF could not be parsed ({type(exc).__name__})")
        empty = sum(1 for _, t in blocks if not t)
        if empty:
            reasons.append(f"{empty} of {len(blocks)} PDF pages have no extractable text (scanned pages need OCR review)")
        sections = [Section(i + 1, f"#{i + 1} page {i + 1}", f"page {i + 1}", t) for i, (_, t) in enumerate(blocks) if t]
    elif fmt == "html":
        text, clean = decode_bytes(content, charset)
        if not clean:
            reasons.append("content does not decode cleanly with its declared encoding; characters were replaced")
        parser = _Blocks(heading_classes)
        parser.feed(text)
        parser.close()
        if parser.saw_html_start and not parser.saw_html_end:
            reasons.append("HTML is truncated (no closing </html>)")
        sections = _sections_from_blocks(parser.blocks)
    elif fmt == "txt":
        text, clean = decode_bytes(content, charset)
        if not clean:
            reasons.append("content does not decode cleanly with its declared encoding; characters were replaced")
        blocks = [(False, normalize(p)) for p in re.split(r"\n\s*\n", text) if normalize(p)]
        sections = _sections_from_blocks(blocks)
    else:
        return Parsed([], False, f"unsupported format '{fmt}'")
    total = sum(len(s.text) for s in sections)
    if total < min_chars:
        reasons.append(f"only {total} characters of text were extracted (expected at least {min_chars})")
    return Parsed(sections, not reasons, "; ".join(reasons) or None)
