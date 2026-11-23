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


# PDF glyph repair. Fonts embedded with ligatures often extract as a presentation-form ligature (U+FB00-FB06)
# or, when the font maps them to its private-use area, as an arbitrary code point (NIST SP 800-53 in Calibri:
# "idenfy" for "identify", "Soware" for "Software"). The private-use code point means different letters
# in different fonts of the same file, so each word is repaired from the document's own vocabulary: the reading
# that is a word the document also spells plainly. A word with no such reading is left unchanged.
_LIGATURES = {0xFB00: "ff", 0xFB01: "fi", 0xFB02: "fl", 0xFB03: "ffi", 0xFB04: "ffl", 0xFB05: "st", 0xFB06: "st"}
_PUA = re.compile(r"[-]")
_PUA_WORD = re.compile(r"[A-Za-z]*[-][A-Za-z-]*")
_GLYPH_READINGS = ("ti", "tt", "ft", "tf", "fi", "fl", "ff", "ffi", "ffl", "tti", "fk", "fb", "fh", "fj", "st", "th")
_MAX_GLYPHS_PER_WORD = 3


def repair_glyphs(pages: list[str]) -> list[str]:
    """Expand ligature glyphs in extracted PDF text (see above). Deterministic; never invents a word."""
    from collections import Counter
    from itertools import product

    pages = [p.translate(_LIGATURES) for p in pages]
    if not any(_PUA.search(p) for p in pages):
        return pages
    # vocabulary: whole words spelled without any private-use glyph
    plain = Counter(w.lower() for p in pages
                    for w in re.findall(r"(?<![A-Za-z-])[A-Za-z]+(?![A-Za-z-])", p))
    cache: dict[str, tuple[str | None, tuple[str, ...]]] = {}
    votes: dict[str, Counter[str]] = {}

    def fix(word: str) -> tuple[str | None, tuple[str, ...]]:
        if word in cache:
            return cache[word]
        parts = _PUA.split(word)
        best, best_n, best_combo = None, 0, ()
        if len(parts) - 1 <= _MAX_GLYPHS_PER_WORD:
            for combo in product(_GLYPH_READINGS, repeat=len(parts) - 1):
                cand = parts[0] + "".join(c + parts[i + 1] for i, c in enumerate(combo))
                n = plain.get(cand.lower(), 0)
                if n > best_n:
                    best, best_n, best_combo = cand, n, combo
        if best is not None:
            letters = "".join(parts)
            if len(letters) > 1 and letters.isupper():
                best = best.upper()  # an all-capitals heading keeps its case
        cache[word] = (best, best_combo)
        return cache[word]

    for p in pages:  # every occurrence votes, so a common word weighs as often as it is printed
        for m in _PUA_WORD.finditer(p):
            word = m.group(0)
            for glyph, reading in zip(_PUA.findall(word), fix(word)[1]):
                votes.setdefault(glyph, Counter())[reading] += 1
    # a glyph whose resolved words almost all read the same way is read that way where no word decides it
    usual = {g: c.most_common(1)[0][0] for g, c in votes.items()
             if sum(c.values()) >= 20 and c.most_common(1)[0][1] >= 0.9 * sum(c.values())}

    def apply(word: str) -> str:
        done = cache.get(word, (None, ()))[0]
        if done is not None:
            return done
        return _PUA.sub(lambda g: usual.get(g.group(0), g.group(0)), word)

    return [_PUA_WORD.sub(lambda m: apply(m.group(0)), p) for p in pages]


# OSCAL catalogs (NIST SP 800-53 as published by NIST in OSCAL JSON). Each control is rendered in the official
# text layout ("AC-2 ACCOUNT MANAGEMENT Control: a. ...", "(1) ACCOUNT MANAGEMENT | AUTOMATED SYSTEM ACCOUNT
# MANAGEMENT Control: ...") so canonical control references are derived exactly as for the PDF, but from the
# structure itself: no page layout, ligatures, running headers or table of contents. One section per base control
# with its enhancements; discussion text is omitted (it explains a control, it is not a requirement). Withdrawn
# controls are skipped.
_OSCAL_INSERT = re.compile(r"\{\{\s*insert:\s*param,\s*([A-Za-z0-9_.\-]+)\s*\}\}")


def _oscal_props(node: dict) -> dict[str, str]:
    """name -> value; a classless prop wins (the label "AC-1" over its zero-padded class variant "AC-01")."""
    out: dict[str, str] = {}
    for p in sorted((p for p in node.get("props", []) if isinstance(p, dict)), key=lambda p: "class" not in p):
        out[str(p.get("name"))] = str(p.get("value"))
    return out


def _oscal_param_text(params: dict[str, dict], pid: str, depth: int = 0) -> str:
    p = params.get(pid) or {}
    sel = p.get("select")
    if isinstance(sel, dict) and depth < 3:
        many = " (one or more)" if sel.get("how-many") == "one-or-more" else ""
        choices = "; ".join(_OSCAL_INSERT.sub(lambda m: _oscal_param_text(params, m.group(1), depth + 1), str(c))
                            for c in sel.get("choice", []))
        return f"[Selection{many}: {choices}]"
    label = (p.get("label") or "").strip() or next((g.get("prose", "") for g in p.get("guidelines", [])), "").strip()
    if not label:
        label = "value"
    if not label.lower().startswith("organization-defined"):
        label = "organization-defined " + label
    return f"[Assignment: {label}]"


def _oscal_statement(part: dict, params: dict[str, dict]) -> str:
    label = _oscal_props(part).get("label")
    prose = _OSCAL_INSERT.sub(lambda m: _oscal_param_text(params, m.group(1)), part.get("prose", "") or "")
    text = " ".join(x for x in (label, prose) if x)
    children = [_oscal_statement(c, params) for c in part.get("parts", []) if c.get("name") in ("item", "statement")]
    return " ".join(x for x in (text, *children) if x)


def _oscal_control(ctl: dict, base_title: str | None) -> str | None:
    props = _oscal_props(ctl)
    if props.get("status") == "withdrawn":
        return None
    params = {p["id"]: p for p in ctl.get("params", []) if isinstance(p, dict) and p.get("id")}
    title = normalize(ctl.get("title", "")).upper()
    label = props.get("label") or str(ctl.get("id", "")).upper()
    stmt = next((p for p in ctl.get("parts", []) if p.get("name") == "statement"), None)
    body = _oscal_statement(stmt, params) if stmt else ""
    if base_title is None:
        head = f"{label} {title}"
    else:
        number = re.search(r"\((\d{1,2})\)\s*$", label)
        head = f"({number.group(1) if number else label}) {base_title} | {title}"
    return normalize(f"{head} Control: {body}")


def parse_oscal_catalog(content: bytes) -> Parsed:
    import json

    try:
        doc = json.loads(content.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        return Parsed([], False, f"JSON could not be parsed ({type(exc).__name__})")
    catalog = doc.get("catalog") if isinstance(doc, dict) else None
    if not isinstance(catalog, dict) or not isinstance(catalog.get("groups", catalog.get("controls")), list):
        return Parsed([], False, "only OSCAL catalogs are supported as JSON (no 'catalog' with groups or controls)")
    sections: list[Section] = []

    def controls(node: dict) -> list[dict]:
        out = [c for c in node.get("controls", []) if isinstance(c, dict)]
        for g in node.get("groups", []):
            if isinstance(g, dict):
                out += controls(g)
        return out

    for ctl in controls(catalog):
        base = _oscal_control(ctl, None)
        if base is None:
            continue
        base_title = normalize(ctl.get("title", "")).upper()
        texts = [base] + [t for e in ctl.get("controls", []) if isinstance(e, dict)
                          for t in [_oscal_control(e, base_title)] if t]
        label = _oscal_props(ctl).get("label") or str(ctl.get("id", "")).upper()
        chunk: list[str] = []
        part = 0

        def emit() -> None:
            nonlocal chunk, part
            if not chunk:
                return
            part += 1
            ref = f"{label} {base_title}"[:110] + ("" if part == 1 else f" [part {part}]")
            sections.append(Section(len(sections) + 1, f"#{len(sections) + 1} {ref}", f"{label} {base_title}",
                                    "\n".join(chunk)))
            chunk = []

        for t in texts:
            if chunk and sum(len(c) + 1 for c in chunk) + len(t) > MAX_SECTION_CHARS:
                emit()
            chunk.append(t)
        emit()
    if not sections:
        return Parsed([], False, "the OSCAL catalog contains no controls")
    return Parsed(sections, True, None)


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
            blocks = [(False, normalize(t)) for t in repair_glyphs([page.extract_text() or "" for page in reader.pages])]
        except Exception as exc:  # noqa: BLE001 - any parser failure means "incomplete"
            return Parsed([], False, f"PDF could not be parsed ({type(exc).__name__})")
        empty = sum(1 for _, t in blocks if not t)
        if empty:
            reasons.append(f"{empty} of {len(blocks)} PDF pages have no extractable text (scanned pages need OCR review)")
        sections = [Section(i + 1, f"#{i + 1} page {i + 1}", f"page {i + 1}", t) for i, (_, t) in enumerate(blocks) if t]
    elif fmt == "json":
        parsed = parse_oscal_catalog(content)
        if not parsed.sections:
            return parsed
        sections = parsed.sections
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
