"""PAM keyword screening of document sections before model extraction.

A conservative relevance screen used to bound model work: only lines that
mention PAM subjects (plus one line of context either side) are sent to the
model. It is not a completeness or applicability test - sections it skips are
counted and reported, never treated as evidence that no obligation exists.
"""

from __future__ import annotations

import re

SCREENING_VERSION = "pam-keyword-screen-v1"
SCREENING_MODES = ("none", SCREENING_VERSION)

PAM_TERMS = re.compile(
    r"\b(privileged|access (?:control|rights?|management|polic\w*|to (?:information|systems|data|network))|"
    r"authenticat\w*|password\w*|credential\w*|identity management|user (?:access|account)|"
    r"log(?:ging|s| files)|session (?:monitor\w*|record\w*)|segregation of duties|multi.factor)\b", re.I)


def screened_text(text: str) -> str:
    """The matching lines of ``text`` with one line of context; empty when nothing matches."""
    lines = text.splitlines()
    selected: set[int] = set()
    for i, line in enumerate(lines):
        if PAM_TERMS.search(line):
            selected.update(range(max(0, i - 1), min(len(lines), i + 2)))
    return "\n".join(lines[i] for i in sorted(selected))


def passes(text: str) -> bool:
    return bool(PAM_TERMS.search(text))


class Screen:
    """The screen applied to one source's sections: the source's own ``section_screen``
    (from its verified config) when it declares one, otherwise the PAM keyword screen."""

    def __init__(self, section_screen: dict | None = None) -> None:
        self.custom = bool(section_screen)
        self._include = [re.compile(p) for p in (section_screen or {}).get("include", [])]
        self._excerpt = [re.compile(p) for p in (section_screen or {}).get("excerpt", [])]

    @property
    def label(self) -> str:
        return f"{SCREENING_VERSION}+source" if self.custom else SCREENING_VERSION

    def passes(self, text: str) -> bool:
        if not self.custom:
            return passes(text)
        return any(p.search(text) for p in self._include)

    def excerpt(self, text: str) -> str:
        """What is sent to the model; empty when the section is screened out."""
        if not self.custom:
            return screened_text(text)
        if not self.passes(text):
            return ""
        if not self._excerpt:
            return text
        spans = sorted({m.span() for p in self._excerpt for m in p.finditer(text) if m.end() > m.start()})
        merged: list[list[int]] = []
        for start, end in spans:
            if merged and start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        # a source pattern that matches nothing on an included section falls back to the full section
        return "\n".join(text[a:b].strip() for a, b in merged) or text


def screen_for_source(db, source_id: str | None) -> Screen:
    row = db.one("SELECT config FROM source WHERE id=?", (source_id,)) if source_id else None
    return Screen((row or {}).get("config", {}).get("section_screen") if row else None)
