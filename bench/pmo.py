"""The PMO test set: thirty fictitious notes, read from `bench/data/pmo_notes.md`.

The file was generated outside this project, as test data, and is kept exactly as
it arrived so its provenance is plain. It is read here rather than retyped into
`notes.py` because thirty notes retyped by hand is thirty chances to change one.

It is still a file from somewhere else, so it is read strictly (Law 5). Every
entry must have exactly the shape below, and anything else stops the read with
the line it happened on, rather than quietly skipping a note — a test set that
silently loses entries scores whatever is left.

    ### 2026-07-02 — Maria Chen (Senior PM)
    **Category:** Project Update | **Sentiment:** Positive
    <the note, one or more lines>
    **Follow-up:** Mention in next steering committee update.

**Only the note body goes to a model.** Category and sentiment are the
generator's labels, not something a supervisor types, and showing them to the
model would be handing it the answer. They are kept because they are ground
truth for analysis Counselog does not do yet.

**What the set is good for.** Every entry is headed by one person, so for the
self/team question it is nearly all negatives — which is exactly the failure the
small models showed in phase 4, saying yes to everything. It has few positives;
`notes.LABELLED` still carries those.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from core.sanitize import sanitize

SOURCE = Path(__file__).resolve().parent / "data" / "pmo_notes.md"

# How many entries the file holds, pinned here so a truncated copy is caught
# instead of measured. Not read from the file's own "Entry count" line, because
# that line says 30 and the file holds 32 — the first thing the strict read
# found. The file is left as it arrived; the count it should have had lives here.
ENTRIES = 32
_HEADING = re.compile(r"^### (\d{4}-\d{2}-\d{2}) — ([A-Z][A-Za-z]+ [A-Z][A-Za-z]+) \([^()]+\)$")
_LABELS = re.compile(r"^\*\*Category:\*\* ([^|*]+?) \| \*\*Sentiment:\*\* (Positive|Neutral|Negative)$")
_FOLLOW_UP = re.compile(r"^\*\*Follow-up:\*\* (.+)$")

# ── self/team labels: PROPOSED, NOT YET REVIEWED ─────────────────────────────
#
# The file has no self/team labels; these are a first reading for the person
# who owns the record to argue with. Every note not listed is labelled "neither"
# — about one person — and that is a firm label.
#
# The ones listed are ARGUABLE: a reasonable reader could go either way, so they
# are scored apart from the firm ones. A model that disagrees on these has not
# necessarily got them wrong, and lumping them in would make that look like an
# error.
ARGUABLE: dict[str, tuple[set[str], str]] = {
    "2026-07-21": (set(), "a leadership decision is needed — the supervisor's to carry?"),
    "2026-07-23": ({"team"}, "'might be a process gap, not a Priya problem'"),
    "2026-09-19": ({"self"}, "'need to think about how to answer it honestly'"),
}


@dataclass(frozen=True)
class PmoNote:
    date: str
    person: str
    category: str
    sentiment: str
    text: str
    follow_up: str

    @property
    def expected(self) -> set[str]:
        """The self/team answer this note should get."""
        return ARGUABLE.get(self.date, (set(), ""))[0]

    @property
    def arguable(self) -> bool:
        return self.date in ARGUABLE


class MalformedTestSet(Exception):
    """The file is not in the shape this reader knows. Names the line."""


def load(path: Path = SOURCE) -> list[PmoNote]:
    lines = path.read_text(encoding="utf-8").splitlines()
    notes: list[PmoNote] = []
    starts = [i for i, line in enumerate(lines) if line.startswith("### ")]
    for start in starts:
        notes.append(_entry(path.name, lines, start))

    if len(notes) != ENTRIES:
        raise MalformedTestSet(f"{path.name}: expected {ENTRIES} entries, found {len(notes)}")
    dates = [note.date for note in notes]
    if len(set(dates)) != len(dates):
        raise MalformedTestSet(f"{path.name}: two entries share a date; labels are keyed by it")
    unknown = set(ARGUABLE) - set(dates)
    if unknown:
        raise MalformedTestSet(f"labels for dates not in the file: {sorted(unknown)}")
    return notes


def _entry(name: str, lines: list[str], start: int) -> PmoNote:
    def fail(offset: int, what: str) -> MalformedTestSet:
        return MalformedTestSet(f"{name} line {start + offset + 1}: {what}")

    heading = _HEADING.match(lines[start])
    if not heading:
        raise fail(0, "heading is not '### YYYY-MM-DD — First Last (Role)'")
    labels = _LABELS.match(lines[start + 1]) if start + 1 < len(lines) else None
    if not labels:
        raise fail(1, "expected the Category | Sentiment line")

    # The body runs until the follow-up line; the entry ends at '---' or EOF.
    body: list[str] = []
    offset = 2
    while start + offset < len(lines) and not lines[start + offset].startswith("**Follow-up:**"):
        line = lines[start + offset]
        if line.startswith(("### ", "---")):
            raise fail(offset, "entry ended without a Follow-up line")
        body.append(line)
        offset += 1
    if start + offset >= len(lines):
        raise fail(offset, "file ended without a Follow-up line")
    follow_up = _FOLLOW_UP.match(lines[start + offset])
    if not follow_up:
        raise fail(offset, "Follow-up line is empty")

    text = sanitize("\n".join(body).strip())
    if not text:
        raise fail(2, "entry has no note text")
    return PmoNote(date=heading.group(1), person=heading.group(2),
                   category=labels.group(1).strip(), sentiment=labels.group(2),
                   text=text, follow_up=follow_up.group(1).strip())
