"""The PMO test set: eighty-two fictitious notes, read from `bench/data/`.

Two files, generated outside this project as test data and kept exactly as they
arrived so their provenance is plain:

  - `pmo_notes.md`, July to September 2026, 32 entries.
  - `pmo_notes_expansion.md`, a prequel (January to June) and a sequel
    (September 28 to October 20), 50 entries. Read together the two are one
    continuous log.

They are read here rather than retyped into `notes.py` because eighty notes
retyped by hand is eighty chances to change one.

They are still files from somewhere else, so they are read strictly (Law 5).
Every entry must have exactly this shape, and anything else stops the read with
the line it happened on, rather than quietly skipping a note — a test set that
silently loses entries scores whatever is left.

    ### 2026-07-02 — Maria Chen (Senior PM)        or  — Team-wide  /  — Self-note
    **Category:** Project Update | **Sentiment:** Positive
    **Visibility:** Private                          (optional)
    <the note, one or more lines>
    **Follow-up:** Mention in next steering committee update.

**Only the note body goes to a model.** Category, sentiment and the heading are
the generator's labels, not something a supervisor types, and showing them to
the model would be handing it the answer. They are kept because they are ground
truth — for the self/team question here, and for analysis Counselog does not do
yet (sentiment, follow-ups, how much is written about whom).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from core.sanitize import sanitize

DATA = Path(__file__).resolve().parent / "data"

# How many entries each file holds, pinned here so a truncated copy is caught
# instead of measured. Not read from the files' own "Entry count" lines: the
# first file's says 30 and it holds 32 — the first thing the strict read found.
# The files are left as they arrived; the counts they should have live here.
SOURCES = {
    "pmo_notes.md": 32,
    "pmo_notes_expansion.md": 50,
}

TEAM_WIDE = "Team-wide"
SELF_NOTE = "Self-note"

_HEADING = re.compile(
    r"^### (\d{4}-\d{2}-\d{2}) — "
    rf"(?:({TEAM_WIDE}|{SELF_NOTE})|([A-Z][a-z]+ [A-Z][a-z]+) \([^()]+\))$")
_LABELS = re.compile(r"^\*\*Category:\*\* ([^|*]+?) \| \*\*Sentiment:\*\* (Positive|Neutral|Negative)$")
_VISIBILITY = re.compile(r"^\*\*Visibility:\*\* (Private)$")
_FOLLOW_UP = re.compile(r"^\*\*Follow-up:\*\* (.+)$")

# ── self/team labels ─────────────────────────────────────────────────────────
#
# The heading gives a first label: "Team-wide" is team, "Self-note" is self,
# and a note headed with a person's name is about that person, so neither. That
# is the generator's reading, adopted as the default because it is the only one
# that was not written by the tool being tested.
#
# PROPOSED, NOT YET REVIEWED: the overrides below, where the heading's one label
# does not fit — a note can be about the team *and* the writer, and a note
# headed with a name can be mostly about the writer's own conduct. All of them
# are ARGUABLE, so they are scored apart from the firm ones: a model that
# disagrees with an arguable label has not necessarily got it wrong.
#
# Keyed by (date, subject), because five dates hold two entries each.
ARGUABLE: dict[tuple[str, str], tuple[set[str], str]] = {
    # first file
    ("2026-07-21", "Sam Okafor"): (set(), "a leadership decision is needed — the supervisor's to carry?"),
    ("2026-07-23", "Priya Nair"): ({"team"}, "'might be a process gap, not a Priya problem'"),
    ("2026-09-19", "Priya Nair"): ({"self"}, "'need to think about how to answer it honestly'"),
    # expansion: team-wide, but as much about the writer
    ("2026-01-06", TEAM_WIDE): ({"self", "team"}, "opens with the writer's own note-taking habit"),
    ("2026-09-28", TEAM_WIDE): ({"self", "team"}, "mostly the writer's dilemma over Dana's confidence"),
    # expansion: headed with a name, but about the writer's own honesty
    ("2026-02-10", "Sam Okafor"): ({"self"}, "'I wasnt sure I was being straight, just careful'"),
    ("2026-10-02", "Priya Nair"): ({"self"}, "'Is that the same as lying?'"),
    ("2026-10-05", "Maria Chen"): ({"self"}, "'makes these conversations feel slightly dishonest'"),
}


@dataclass(frozen=True)
class PmoNote:
    source: str
    date: str
    subject: str        # a person's name, or TEAM_WIDE, or SELF_NOTE
    category: str
    sentiment: str
    private: bool
    text: str
    follow_up: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.date, self.subject)

    @property
    def person(self) -> str | None:
        return None if self.subject in (TEAM_WIDE, SELF_NOTE) else self.subject

    @property
    def expected(self) -> set[str]:
        """The self/team answer this note should get."""
        if self.key in ARGUABLE:
            return ARGUABLE[self.key][0]
        return {TEAM_WIDE: {"team"}, SELF_NOTE: {"self"}}.get(self.subject, set())

    @property
    def arguable(self) -> bool:
        return self.key in ARGUABLE


class MalformedTestSet(Exception):
    """A file is not in the shape this reader knows. Names the line."""


def load(data: Path = DATA) -> list[PmoNote]:
    """Every PMO note, from every file in SOURCES, in file order."""
    notes = [note for name, count in SOURCES.items()
             for note in load_file(data / name, count)]

    keys = [note.key for note in notes]
    repeated = sorted({key for key in keys if keys.count(key) > 1})
    if repeated:
        raise MalformedTestSet(f"two entries share a date and subject; labels are keyed "
                               f"by both: {repeated}")
    unknown = sorted(set(ARGUABLE) - set(keys))
    if unknown:
        raise MalformedTestSet(f"labels for entries not in the files: {unknown}")
    return notes


def load_file(path: Path, count: int) -> list[PmoNote]:
    lines = path.read_text(encoding="utf-8").splitlines()
    starts = [i for i, line in enumerate(lines) if line.startswith("### ")]
    notes = [_entry(path.name, lines, start) for start in starts]
    if len(notes) != count:
        raise MalformedTestSet(f"{path.name}: expected {count} entries, found {len(notes)}")
    return notes


def _entry(name: str, lines: list[str], start: int) -> PmoNote:
    def fail(offset: int, what: str) -> MalformedTestSet:
        return MalformedTestSet(f"{name} line {start + offset + 1}: {what}")

    def line(offset: int) -> str:
        return lines[start + offset] if start + offset < len(lines) else ""

    heading = _HEADING.match(lines[start])
    if not heading:
        raise fail(0, "heading is not '### YYYY-MM-DD — First Last (Role)', "
                      f"'— {TEAM_WIDE}' or '— {SELF_NOTE}'")
    labels = _LABELS.match(line(1))
    if not labels:
        raise fail(1, "expected the Category | Sentiment line")

    offset = 2
    private = bool(_VISIBILITY.match(line(offset)))
    if private:
        offset += 1
    elif line(offset).startswith("**Visibility:**"):
        raise fail(offset, "Visibility is not 'Private'; no other value is known")

    # The body runs until the follow-up line; the entry ends at '---' or EOF.
    body_starts = offset
    body: list[str] = []
    while start + offset < len(lines) and not line(offset).startswith("**Follow-up:**"):
        if line(offset).startswith(("#", "---")):
            raise fail(offset, "entry ended without a Follow-up line")
        body.append(line(offset))
        offset += 1
    if start + offset >= len(lines):
        raise fail(offset, "file ended without a Follow-up line")
    follow_up = _FOLLOW_UP.match(line(offset))
    if not follow_up:
        raise fail(offset, "Follow-up line is empty")

    text = sanitize("\n".join(body).strip())
    if not text:
        raise fail(body_starts, "entry has no note text")
    return PmoNote(source=name, date=heading.group(1),
                   subject=heading.group(2) or heading.group(3),
                   category=labels.group(1).strip(), sentiment=labels.group(2),
                   private=private, text=text, follow_up=follow_up.group(1).strip())
