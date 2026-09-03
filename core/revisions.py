"""Correcting a note without rewriting the record.

Editing text in place would re-hash the body and make `verify` report the note
as altered — which is exactly what it should report, because that *is* an
alteration. The database refuses to help anyway: `note_chain` carries a trigger
denying UPDATE outright.

So an edit appends. The correction is a new note pointing back at the one it
replaces; the original keeps its text, its hash and its place in the chain. What
the record currently says is the newest note in the thread, and what it said
before is still there and still provable.

**This means an edit corrects, it does not unsay.** Fixing a typo leaves the
typo in the record. That is the right behaviour for a journal that may be read
in an HR conversation — a note that can be quietly rewritten afterwards is worth
nothing as evidence — but it is not what "edit" usually means, so the interface
has to say so before someone relies on it. Removing text is what `forget` is
for, and it works on any revision in the thread.
"""

from __future__ import annotations

from dataclasses import dataclass

import sqlcipher3

from core import models, tags
from core.sanitize import sanitize


class RevisionError(Exception):
    """The note could not be corrected."""


@dataclass(frozen=True)
class Thread:
    """One note and every correction made to it, oldest first."""

    revisions: tuple[models.Note, ...]

    @property
    def root(self) -> models.Note:
        """As first written. Its time is where the thread sits in the record."""
        return self.revisions[0]

    @property
    def current(self) -> models.Note:
        """What the record says now."""
        return self.revisions[-1]

    @property
    def edited(self) -> bool:
        return len(self.revisions) > 1

    @property
    def edit_count(self) -> int:
        return len(self.revisions) - 1


def revise(conn, note_id: int, new_text: str) -> models.Note:
    """Record a correction, and return the note that now stands.

    The correction inherits the original's backdating, source and trust, because
    it is the same note said better — only the text was in question. It gets its
    own `captured_at`, which is the truth: that is when the correction was
    written, and pretending otherwise would put a false time in the one field
    the whole design refuses to let anyone edit.

    Tags are carried over so the note does not drop out of its bins the moment
    it is corrected, but it is left unprocessed so tagging revisits it — the
    text changed, so the bins may need to. Carried over *with their provenance*:
    a judgment you made about the original is still your judgment about the
    correction, and sorting will leave it alone.
    """
    original = models.get_note(conn, note_id)
    if original.tombstoned:
        raise RevisionError(
            "That note's text has been cleared, so there is nothing to correct.")

    cleaned = sanitize(new_text)
    if not cleaned.strip():
        raise RevisionError("A note needs some text.")
    if cleaned == original.raw_text:
        raise RevisionError("That is the same text the note already has.")

    try:
        revision = models.add_note(
            conn, new_text,
            source_type=original.source_type,
            source_trust=original.source_trust,
            backdated_at=original.backdated_at,
            supersedes=note_id,
        )
    except sqlcipher3.IntegrityError as exc:
        # The unique index on `supersedes`. Two corrections of the same note
        # would fork the thread, leaving no single answer to what it says now.
        raise RevisionError(
            "That note has already been corrected. Edit the correction instead."
        ) from exc

    # Deliberately not via `set_tags`: that would mark the note processed and
    # relabel a person's decision as the model's. The correction keeps every
    # answer already given about it and still queues for sorting, because the
    # machine's time is what it is there for.
    tags.carry_forward(conn, note_id, revision.id)
    return models.get_note(conn, revision.id)


def threads(conn) -> list[Thread]:
    """Every note, grouped with its corrections, ordered as the record reads.

    Ordered by when the *original* happened, not when a correction was written:
    correcting a note from last month should not move it to the top of today.
    """
    notes = models.list_notes(conn, include_replaced=True)
    replaced_by = {note.supersedes: note for note in notes if note.supersedes}
    roots = [note for note in notes if note.supersedes is None]

    built = [Thread(revisions=tuple(_walk(root, replaced_by))) for root in roots]
    built.sort(key=lambda thread: (thread.root.occurred_at, thread.root.id))
    return built


def thread_for(conn, note_id: int) -> Thread | None:
    """The thread any one revision belongs to, found from any point in it."""
    for thread in threads(conn):
        if any(note.id == note_id for note in thread.revisions):
            return thread
    return None


def _walk(root: models.Note, replaced_by: dict[int, models.Note]) -> list[models.Note]:
    """Follow the corrections forward from a note that replaces nothing.

    Guarded against a cycle rather than trusting there cannot be one: the rows
    are structural, not hashed content, and a loop here would hang the interface
    rather than report a problem.
    """
    line = [root]
    seen = {root.id}
    while True:
        following = replaced_by.get(line[-1].id)
        if following is None or following.id in seen:
            return line
        seen.add(following.id)
        line.append(following)
