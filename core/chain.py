"""Tamper-evidence for the note history.

The `captured_at` trigger stops an accidental edit. It does not stop someone who
holds the database key from deleting a row and writing a new one. Since these
notes may end up in an HR conversation, that gap matters, so every note also
appends an entry to a hash chain.

Each entry links to the one before it, so altering, inserting, reordering or
removing any note breaks every link after it. Rebuilding the chain to hide a
change means rewriting all later entries — and once phase 7 signs the chain
head, it means forging a signature too.

**What this proves and what it does not.** It proves the record has not changed
since it was written. It does not prove a note is *true*, and it does not prove
*when* the content was written — only the order in which entries were added.
Third-party proof of time needs an external timestamp authority (spec §10).

**Why the hash is split in two.** Each entry stores a `body_hash` over the note
itself and an `entry_hash` linking that body to the previous entry. Tombstoning
deletes the body but keeps the entry, and a single combined hash would then be
unrecomputable — every tombstone would look exactly like tampering. Splitting
them means a tombstoned note loses only the proof about *its own body*, while
the sequence around it stays fully verifiable.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Iterable, Sequence

# A change to how notes are serialised changes every hash after it, so the
# version is baked into the bytes. An old chain stays verifiable under its own
# version rather than silently failing under new rules.
CANON_VERSION = 1
CANON_PREFIX = b"counselog-note-v1"

# The chain has to start somewhere. Sixty-four zeros is conventional and
# unmistakable in a dump.
GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class ChainEntry:
    """One link. `seq` is 1-based and contiguous — gaps are themselves a break."""

    seq: int
    note_id: int
    body_hash: str
    prev_hash: str
    entry_hash: str
    hashed_at: str


@dataclass(frozen=True)
class Break:
    """Where verification stopped believing the record, and why.

    `seq` is 0 for a note that sits outside the chain entirely — there is no
    sequence position to point at, which is precisely the problem.
    """

    seq: int
    note_id: int
    reason: str


@dataclass(frozen=True)
class VerifyResult:
    checked: int
    tombstoned: int
    breaks: tuple[Break, ...]

    @property
    def ok(self) -> bool:
        return not self.breaks


def _field(value: bytes) -> bytes:
    """Length-prefix one field.

    Concatenating fields with a separator would be ambiguous: a note whose text
    contains the separator could be made to hash the same as a different note
    with different field boundaries. A four-byte length in front of each field
    removes that whole class of problem.
    """
    return struct.pack(">I", len(value)) + value


def canonical_note(
    *,
    note_id: int,
    captured_at: str,
    backdated_at: str | None,
    source_type: str,
    source_trust: str,
    raw_text: str,
) -> bytes:
    """The exact bytes that represent a note for hashing.

    Keyword-only and explicit: adding a field here silently changes every future
    hash, so it should be impossible to do by accident through positional args.
    The text must already be sanitized — hash what is stored, not what was typed.
    """
    parts: Sequence[bytes] = (
        CANON_PREFIX,
        str(note_id).encode("utf-8"),
        captured_at.encode("utf-8"),
        (backdated_at or "").encode("utf-8"),
        source_type.encode("utf-8"),
        source_trust.encode("utf-8"),
        raw_text.encode("utf-8"),
    )
    return b"".join(_field(part) for part in parts)


def body_hash(**note_fields: object) -> str:
    """SHA-256 over one note's canonical form."""
    return hashlib.sha256(canonical_note(**note_fields)).hexdigest()  # type: ignore[arg-type]


def link_hash(prev_hash: str, body: str) -> str:
    """SHA-256 binding a note's body to everything that came before it."""
    return hashlib.sha256(
        _field(prev_hash.encode("ascii")) + _field(body.encode("ascii"))
    ).hexdigest()


def next_entry(previous: ChainEntry | None, *, note_id: int, body: str, hashed_at: str) -> ChainEntry:
    """Build the entry that follows `previous`."""
    prev_hash = previous.entry_hash if previous else GENESIS_HASH
    seq = previous.seq + 1 if previous else 1
    return ChainEntry(
        seq=seq,
        note_id=note_id,
        body_hash=body,
        prev_hash=prev_hash,
        entry_hash=link_hash(prev_hash, body),
        hashed_at=hashed_at,
    )


def verify_chain(
    entries: Iterable[ChainEntry],
    bodies: dict[int, str | None],
) -> VerifyResult:
    """Walk the chain and report every break.

    `bodies` maps note id to the body hash recomputed from the note as it stands
    right now, or None if the note has been tombstoned and its body is gone.

    Reports *every* break rather than stopping at the first. One altered note
    breaks its own link and mismatches the next entry's `prev_hash`, and a reader
    deserves to see the whole shape of the damage — not one line at a time.

    Walking the chain alone is not enough. A note inserted straight into the
    notes table, with no chain entry, would never be visited by the walk — so
    fabricated notes could be appended and still verify clean. Every note must
    therefore be accounted for by an entry, and any that is not is a break.
    """
    breaks: list[Break] = []
    covered: set[int] = set()
    checked = 0
    tombstoned = 0
    expected_prev = GENESIS_HASH
    expected_seq = 1

    for entry in entries:
        checked += 1

        if entry.seq != expected_seq:
            breaks.append(Break(entry.seq, entry.note_id,
                                f"sequence jumps to {entry.seq}, expected {expected_seq}"))
            expected_seq = entry.seq

        if entry.prev_hash != expected_prev:
            breaks.append(Break(entry.seq, entry.note_id,
                                "does not follow the previous entry — a note was "
                                "changed, inserted, or removed before this point"))

        if entry.entry_hash != link_hash(entry.prev_hash, entry.body_hash):
            breaks.append(Break(entry.seq, entry.note_id,
                                "the entry's own hash does not match its contents"))

        current = bodies.get(entry.note_id, "__missing__")
        if current is None:
            # Tombstoned: the body is deliberately gone, so it cannot be
            # rechecked. The link either side of it still can be.
            tombstoned += 1
        elif current == "__missing__":
            breaks.append(Break(entry.seq, entry.note_id,
                                "the note this entry refers to is missing entirely"))
        elif current != entry.body_hash:
            breaks.append(Break(entry.seq, entry.note_id,
                                "the note's text has been changed since it was written"))

        expected_prev = entry.entry_hash
        expected_seq = entry.seq + 1
        covered.add(entry.note_id)

    for note_id in sorted(set(bodies) - covered):
        breaks.append(Break(0, note_id,
                            "this note is not in the chain at all — it was added "
                            "without being recorded"))

    return VerifyResult(checked=checked, tombstoned=tombstoned, breaks=tuple(breaks))
