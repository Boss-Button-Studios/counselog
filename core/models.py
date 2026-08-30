"""Reading and writing the domain objects: people, bins, notes, tags, chain.

The one rule that shapes this module: a note and its chain entry are written in
a single transaction, always. A note without a chain entry is unverifiable, and
a chain entry without a note is a break. Nothing outside this module should
insert into `notes` directly.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable, Sequence

import sqlcipher3

from core import chain
from core.sanitize import sanitize

SOURCE_TEXT = "text_prompt"
SOURCE_FILE = "file_import"
TRUST_SELF = "self_authored"
TRUST_THIRD_PARTY = "third_party"


class ModelError(Exception):
    """A domain rule was violated."""


def utc_now() -> str:
    """One place that decides what 'now' looks like, so it is consistent."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class Person:
    id: int
    display_name: str
    aliases: tuple[str, ...]
    active: bool
    created_at: str


@dataclass(frozen=True)
class Note:
    id: int
    captured_at: str
    backdated_at: str | None
    source_type: str
    source_trust: str
    raw_text: str
    processed: bool
    tombstoned_at: str | None

    @property
    def tombstoned(self) -> bool:
        return self.tombstoned_at is not None

    @property
    def occurred_at(self) -> str:
        """When the event happened, as best the record knows.

        Backdating is the user's claim about the past; captured_at is the fact
        of when it was written. Reports order by this, and mark the difference.
        """
        return self.backdated_at or self.captured_at


# ── people and bins ──────────────────────────────────────────────────────────


def add_person(conn: "sqlcipher3.Connection", display_name: str,
               aliases: Sequence[str] = ()) -> Person:
    """Add a person and their bin together.

    A person without a bin cannot be tagged, so the two are created in one
    transaction rather than left for a caller to remember.
    """
    display_name = display_name.strip()
    if not display_name:
        raise ModelError("A person needs a name.")

    cleaned = _clean_aliases(aliases, display_name)
    with conn:
        try:
            cursor = conn.execute(
                "INSERT INTO people (display_name, aliases, active, created_at) "
                "VALUES (?, ?, 1, ?)",
                (display_name, json.dumps(cleaned), utc_now()),
            )
        except sqlcipher3.IntegrityError as exc:
            raise ModelError(f"{display_name} is already on the list.") from exc
        person_id = int(cursor.lastrowid)
        conn.execute("INSERT INTO bins (kind, person_id) VALUES ('person', ?)", (person_id,))
    return get_person(conn, person_id)


def _clean_aliases(aliases: Iterable[str], display_name: str) -> list[str]:
    """Normalise aliases: trimmed, deduplicated, case-insensitive, no blanks.

    The display name is always an alias — matching should not depend on the user
    remembering to repeat it.
    """
    seen: dict[str, str] = {}
    for alias in (*aliases, display_name):
        text = sanitize(alias).strip()
        if text and text.casefold() not in seen:
            seen[text.casefold()] = text
    return list(seen.values())


def get_person(conn: "sqlcipher3.Connection", person_id: int) -> Person:
    row = conn.execute("SELECT * FROM people WHERE id = ?", (person_id,)).fetchone()
    if row is None:
        raise ModelError(f"No person with id {person_id}.")
    return _person_from_row(row)


def list_people(conn: "sqlcipher3.Connection", *, include_inactive: bool = False) -> list[Person]:
    sql = "SELECT * FROM people"
    if not include_inactive:
        sql += " WHERE active = 1"
    sql += " ORDER BY display_name COLLATE NOCASE"
    return [_person_from_row(r) for r in conn.execute(sql)]


def set_person_active(conn: "sqlcipher3.Connection", person_id: int, active: bool) -> Person:
    """Soft-delete or restore someone.

    Never a hard delete: their notes and the chain entries over them must
    survive, or the record stops being verifiable.
    """
    with conn:
        conn.execute("UPDATE people SET active = ? WHERE id = ?", (1 if active else 0, person_id))
    return get_person(conn, person_id)


def _person_from_row(row: "sqlcipher3.Row") -> Person:
    return Person(
        id=int(row["id"]),
        display_name=row["display_name"],
        aliases=tuple(json.loads(row["aliases"])),
        active=bool(row["active"]),
        created_at=row["created_at"],
    )


def bin_for_person(conn: "sqlcipher3.Connection", person_id: int) -> int:
    row = conn.execute("SELECT id FROM bins WHERE person_id = ?", (person_id,)).fetchone()
    if row is None:
        raise ModelError(f"No bin for person {person_id}.")
    return int(row["id"])


def fixed_bin(conn: "sqlcipher3.Connection", kind: str) -> int:
    row = conn.execute("SELECT id FROM bins WHERE kind = ?", (kind,)).fetchone()
    if row is None:
        raise ModelError(f"No '{kind}' bin in this database.")
    return int(row["id"])


# ── notes ────────────────────────────────────────────────────────────────────


def add_note(
    conn: "sqlcipher3.Connection",
    raw_text: str,
    *,
    source_type: str = SOURCE_TEXT,
    source_trust: str = TRUST_SELF,
    backdated_at: str | None = None,
    captured_at: str | None = None,
) -> Note:
    """Store a note and extend the chain, atomically.

    `captured_at` is set here, not by the caller, except in tests — the point of
    the field is that it records when the note reached the system, not when
    someone says it did. Backdating is a separate, explicit field.

    The text is sanitized before it is stored *and* before it is hashed, so the
    chain covers exactly what the database holds.
    """
    if not raw_text or not raw_text.strip():
        raise ModelError("A note needs some text.")
    if source_type not in (SOURCE_TEXT, SOURCE_FILE):
        raise ModelError(f"Unknown source type {source_type!r}.")
    if source_trust not in (TRUST_SELF, TRUST_THIRD_PARTY):
        raise ModelError(f"Unknown source trust {source_trust!r}.")

    cleaned = sanitize(raw_text)
    stamped = captured_at or utc_now()

    with conn:
        cursor = conn.execute(
            "INSERT INTO notes (captured_at, backdated_at, source_type, source_trust, "
            "raw_text, processed) VALUES (?, ?, ?, ?, ?, 0)",
            (stamped, backdated_at, source_type, source_trust, cleaned),
        )
        note_id = int(cursor.lastrowid)
        _append_chain_entry(conn, note_id, stamped, backdated_at, source_type,
                            source_trust, cleaned)
    return get_note(conn, note_id)


def _append_chain_entry(conn, note_id, captured_at, backdated_at, source_type,
                        source_trust, raw_text) -> None:
    """Extend the chain by one. Must run inside the caller's transaction."""
    body = chain.body_hash(
        note_id=note_id,
        captured_at=captured_at,
        backdated_at=backdated_at,
        source_type=source_type,
        source_trust=source_trust,
        raw_text=raw_text,
    )
    entry = chain.next_entry(chain_head(conn), note_id=note_id, body=body, hashed_at=utc_now())
    conn.execute(
        "INSERT INTO note_chain (seq, note_id, body_hash, prev_hash, entry_hash, hashed_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (entry.seq, entry.note_id, entry.body_hash, entry.prev_hash,
         entry.entry_hash, entry.hashed_at),
    )


def get_note(conn: "sqlcipher3.Connection", note_id: int) -> Note:
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise ModelError(f"No note with id {note_id}.")
    return _note_from_row(row)


def list_notes(
    conn: "sqlcipher3.Connection",
    *,
    since: str | None = None,
    until: str | None = None,
    unprocessed_only: bool = False,
) -> list[Note]:
    sql = "SELECT * FROM notes WHERE 1 = 1"
    params: list[object] = []
    if since:
        sql += " AND coalesce(backdated_at, captured_at) >= ?"
        params.append(since)
    if until:
        sql += " AND coalesce(backdated_at, captured_at) <= ?"
        params.append(until)
    if unprocessed_only:
        sql += " AND processed = 0"
    sql += " ORDER BY coalesce(backdated_at, captured_at), id"
    return [_note_from_row(r) for r in conn.execute(sql, params)]


def tombstone_note(conn: "sqlcipher3.Connection", note_id: int) -> Note:
    """Purge a note's text while keeping its place in the record.

    This is how deletion works here. The body goes; the chain entry stays, so
    the surrounding history remains verifiable. What is lost is the ability to
    prove anything about *this* note's text — which is the unavoidable cost of
    genuinely removing it.
    """
    note = get_note(conn, note_id)
    if note.tombstoned:
        raise ModelError(f"Note {note_id} is already cleared.")
    with conn:
        conn.execute(
            "UPDATE notes SET raw_text = '', tombstoned_at = ? WHERE id = ?",
            (utc_now(), note_id),
        )
    return get_note(conn, note_id)


def _note_from_row(row: "sqlcipher3.Row") -> Note:
    return Note(
        id=int(row["id"]),
        captured_at=row["captured_at"],
        backdated_at=row["backdated_at"],
        source_type=row["source_type"],
        source_trust=row["source_trust"],
        raw_text=row["raw_text"],
        processed=bool(row["processed"]),
        tombstoned_at=row["tombstoned_at"],
    )


# ── chain ────────────────────────────────────────────────────────────────────


def chain_head(conn: "sqlcipher3.Connection") -> chain.ChainEntry | None:
    row = conn.execute("SELECT * FROM note_chain ORDER BY seq DESC LIMIT 1").fetchone()
    return _entry_from_row(row) if row else None


def chain_entries(conn: "sqlcipher3.Connection") -> list[chain.ChainEntry]:
    return [_entry_from_row(r) for r in conn.execute("SELECT * FROM note_chain ORDER BY seq")]


def verify(conn: "sqlcipher3.Connection") -> chain.VerifyResult:
    """Recompute every note's hash and walk the chain.

    A tombstoned note reports its body as None: it cannot be rechecked, and
    saying so is more honest than quietly passing it.
    """
    bodies: dict[int, str | None] = {}
    for note in _all_notes(conn):
        if note.tombstoned:
            bodies[note.id] = None
        else:
            bodies[note.id] = chain.body_hash(
                note_id=note.id,
                captured_at=note.captured_at,
                backdated_at=note.backdated_at,
                source_type=note.source_type,
                source_trust=note.source_trust,
                raw_text=note.raw_text,
            )
    return chain.verify_chain(chain_entries(conn), bodies)


def _all_notes(conn: "sqlcipher3.Connection") -> list[Note]:
    return [_note_from_row(r) for r in conn.execute("SELECT * FROM notes ORDER BY id")]


def _entry_from_row(row: "sqlcipher3.Row") -> chain.ChainEntry:
    return chain.ChainEntry(
        seq=int(row["seq"]),
        note_id=int(row["note_id"]),
        body_hash=row["body_hash"],
        prev_hash=row["prev_hash"],
        entry_hash=row["entry_hash"],
        hashed_at=row["hashed_at"],
    )
