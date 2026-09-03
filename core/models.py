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


# Distinguishes "leave this as it is" from "set this to None", where None is a
# value with its own meaning. A plain default cannot express both.
UNCHANGED = object()


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
    # Free text, written the way people write it. None means nobody has been
    # asked; '' means they were asked and preferred not to say. Keeping those
    # apart is the whole reason this is not a plain string — see the schema.
    pronouns: str | None = None

    @property
    def pronouns_known(self) -> bool:
        return bool(self.pronouns)

    @property
    def pronouns_withheld(self) -> bool:
        return self.pronouns == ""


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
    # The note this one replaces, if it is a correction of an earlier one.
    supersedes: int | None = None

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
               aliases: Sequence[str] = (), pronouns: str | None = None) -> Person:
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
                "INSERT INTO people (display_name, aliases, pronouns, active, created_at) "
                "VALUES (?, ?, ?, 1, ?)",
                (display_name, json.dumps(cleaned), pronouns, utc_now()),
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


def update_person(conn: "sqlcipher3.Connection", person_id: int, *,
                  display_name: str | None = None,
                  aliases: Sequence[str] | None = None,
                  pronouns: str | None | object = UNCHANGED) -> Person:
    """Correct a person's record.

    Aliases could only be set when someone was created, which quietly cost
    accuracy: they are what resolves a name exactly, so a missing or misspelled
    one sends a note to the model to guess about, or to no bin at all.

    `pronouns` needs a sentinel rather than a default of None, because None is
    itself a meaningful value here — "nobody has been asked" — and is a
    different thing from "do not change what is recorded".
    """
    person = get_person(conn, person_id)
    name = (display_name or person.display_name).strip()
    if not name:
        raise ModelError("A person needs a name.")
    cleaned = _clean_aliases(person.aliases if aliases is None else aliases, name)
    settled = person.pronouns if pronouns is UNCHANGED else pronouns

    with conn:
        try:
            conn.execute(
                "UPDATE people SET display_name = ?, aliases = ?, pronouns = ? "
                "WHERE id = ?",
                (name, json.dumps(cleaned), settled, person_id),
            )
        except sqlcipher3.IntegrityError as exc:
            raise ModelError(f"{name} is already on the list.") from exc
    return get_person(conn, person_id)


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
        pronouns=row["pronouns"],
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
    supersedes: int | None = None,
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
            "raw_text, processed, supersedes) VALUES (?, ?, ?, ?, ?, 0, ?)",
            (stamped, backdated_at, source_type, source_trust, cleaned, supersedes),
        )
        note_id = int(cursor.lastrowid)
        _append_chain_entry(conn, note_id, stamped, backdated_at, source_type,
                            source_trust, cleaned, supersedes)
    return get_note(conn, note_id)


def _append_chain_entry(conn, note_id, captured_at, backdated_at, source_type,
                        source_trust, raw_text, supersedes=None) -> None:
    """Extend the chain by one. Must run inside the caller's transaction."""
    body = chain.body_hash(
        note_id=note_id,
        captured_at=captured_at,
        backdated_at=backdated_at,
        source_type=source_type,
        source_trust=source_trust,
        raw_text=raw_text,
        supersedes=supersedes,
    )
    entry = chain.next_entry(chain_head(conn), note_id=note_id, body=body, hashed_at=utc_now())
    conn.execute(
        "INSERT INTO note_chain (seq, note_id, body_hash, prev_hash, entry_hash, "
        "hashed_at, canon_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (entry.seq, entry.note_id, entry.body_hash, entry.prev_hash,
         entry.entry_hash, entry.hashed_at, chain.CANON_VERSION),
    )


def get_note(conn: "sqlcipher3.Connection", note_id: int) -> Note:
    row = conn.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        raise ModelError(f"No note with id {note_id}.")
    return note_from_row(row)


# A note that has been edited is still in the record and still hashed, but it is
# no longer what the record *says*. Everything that reads notes for a person —
# lists, bins, tagging — wants the current text, so excluding replaced notes is
# the default and asking for them is explicit.
SUPERSEDED = ("id IN (SELECT supersedes FROM notes WHERE supersedes IS NOT NULL)")


def list_notes(
    conn: "sqlcipher3.Connection",
    *,
    since: str | None = None,
    until: str | None = None,
    unprocessed_only: bool = False,
    include_replaced: bool = False,
) -> list[Note]:
    sql = "SELECT * FROM notes WHERE 1 = 1"
    params: list[object] = []
    if not include_replaced:
        sql += f" AND NOT {SUPERSEDED}"
    if since:
        sql += " AND coalesce(backdated_at, captured_at) >= ?"
        params.append(since)
    if until:
        sql += " AND coalesce(backdated_at, captured_at) <= ?"
        params.append(until)
    if unprocessed_only:
        sql += " AND processed = 0"
    sql += " ORDER BY coalesce(backdated_at, captured_at), id"
    return [note_from_row(r) for r in conn.execute(sql, params)]


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


def note_from_row(row: "sqlcipher3.Row") -> Note:
    return Note(
        id=int(row["id"]),
        captured_at=row["captured_at"],
        backdated_at=row["backdated_at"],
        source_type=row["source_type"],
        source_trust=row["source_trust"],
        raw_text=row["raw_text"],
        processed=bool(row["processed"]),
        tombstoned_at=row["tombstoned_at"],
        supersedes=row["supersedes"],
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
    entries = chain_entries(conn)
    # Each body is rechecked under the serialisation its own entry was written
    # with. Trying versions until one matched would let a note be edited freely
    # in a field that only the newer version covers.
    versions = {entry.note_id: entry.canon_version for entry in entries}

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
                supersedes=note.supersedes,
                version=versions.get(note.id, 1),
            )
    return chain.verify_chain(entries, bodies)


def _all_notes(conn: "sqlcipher3.Connection") -> list[Note]:
    return [note_from_row(r) for r in conn.execute("SELECT * FROM notes ORDER BY id")]


def _entry_from_row(row: "sqlcipher3.Row") -> chain.ChainEntry:
    return chain.ChainEntry(
        seq=int(row["seq"]),
        note_id=int(row["note_id"]),
        body_hash=row["body_hash"],
        prev_hash=row["prev_hash"],
        entry_hash=row["entry_hash"],
        hashed_at=row["hashed_at"],
        canon_version=int(row["canon_version"]),
    )


def upsert_person(conn: "sqlcipher3.Connection", person_id: int, display_name: str,
                  aliases: "Sequence[str]", active: bool, created_at: str) -> None:
    """Mirror one person from the laptop, keeping the laptop's id.

    Preserving the id is what makes 'person:<id>' a stable bin key on both
    machines. The mirror never invents people, so this only ever receives.
    """
    with conn:
        conn.execute(
            "INSERT INTO people (id, display_name, aliases, active, created_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET display_name = excluded.display_name, "
            "aliases = excluded.aliases, active = excluded.active",
            (person_id, display_name, json.dumps(list(aliases)), 1 if active else 0, created_at),
        )
        existing = conn.execute("SELECT id FROM bins WHERE person_id = ?", (person_id,)).fetchone()
        if existing is None:
            conn.execute("INSERT INTO bins (kind, person_id) VALUES ('person', ?)", (person_id,))


def unprocessed_notes(conn: "sqlcipher3.Connection") -> list[Note]:
    """Notes still needing bin tagging.

    A replaced note is skipped: its text is no longer what the record says, and
    the model's time is far too expensive to spend on a superseded draft.
    """
    return [
        note_from_row(row) for row in conn.execute(
            f"SELECT * FROM notes WHERE processed = 0 AND tombstoned_at IS NULL "
            f"AND NOT {SUPERSEDED} ORDER BY id")
    ]
