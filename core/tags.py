"""Which bin a note belongs in, and who decided.

Bins are addressed by a stable key — 'self', 'team', or 'person:<id>' — never by
their row id, because ids are auto-increment and may legitimately differ between
the laptop and the mirror. Person ids are preserved across the wire, so the key
means the same thing on both machines.

Split out of `core/models.py` when that file outgrew the length cap. The
dependency runs one way: a tag needs to know what a note and a person are, and
neither needs to know anything about tags.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Sequence

from core.models import (
    SUPERSEDED,
    ModelError,
    Note,
    note_from_row,
    bin_for_person,
    fixed_bin,
)

if TYPE_CHECKING:
    import sqlcipher3


# ── bins by stable key, and tags ─────────────────────────────────────────────
#
# Bin ids are auto-increment and can legitimately differ between the laptop and
# the mirror. Tags therefore travel by a stable key — 'self', 'team', or
# 'person:<person id>' — and each machine resolves that to its own local id.
# Person ids are preserved across the wire, so the key is stable everywhere.

BIN_SELF = "self"
BIN_TEAM = "team"
PERSON_PREFIX = "person:"


def bin_key_for_id(conn: "sqlcipher3.Connection", bin_id: int) -> str:
    row = conn.execute("SELECT kind, person_id FROM bins WHERE id = ?", (bin_id,)).fetchone()
    if row is None:
        raise ModelError(f"No bin with id {bin_id}.")
    if row["kind"] == "person":
        return f"{PERSON_PREFIX}{row['person_id']}"
    return row["kind"]


def bin_id_for_key(conn: "sqlcipher3.Connection", key: str) -> int:
    if key in (BIN_SELF, BIN_TEAM):
        return fixed_bin(conn, key)
    if key.startswith(PERSON_PREFIX):
        try:
            person_id = int(key[len(PERSON_PREFIX):])
        except ValueError as exc:
            raise ModelError(f"Malformed bin key {key!r}.") from exc
        return bin_for_person(conn, person_id)
    raise ModelError(f"Unknown bin key {key!r}.")


def set_tags(conn: "sqlcipher3.Connection", note_id: int,
             tags: "Sequence[tuple[str, float | None]]") -> None:
    """Replace a note's tags and mark it processed.

    Replacing rather than adding, so re-tagging a note after correcting an alias
    converges instead of accumulating stale bins. Tags live outside the hashed
    note body, so this never disturbs the chain.
    """
    with conn:
        conn.execute("DELETE FROM note_tags WHERE note_id = ?", (note_id,))
        for key, confidence in tags:
            conn.execute(
                "INSERT INTO note_tags (note_id, bin_id, confidence) VALUES (?, ?, ?)",
                (note_id, bin_id_for_key(conn, key), confidence),
            )
        conn.execute("UPDATE notes SET processed = 1 WHERE id = ?", (note_id,))


def tags_for_note(conn: "sqlcipher3.Connection", note_id: int) -> list[tuple[str, float | None]]:
    rows = conn.execute(
        "SELECT bin_id, confidence FROM note_tags WHERE note_id = ? ORDER BY bin_id",
        (note_id,),
    ).fetchall()
    return [(bin_key_for_id(conn, int(r["bin_id"])), r["confidence"]) for r in rows]


def notes_for_bin(conn: "sqlcipher3.Connection", key: str, *,
                  since: str | None = None, until: str | None = None) -> list[Note]:
    """Every note in one bin, in the order things happened."""
    sql = ("SELECT n.* FROM notes n JOIN note_tags t ON t.note_id = n.id "
           f"WHERE t.bin_id = ? AND NOT n.{SUPERSEDED}")
    params: list[object] = [bin_id_for_key(conn, key)]
    if since:
        sql += " AND coalesce(n.backdated_at, n.captured_at) >= ?"
        params.append(since)
    if until:
        sql += " AND coalesce(n.backdated_at, n.captured_at) <= ?"
        params.append(until)
    sql += " ORDER BY coalesce(n.backdated_at, n.captured_at), n.id"
    return [note_from_row(r) for r in conn.execute(sql, params)]


def tags_needing_review(conn: "sqlcipher3.Connection", threshold: float) -> list[tuple[Note, str, float]]:
    """Model-assigned tags the model was not sure about.

    Exact alias matches have a NULL confidence and never appear here — there is
    nothing to second-guess about a name that is literally present.

    Replaced notes are skipped. A corrected note is re-sorted, so its old version
    and its new one would otherwise both queue up, asking twice about the same
    thing and once about text no longer in the record.
    """
    rows = conn.execute(
        "SELECT n.*, t.bin_id, t.confidence FROM note_tags t JOIN notes n ON n.id = t.note_id "
        f"WHERE t.confidence IS NOT NULL AND t.confidence < ? AND NOT n.{SUPERSEDED} "
        "ORDER BY t.confidence, n.id",
        (threshold,),
    ).fetchall()
    return [(note_from_row(r), bin_key_for_id(conn, int(r["bin_id"])), float(r["confidence"]))
            for r in rows]


def confirm_tag(conn: "sqlcipher3.Connection", note_id: int, key: str) -> None:
    """Accept a suggested tag. A confirmed tag is as good as an exact match."""
    with conn:
        conn.execute(
            "UPDATE note_tags SET confidence = 1.0 WHERE note_id = ? AND bin_id = ?",
            (note_id, bin_id_for_key(conn, key)),
        )


def reject_tag(conn: "sqlcipher3.Connection", note_id: int, key: str) -> None:
    with conn:
        conn.execute("DELETE FROM note_tags WHERE note_id = ? AND bin_id = ?",
                     (note_id, bin_id_for_key(conn, key)))
