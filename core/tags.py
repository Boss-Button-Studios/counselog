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

from dataclasses import dataclass
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

# Who put a note in a bin. Only a person's decision survives re-sorting.
BY_ALIAS = "alias"      # the name was literally in the text
BY_MODEL = "model"      # the model judged it
BY_PERSON = "person"    # someone looked and said so

INCLUDED = "included"
EXCLUDED = "excluded"   # someone looked and said it is *not* about this


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
    """Record what sorting found, and mark the note processed.

    Replaces what sorting decided last time, so correcting an alias and running
    again converges instead of accumulating stale bins — but never touches what a
    *person* decided. A corrected note is re-sorted from scratch, so without that
    exemption every typo fix would throw away a judgment someone made and put the
    question back in the review queue.

    A bin a person has excluded is not re-added. The model is entitled to suggest
    it again; it is not entitled to overrule the answer it already got.

    Tags live outside the hashed note body, so none of this disturbs the chain.
    """
    decided = {
        bin_key_for_id(conn, int(row["bin_id"])): row["decision"]
        for row in conn.execute(
            "SELECT bin_id, decision FROM note_tags WHERE note_id = ? "
            "AND decided_by = ?", (note_id, BY_PERSON))
    }

    with conn:
        conn.execute("DELETE FROM note_tags WHERE note_id = ? AND decided_by != ?",
                     (note_id, BY_PERSON))
        for key, confidence in tags:
            if key in decided:
                continue  # a person has already answered this one, either way
            conn.execute(
                "INSERT INTO note_tags (note_id, bin_id, confidence, decided_by, "
                "decision) VALUES (?, ?, ?, ?, ?)",
                (note_id, bin_id_for_key(conn, key), confidence,
                 BY_ALIAS if confidence is None else BY_MODEL, INCLUDED),
            )
        conn.execute("UPDATE notes SET processed = 1 WHERE id = ?", (note_id,))


def tags_for_note(conn: "sqlcipher3.Connection", note_id: int) -> list[tuple[str, float | None]]:
    """The bins a note is in. Exclusions are decisions, not tags, and are not here."""
    return [(d.key, d.confidence) for d in tag_decisions(conn, note_id) if d.included]


@dataclass(frozen=True)
class TagDecision:
    """One answer about one bin, and where the answer came from."""

    key: str
    confidence: float | None
    decided_by: str
    decision: str

    @property
    def included(self) -> bool:
        return self.decision == INCLUDED

    @property
    def checked(self) -> bool:
        """Did a person actually look at this one?

        What a report needs in order to say what it stands on. An exact name
        match is reliable but nobody read it; only this is a human judgment.
        """
        return self.decided_by == BY_PERSON


def tag_decisions(conn: "sqlcipher3.Connection", note_id: int) -> list[TagDecision]:
    """Every answer recorded about this note, exclusions included."""
    return [
        TagDecision(key=bin_key_for_id(conn, int(r["bin_id"])), confidence=r["confidence"],
                    decided_by=r["decided_by"], decision=r["decision"])
        for r in conn.execute(
            "SELECT bin_id, confidence, decided_by, decision FROM note_tags "
            "WHERE note_id = ? ORDER BY bin_id", (note_id,))
    ]


def carry_forward(conn: "sqlcipher3.Connection", from_note: int, to_note: int) -> None:
    """Copy every decision from a note to the correction that replaces it.

    Provenance travels with them. Copying a person's judgment as though the model
    had made it would let the next sorting run discard it, which is the whole
    thing this exists to prevent.
    """
    decisions = tag_decisions(conn, from_note)
    if not decisions:
        return
    with conn:
        for d in decisions:
            conn.execute(
                "INSERT OR REPLACE INTO note_tags (note_id, bin_id, confidence, "
                "decided_by, decision) VALUES (?, ?, ?, ?, ?)",
                (to_note, bin_id_for_key(conn, d.key), d.confidence,
                 d.decided_by, d.decision),
            )


def notes_for_bin(conn: "sqlcipher3.Connection", key: str, *,
                  since: str | None = None, until: str | None = None) -> list[Note]:
    """Every note in one bin, in the order things happened."""
    sql = ("SELECT n.* FROM notes n JOIN note_tags t ON t.note_id = n.id "
           f"WHERE t.bin_id = ? AND t.decision = '{INCLUDED}' AND NOT n.{SUPERSEDED}")
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
        f"WHERE t.confidence IS NOT NULL AND t.confidence < ? "
        f"AND t.decided_by = '{BY_MODEL}' AND t.decision = '{INCLUDED}' "
        f"AND NOT n.{SUPERSEDED} "
        "ORDER BY t.confidence, n.id",
        (threshold,),
    ).fetchall()
    return [(note_from_row(r), bin_key_for_id(conn, int(r["bin_id"])), float(r["confidence"]))
            for r in rows]


def confirm_tag(conn: "sqlcipher3.Connection", note_id: int, key: str) -> None:
    """Accept a suggested tag. A confirmed tag is as good as an exact match.

    The confidence goes to NULL rather than 1.0: it is no longer a guess, and
    leaving a number there would mean a later reader could not tell a decision
    from a model that happened to sound certain — which is exactly the gap that
    made confirmations before this unrecoverable.
    """
    with conn:
        conn.execute(
            "INSERT INTO note_tags (note_id, bin_id, confidence, decided_by, decision) "
            "VALUES (?, ?, NULL, ?, ?) "
            "ON CONFLICT(note_id, bin_id) DO UPDATE SET confidence = NULL, "
            "decided_by = excluded.decided_by, decision = excluded.decision",
            (note_id, bin_id_for_key(conn, key), BY_PERSON, INCLUDED),
        )


def reject_tag(conn: "sqlcipher3.Connection", note_id: int, key: str) -> None:
    """Say a note is not about this after all, and have that remembered.

    Recorded rather than deleted. A corrected note is sorted again from scratch,
    and a deleted row says nothing — so the model would suggest the same bin next
    week and the same answer would have to be given again.
    """
    with conn:
        conn.execute(
            "INSERT INTO note_tags (note_id, bin_id, confidence, decided_by, decision) "
            "VALUES (?, ?, NULL, ?, ?) "
            "ON CONFLICT(note_id, bin_id) DO UPDATE SET confidence = NULL, "
            "decided_by = excluded.decided_by, decision = excluded.decision",
            (note_id, bin_id_for_key(conn, key), BY_PERSON, EXCLUDED),
        )
