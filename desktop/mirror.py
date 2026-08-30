"""The desktop's copy of the notes.

Spec §4 wants this so reports can be regenerated without shipping note text back
across the network every time. It is a mirror, not a second source of truth: it
only ever receives, never originates.

It carries the chain as well as the notes, which gives something the plan did
not call out — the two machines hold independent copies of the same history, so
altering the record convincingly means altering both, consistently, with the key
to each. Divergence between them is itself evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

import sqlcipher3

from core import chain, models
from core.protocol import NotePayload, ProtocolError


@dataclass(frozen=True)
class SyncResult:
    stored: int
    skipped: int
    head_seq: int


def head_seq(conn: "sqlcipher3.Connection") -> int:
    """The last chain position this mirror holds. 0 when empty."""
    head = models.chain_head(conn)
    return head.seq if head else 0


def store(conn: "sqlcipher3.Connection", payloads: list[NotePayload]) -> SyncResult:
    """Write a validated batch into the mirror.

    Idempotent: re-sending notes the mirror already has is a no-op, so a sync
    interrupted half way can simply be run again.

    Refuses a batch that would leave a gap. The chain only means anything if it
    is contiguous, and a mirror with a hole in it would report tampering forever
    after — so an out-of-order batch is rejected rather than half-applied.
    """
    stored = skipped = 0
    expected = head_seq(conn) + 1

    with conn:
        for payload in payloads:
            if payload.seq < expected:
                skipped += 1  # already have it
                continue
            if payload.seq != expected:
                raise ProtocolError(
                    f"This batch starts at position {payload.seq} but the mirror "
                    f"expects {expected}. Send the missing notes first."
                )
            _insert(conn, payload)
            stored += 1
            expected += 1

    return SyncResult(stored=stored, skipped=skipped, head_seq=head_seq(conn))


def _insert(conn: "sqlcipher3.Connection", payload: NotePayload) -> None:
    """Insert one note and its chain entry, preserving the laptop's ids.

    Ids are kept identical across both machines so a report generated here can
    be matched against the laptop's copy without a translation table.
    """
    conn.execute(
        "INSERT INTO notes (id, captured_at, backdated_at, source_type, source_trust, "
        "raw_text, processed, tombstoned_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?)",
        (payload.note_id, payload.captured_at, payload.backdated_at, payload.source_type,
         payload.source_trust, payload.raw_text, payload.tombstoned_at),
    )
    conn.execute(
        "INSERT INTO note_chain (seq, note_id, body_hash, prev_hash, entry_hash, hashed_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (payload.seq, payload.note_id, payload.body_hash, payload.prev_hash,
         payload.entry_hash, payload.hashed_at),
    )


def to_payloads(conn: "sqlcipher3.Connection", *, after_seq: int = 0) -> list[NotePayload]:
    """Read notes out of a database as sendable payloads.

    Lives here rather than on the laptop side because both ends need the same
    view of what a note-on-the-wire is, and one definition is easier to keep
    right than two.
    """
    rows = conn.execute(
        "SELECT c.seq, c.body_hash, c.prev_hash, c.entry_hash, c.hashed_at, n.* "
        "FROM note_chain c JOIN notes n ON n.id = c.note_id "
        "WHERE c.seq > ? ORDER BY c.seq",
        (after_seq,),
    ).fetchall()
    return [
        NotePayload(
            note_id=int(row["id"]),
            captured_at=row["captured_at"],
            backdated_at=row["backdated_at"],
            source_type=row["source_type"],
            source_trust=row["source_trust"],
            raw_text=row["raw_text"],
            tombstoned_at=row["tombstoned_at"],
            seq=int(row["seq"]),
            body_hash=row["body_hash"],
            prev_hash=row["prev_hash"],
            entry_hash=row["entry_hash"],
            hashed_at=row["hashed_at"],
        )
        for row in rows
    ]


def verify(conn: "sqlcipher3.Connection") -> chain.VerifyResult:
    """Check the mirror's own copy of the history."""
    return models.verify(conn)
