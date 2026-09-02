"""Taking spooled notes into the record, once the database is open.

`core/spool.py` is the locked half: it accepts a sealed note from anyone,
because a server with no key cannot tell a real one from a forgery. This is the
unlocked half, and it is where the judging happens — the drain runs, what passes
becomes a real note in the chain, and what fails is written down rather than
thrown away.

Three things live here because they only make sense with the key in hand:

  - **the spool keypair.** The private half is inside the encrypted database;
    the public half is published to a file so the locked server can seal.
  - **the bookmark.** How far the spool has been drained, and the hash it
    reached. Kept inside the encrypted database, which is what makes a wholesale
    rewrite of the spool detectable: an attacker cannot continue from a value
    they were never able to read.
  - **the quarantine.** Entries that failed a check, kept so they can be looked
    at tomorrow rather than only in the second after they were noticed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from core import devices, models, spool
from core.paths import spool_public_key_path

# How far a device's clock may disagree with this machine's before it is worth
# mentioning. Generous: a phone that is a minute out is normal, and nagging
# about it would train the user to ignore the message that matters.
CLOCK_TOLERANCE_SECONDS = 300

SEQ_KEY = "spool_drained_seq"
HEAD_KEY = "spool_drained_head"
FILE_KEY = "spool_drained_file"


class IntakeError(Exception):
    """The spool could not be taken in."""


@dataclass(frozen=True)
class ClockDisagreement:
    """A device whose idea of the time differs from this machine's."""

    device_id: str
    claimed_at: str
    received_at: str


@dataclass
class IntakeReport:
    """What a drain did, in terms the interface can show a person."""

    stored: list[models.Note] = field(default_factory=list)
    quarantined: list[spool.Quarantined] = field(default_factory=list)
    clock_disagreements: list[ClockDisagreement] = field(default_factory=list)
    # A different file than the one being read last time. Notes held in the old
    # one are gone; nothing in the new one was ever taken in, so it is read from
    # the start.
    spool_was_replaced: bool = False
    # The same file, but the entry the last drain stopped at is missing or
    # changed. Reading from the start would file notes twice, so it carries on
    # from the bookmark and the chain check does the rest.
    spool_was_altered: bool = False

    @property
    def anything_happened(self) -> bool:
        return bool(self.stored or self.quarantined
                    or self.spool_was_replaced or self.spool_was_altered)


# ── the keypair ──────────────────────────────────────────────────────────────


def ensure_identity(conn, path: Path | None = None) -> bytes:
    """Return the spool's public key, creating and publishing it if needed.

    Run at every sign-in, not only at setup, and that is deliberate. The
    published file is the one thing in this design that an attacker could
    usefully *replace*: swap in their own public key and the locked server would
    seal tomorrow's notes to them. Rewriting it from the private half every time
    the database is open bounds that to a single reading session, and the notes
    sealed to the wrong key cannot be opened here, so they surface in the
    quarantine instead of vanishing.
    """
    path = Path(path) if path is not None else spool_public_key_path()
    row = conn.execute("SELECT private_key FROM spool_identity WHERE id = 1").fetchone()
    if row is None:
        private, public = spool.new_identity()
        with conn:
            conn.execute(
                "INSERT INTO spool_identity (id, private_key, created_at) "
                "VALUES (1, ?, ?)",
                (private, devices.utc_now()),
            )
    else:
        private = bytes(row["private_key"])
        public = spool.public_of(private)

    _publish(public, path)
    return public


def private_key(conn) -> bytes:
    row = conn.execute("SELECT private_key FROM spool_identity WHERE id = 1").fetchone()
    if row is None:
        raise IntakeError("This database has no spool key yet.")
    return bytes(row["private_key"])


def _publish(public: bytes, path: Path) -> None:
    """Write the public key where the locked server can find it.

    Written to a temporary file and renamed, so a reader never sees a
    half-written key. 0600 even though it is public: the file being world
    readable would say nothing useful, and a tight default is the cheaper habit.
    """
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".new")
    try:
        with open(temporary, "wb", opener=lambda p, f: os.open(p, f, 0o600)) as handle:
            handle.write(public)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def published_key(path: Path | None = None) -> bytes:
    """The public key the locked server seals with.

    Length-checked rather than trusted: this file sits outside the encrypted
    database, so a short or empty one is a thing that can actually happen, and a
    clear refusal beats a confusing failure inside the cipher (Law 5).
    """
    path = Path(path) if path is not None else spool_public_key_path()
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise IntakeError(
            "This machine is not set up to take notes while locked yet."
        ) from exc
    if len(raw) != 32:
        raise IntakeError("The spool key on this machine is unusable.")
    return raw


# ── how far the spool has been read ──────────────────────────────────────────


def bookmark(conn) -> tuple[int, str, str]:
    """The last spool position taken in, the hash it ended on, and which file.

    All three, because two of them answer different questions. The hash proves
    the reading continues from where it stopped; the file name says whether it
    is even the same spool.
    """
    values = {
        row["key"]: row["value"]
        for row in conn.execute(
            "SELECT key, value FROM schema_meta WHERE key IN (?, ?, ?)",
            (SEQ_KEY, HEAD_KEY, FILE_KEY),
        )
    }
    try:
        return int(values[SEQ_KEY]), values[HEAD_KEY], values.get(FILE_KEY, "")
    except (KeyError, ValueError):
        return 0, spool.GENESIS, ""


def set_bookmark(conn, seq: int, head: str, spool_id: str) -> None:
    with conn:
        conn.executemany(
            "INSERT INTO schema_meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [(SEQ_KEY, str(seq)), (HEAD_KEY, head), (FILE_KEY, spool_id)],
        )


# ── the quarantine ───────────────────────────────────────────────────────────


def hold(conn, entry: spool.Quarantined, received_at: str) -> None:
    """Write down an entry that failed a check."""
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO spool_quarantine "
            "(seq, device_id, reason, received_at, noticed_at) VALUES (?, ?, ?, ?, ?)",
            (entry.seq, entry.device_id, entry.reason, received_at, devices.utc_now()),
        )


def held(conn, *, include_acknowledged: bool = False) -> list[dict]:
    """Everything the quarantine is holding, newest first."""
    query = ("SELECT seq, device_id, reason, received_at, noticed_at, acknowledged_at "
             "FROM spool_quarantine")
    if not include_acknowledged:
        query += " WHERE acknowledged_at IS NULL"
    return [dict(row) for row in conn.execute(query + " ORDER BY seq DESC")]


def acknowledge(conn, seq: int) -> bool:
    """Mark one held entry as seen. The row stays: it is the evidence."""
    with conn:
        cursor = conn.execute(
            "UPDATE spool_quarantine SET acknowledged_at = ? "
            "WHERE seq = ? AND acknowledged_at IS NULL",
            (devices.utc_now(), seq),
        )
    return cursor.rowcount > 0


# ── the drain ────────────────────────────────────────────────────────────────


def take_in(conn, spool_conn) -> IntakeReport:
    """Move everything written since the last drain into the record.

    Stores each note and advances the bookmark one entry at a time. Advancing
    the whole batch at the end would be simpler, but a crash halfway would leave
    notes already stored and a bookmark that had not moved — and the next drain
    would file every one of them a second time. Duplicate entries in a record
    that may be read in an HR conversation are worth this much care.
    """
    report = IntakeReport()
    from_seq, expected_head, from_file = bookmark(conn)
    this_file = spool.identity(spool_conn)

    # Deleting or rewriting the spool destroys notes; it cannot add any, because
    # a replacement still cannot produce a stamp without an enrolled browser's
    # key. So neither case refuses — refusing would only finish the job — but
    # both are reported, and which one it is decides where reading resumes.
    if from_seq and this_file and this_file != from_file:
        # A different file. Nothing in it was ever taken in, so it is safe, and
        # necessary, to read from the beginning.
        report.spool_was_replaced = True
        from_seq, expected_head = 0, spool.GENESIS
    elif from_seq and spool.hash_at(spool_conn, from_seq) != expected_head:
        # The same file, with the entry we stopped at missing or altered.
        # Reading from the start here would file everything before the bookmark
        # a second time, so it carries on and the chain check catches the rest.
        report.spool_was_altered = True

    entries = spool.entries_after(spool_conn, from_seq)
    if not entries:
        if report.spool_was_replaced and this_file:
            # Settle on the new file, so a replacement is reported once rather
            # than at every sign-in until something is written.
            set_bookmark(conn, 0, spool.GENESIS, this_file)
        return report


    accepted, quarantined = spool.drain(
        spool_conn,
        private_key=private_key(conn),
        device_secrets=devices.secrets_by_id(conn),
        from_seq=from_seq,
        expected_head=expected_head,
    )

    by_seq = {entry.seq: entry for entry in entries}
    outcomes: dict[int, object] = {note.seq: note for note in accepted}
    outcomes.update({bad.seq: bad for bad in quarantined})
    seen_devices: set[str] = set()

    for seq in sorted(outcomes):
        outcome = outcomes[seq]
        entry = by_seq[seq]
        if isinstance(outcome, spool.DrainedNote):
            _store(conn, outcome, report)
            seen_devices.add(outcome.device_id)
        else:
            hold(conn, outcome, entry.received_at)
            report.quarantined.append(outcome)
        set_bookmark(conn, seq, entry.entry_hash, this_file)

    for device_id in seen_devices:
        devices.touch(conn, device_id)
    return report


def _store(conn, note: spool.DrainedNote, report: IntakeReport) -> None:
    """File one drained note under this machine's clock.

    `captured_at` is the time the note reached this machine, not the time the
    writing device claimed. The claim is stamped and so cannot be moved by an
    attacker, but it is still a phone's clock, and `captured_at` is the field
    that has to mean something in an HR conversation. One clock, ours. A device
    that disagrees noticeably is reported rather than quietly corrected.
    """
    if _disagrees(note.claimed_at, note.received_at):
        report.clock_disagreements.append(
            ClockDisagreement(note.device_id, note.claimed_at, note.received_at))
    report.stored.append(
        models.add_note(conn, note.text, captured_at=note.received_at))


def _disagrees(claimed_at: str, received_at: str) -> bool:
    try:
        gap = datetime.fromisoformat(claimed_at) - datetime.fromisoformat(received_at)
    except ValueError:
        return True  # unparseable is a disagreement worth showing
    return abs(gap.total_seconds()) > CLOCK_TOLERANCE_SECONDS
