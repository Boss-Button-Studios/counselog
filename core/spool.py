"""Capturing a note while the database is locked.

A note is worth writing in the ninety seconds after a conversation ends, and
demanding a passphrase first is how a tool stops being used. So writing needs no
unlocked session at all: the note is sealed to a public key and set aside, and
drained into the real database the next time someone signs in.

That is what lets the reading window be five minutes instead of hours.

**Sealing alone is not enough.** A public key is public, so anything able to
write this file could post to it. The locked server holds no secret and cannot
tell a real note from a forged one — so it does not try. It accepts, and the
*unlocked* server judges, where two independent checks apply:

  1. **A chain over the entries.** Each links to the one before, and the head is
     recorded inside the encrypted database at every drain. Altering, deleting
     or reordering breaks a link; rewriting the file wholesale fails because an
     attacker cannot forge continuity with a value they cannot read.
  2. **A per-device MAC.** Each enrolled browser holds a random key and stamps
     every note it writes. The verifying copy lives inside the encrypted
     database. Forging therefore needs a compromised enrolled browser, not
     merely write access to a file.

Anything failing either check is quarantined and shown, never silently kept.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from core import chain

SEAL_INFO = b"counselog-spool-v1"
GENESIS = chain.GENESIS_HASH
MAX_NOTE_CHARS = 100_000

SPOOL_SCHEMA = """
-- A random name for this file, given when it is created and never changed. It
-- is what lets the unlocked server tell "the same spool, further along" from "a
-- different spool with the same shape" — which decides whether re-reading from
-- the start would recover notes or file the same ones twice.
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS entries (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    ciphertext  BLOB NOT NULL,
    mac         BLOB NOT NULL,
    device_id   TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    entry_hash  TEXT NOT NULL,
    received_at TEXT NOT NULL
);
"""


class SpoolError(Exception):
    """The spool could not be written or read."""


@dataclass(frozen=True)
class SpoolEntry:
    seq: int
    ciphertext: bytes
    mac: bytes
    device_id: str
    prev_hash: str
    entry_hash: str
    received_at: str


@dataclass(frozen=True)
class DrainedNote:
    """A note recovered from the spool and shown to be genuine.

    Two times, deliberately. `claimed_at` is what the writing device said, and
    is covered by its stamp so it cannot be moved afterwards. `received_at` is
    when this machine took the note in. They are kept apart because a phone's
    clock is a phone's clock: the note is filed under the one clock we control,
    and a device that disagrees with it can be shown rather than believed.
    """

    seq: int
    text: str
    claimed_at: str
    received_at: str
    device_id: str


@dataclass(frozen=True)
class Quarantined:
    """An entry that failed a check. Kept, shown, never accepted."""

    seq: int
    device_id: str
    reason: str


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ── the keypair ──────────────────────────────────────────────────────────────


def new_identity() -> tuple[bytes, bytes]:
    """A fresh spool keypair: (private, public), both raw bytes."""
    private = X25519PrivateKey.generate()
    return (
        private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        ),
        private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        ),
    )


def public_of(private_key: bytes) -> bytes:
    """The public half of a stored private key.

    Used to check that the published public key still belongs to the private one
    inside the database. If it does not, something replaced the file that the
    locked server seals to.
    """
    return X25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def _derive(shared: bytes, ephemeral_public: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=ephemeral_public, info=SEAL_INFO).derive(shared)


def seal(public_key: bytes, plaintext: bytes) -> bytes:
    """Encrypt to the spool's public key, with no way back.

    A fresh ephemeral keypair per note, so two identical notes do not produce
    identical ciphertext and the sealing side keeps nothing that could reopen
    them.
    """
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(public_key))
    nonce = os.urandom(12)
    body = AESGCM(_derive(shared, ephemeral_public)).encrypt(nonce, plaintext, SEAL_INFO)
    return ephemeral_public + nonce + body


def unseal(private_key: bytes, sealed: bytes) -> bytes:
    """Recover a sealed note. Only possible once the database is open."""
    if len(sealed) < 44:
        raise SpoolError("The sealed note is too short to be valid.")
    ephemeral_public, nonce, body = sealed[:32], sealed[32:44], sealed[44:]
    shared = X25519PrivateKey.from_private_bytes(private_key).exchange(
        X25519PublicKey.from_public_bytes(ephemeral_public))
    return AESGCM(_derive(shared, ephemeral_public)).decrypt(nonce, body, SEAL_INFO)


# ── what a device stamps ─────────────────────────────────────────────────────


def stamped_bytes(text: str, captured_at: str, device_id: str) -> bytes:
    """The exact bytes a device stamps with its key.

    Covers when and where as well as what, so an entry cannot be lifted from one
    device's history and replayed as another's, nor have its timestamp moved
    after the fact.

    Length-prefixed rather than JSON, and that choice is load-bearing. These
    bytes are the one thing in Counselog produced in a browser and checked in
    Python, so two languages have to agree on them exactly. JSON does not give
    that: implementations differ on how they escape control characters and lone
    surrogates, and on whether they escape non-ASCII at all. A disagreement
    would quarantine a genuine note and look like tampering. Four bytes of
    length in front of each UTF-8 field is something any language reproduces
    byte for byte (Law 7). `tests/test_web_capture.py` checks the browser's
    encoder against this one.
    """
    return b"".join(chain.length_prefixed(part.encode("utf-8"))
                    for part in (text, captured_at, device_id))


def device_mac(secret: bytes, text: str, captured_at: str, device_id: str) -> bytes:
    return hmac.new(secret, stamped_bytes(text, captured_at, device_id),
                    hashlib.sha256).digest()


# ── what is sealed ───────────────────────────────────────────────────────────


def sealed_payload(text: str, captured_at: str, device_id: str) -> bytes:
    """The note as it is put into the envelope.

    Sealed here and opened here — no browser ever writes or reads these bytes —
    so JSON is safe and readable, unlike the stamp above.
    """
    return json.dumps(
        {"text": text, "captured_at": captured_at, "device_id": device_id},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")


# ── the file ─────────────────────────────────────────────────────────────────


def connect(path: Path | str) -> sqlite3.Connection:
    """Open the spool.

    Plain SQLite, not SQLCipher: every entry is already sealed individually, and
    a locked server has no key with which to open an encrypted file anyway. What
    is wanted here is atomic appends and stable ordering.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    # Overwrite freed content instead of leaving it in the page. This file holds
    # note text that has not reached the encrypted database yet, and clearing a
    # drained body (see `clear_bodies`) should not leave the old bytes lying in
    # a free page where a strings(1) would find them.
    conn.execute("PRAGMA secure_delete = ON")
    conn.executescript(SPOOL_SCHEMA)
    conn.execute("INSERT OR IGNORE INTO meta (key, value) VALUES ('spool_id', ?)",
                 (os.urandom(16).hex(),))
    conn.commit()
    if path.exists():
        os.chmod(path, 0o600)
    return conn


def identity(conn: sqlite3.Connection) -> str:
    """This file's random name. Empty only for a spool written before names."""
    row = conn.execute("SELECT value FROM meta WHERE key = 'spool_id'").fetchone()
    return row["value"] if row else ""


def hash_at(conn: sqlite3.Connection, seq: int) -> str | None:
    """The hash recorded at one position, or None if there is nothing there."""
    row = conn.execute("SELECT entry_hash FROM entries WHERE seq = ?", (seq,)).fetchone()
    return row["entry_hash"] if row else None


def head(conn: sqlite3.Connection) -> tuple[int, str]:
    """The last position and hash in the spool."""
    row = conn.execute(
        "SELECT seq, entry_hash FROM entries ORDER BY seq DESC LIMIT 1").fetchone()
    return (int(row["seq"]), row["entry_hash"]) if row else (0, GENESIS)


def append(conn: sqlite3.Connection, public_key: bytes, *, text: str,
           captured_at: str, device_id: str, mac: bytes) -> int:
    """Seal a note and add it to the spool. Possible while locked."""
    if not text.strip():
        raise SpoolError("A note needs some text.")
    if len(text) > MAX_NOTE_CHARS:
        raise SpoolError("That note is too long.")

    plaintext = sealed_payload(text, captured_at, device_id)
    ciphertext = seal(public_key, plaintext)
    _, prev_hash = head(conn)
    entry_hash = hashlib.sha256(
        chain.length_prefixed(prev_hash.encode("ascii"))
        + chain.length_prefixed(ciphertext)
        + chain.length_prefixed(mac)
        + chain.length_prefixed(device_id.encode("utf-8"))
    ).hexdigest()

    with conn:
        cursor = conn.execute(
            "INSERT INTO entries (ciphertext, mac, device_id, prev_hash, entry_hash, "
            "received_at) VALUES (?, ?, ?, ?, ?, ?)",
            (ciphertext, mac, device_id, prev_hash, entry_hash, utc_now()),
        )
    return int(cursor.lastrowid)


def entries_after(conn: sqlite3.Connection, seq: int) -> list[SpoolEntry]:
    return [
        SpoolEntry(seq=int(r["seq"]), ciphertext=r["ciphertext"], mac=r["mac"],
                   device_id=r["device_id"], prev_hash=r["prev_hash"],
                   entry_hash=r["entry_hash"], received_at=r["received_at"])
        for r in conn.execute("SELECT * FROM entries WHERE seq > ? ORDER BY seq", (seq,))
    ]


def clear_bodies(conn: sqlite3.Connection, up_to_seq: int, *,
                 keep: frozenset[int] | set[int] = frozenset()) -> int:
    """Empty the sealed body of entries already in the record. Keeps the row.

    The same reasoning as a tombstone in the record itself: the link has to
    survive so the chain still verifies, but the text does not need to be here
    once it is safely inside the encrypted database.

    Without this the spool keeps a complete sealed copy of every note ever
    written while locked, for as long as the file exists — so `counselog forget`
    would clear a note from the record and leave that copy behind, recoverable
    by anyone who could open the spool key. Honouring a deletion request has to
    mean the text is gone from everywhere it was put.

    `keep` is for entries that were quarantined. Their text is not in the record
    and is not anywhere else, so clearing it would destroy the only copy of what
    might be a genuine note.

    Cleared in place with `secure_delete` on, and the caller vacuums afterwards.
    Neither is a guarantee the bytes are unrecoverable from the physical disk —
    a copy-on-write filesystem or an SSD's wear levelling can keep an old page
    alive regardless. This narrows the window; it does not close it.
    """
    targets = [
        row["seq"] for row in conn.execute(
            "SELECT seq FROM entries WHERE seq <= ? AND length(ciphertext) > 0",
            (up_to_seq,))
        if row["seq"] not in keep
    ]
    if not targets:
        return 0
    with conn:
        conn.executemany("UPDATE entries SET ciphertext = X'' WHERE seq = ?",
                         [(seq,) for seq in targets])
    return len(targets)


def compact(conn: sqlite3.Connection) -> None:
    """Rewrite the file so cleared bodies stop occupying pages in it."""
    conn.execute("VACUUM")


def recompute_hash(entry: SpoolEntry) -> str:
    return hashlib.sha256(
        chain.length_prefixed(entry.prev_hash.encode("ascii"))
        + chain.length_prefixed(entry.ciphertext)
        + chain.length_prefixed(entry.mac)
        + chain.length_prefixed(entry.device_id.encode("utf-8"))
    ).hexdigest()


def drain(
    conn: sqlite3.Connection,
    *,
    private_key: bytes,
    device_secrets: dict[str, bytes],
    from_seq: int,
    expected_head: str,
) -> tuple[list[DrainedNote], list[Quarantined]]:
    """Recover everything written since the last drain, judging as we go.

    `expected_head` is the hash recorded inside the encrypted database at the
    previous drain. Requiring the spool to continue from it is what makes a
    wholesale rewrite detectable: the attacker would have to reproduce a value
    they could not read.

    Never raises on a bad entry. One forged note must not block the genuine ones
    behind it, or refusing to accept anything becomes a denial of service.
    """
    accepted: list[DrainedNote] = []
    quarantined: list[Quarantined] = []
    previous = expected_head

    for entry in entries_after(conn, from_seq):
        if entry.prev_hash != previous:
            quarantined.append(Quarantined(
                entry.seq, entry.device_id,
                "does not follow the previous entry — the spool was altered"))
            previous = entry.entry_hash
            continue
        previous = entry.entry_hash

        if recompute_hash(entry) != entry.entry_hash:
            quarantined.append(Quarantined(
                entry.seq, entry.device_id, "its own hash does not match its contents"))
            continue

        secret = device_secrets.get(entry.device_id)
        if secret is None:
            quarantined.append(Quarantined(
                entry.seq, entry.device_id,
                "written by a device that is not enrolled"))
            continue

        try:
            plaintext = unseal(private_key, entry.ciphertext)
            payload = json.loads(plaintext.decode("utf-8"))
            text = payload["text"]
            captured_at = payload["captured_at"]
            device_id = payload["device_id"]
        except Exception:
            # Deliberately broad: anything unreadable is quarantined rather than
            # allowed to stop the drain.
            quarantined.append(Quarantined(
                entry.seq, entry.device_id, "could not be opened or read"))
            continue

        if device_id != entry.device_id:
            quarantined.append(Quarantined(
                entry.seq, entry.device_id,
                "claims a different device inside than outside"))
            continue

        expected_mac = device_mac(secret, text, captured_at, device_id)
        if not hmac.compare_digest(expected_mac, entry.mac):
            quarantined.append(Quarantined(
                entry.seq, entry.device_id,
                "was not written by the device it claims to be from"))
            continue

        accepted.append(DrainedNote(seq=entry.seq, text=text, claimed_at=captured_at,
                                    received_at=entry.received_at,
                                    device_id=device_id))

    return accepted, quarantined
