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
    """A note recovered from the spool and shown to be genuine."""

    seq: int
    text: str
    captured_at: str
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


# ── what a device signs ──────────────────────────────────────────────────────


def canonical_capture(text: str, captured_at: str, device_id: str) -> bytes:
    """The exact bytes a device stamps.

    Covers when and where as well as what, so an entry cannot be lifted from one
    device's history and replayed as another's, nor have its timestamp moved.
    """
    payload = json.dumps(
        {"text": text, "captured_at": captured_at, "device_id": device_id},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return payload.encode("utf-8")


def device_mac(secret: bytes, text: str, captured_at: str, device_id: str) -> bytes:
    return hmac.new(secret, canonical_capture(text, captured_at, device_id),
                    hashlib.sha256).digest()


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
    conn.executescript(SPOOL_SCHEMA)
    conn.commit()
    if path.exists():
        os.chmod(path, 0o600)
    return conn


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

    plaintext = canonical_capture(text, captured_at, device_id)
    ciphertext = seal(public_key, plaintext)
    _, prev_hash = head(conn)
    entry_hash = hashlib.sha256(
        chain._field(prev_hash.encode("ascii"))
        + chain._field(ciphertext)
        + chain._field(mac)
        + chain._field(device_id.encode("utf-8"))
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


def recompute_hash(entry: SpoolEntry) -> str:
    return hashlib.sha256(
        chain._field(entry.prev_hash.encode("ascii"))
        + chain._field(entry.ciphertext)
        + chain._field(entry.mac)
        + chain._field(entry.device_id.encode("utf-8"))
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

        accepted.append(DrainedNote(seq=entry.seq, text=text,
                                    captured_at=captured_at, device_id=device_id))

    return accepted, quarantined
