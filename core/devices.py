"""Browsers allowed to write notes while the database is locked.

Capture has to work with no key available, so the locked server cannot tell a
real note from one dropped into the spool by anything else able to write the
file. Enrolment is what closes that gap: each browser is given a random key,
kept in that browser, and stamps every note it writes. The verifying copy lives
here, inside the encrypted database, so only an *unlocked* server can check it.

That division is the whole design. The locked server accepts; the unlocked
server judges. Forging a note therefore needs a compromised enrolled browser,
not merely write access to a file.

A device id is a handle, not a secret. It travels with every note and appears in
the interface, so it is deliberately short and says nothing about the machine.
"""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

SECRET_BYTES = 32
MAX_LABEL_CHARS = 60

# 16 lowercase hex characters. Narrow on purpose: this value arrives from a
# browser on every capture, and anything not matching is not one of ours (Law 5).
DEVICE_ID = re.compile(r"\A[0-9a-f]{16}\Z")
MAC_HEX = re.compile(r"\A[0-9a-f]{64}\Z")

# Exactly the form `utc_now` produces, and nothing else. The browser builds this
# string itself and stamps it, so accepting a looser set of spellings would mean
# two notes a second apart could sort in the wrong order.
CAPTURED_AT = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+00:00\Z")

# What a note carries when no enrolled browser stamped it — because scripting is
# off, or because this browser was never enrolled. Such a note is still accepted
# and still sealed; it is simply held for review instead of filed, and the
# person writing it is told so at the time.
UNSTAMPED = "unstamped"


class DeviceError(Exception):
    """A device could not be enrolled or found."""


@dataclass(frozen=True)
class Device:
    """An enrolled browser, as the interface may describe it. Never the key."""

    id: str
    label: str
    enrolled_at: str
    last_seen: str | None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def is_device_id(value: str | None) -> bool:
    return bool(value) and bool(DEVICE_ID.fullmatch(value))


def is_mac_hex(value: str | None) -> bool:
    return bool(value) and bool(MAC_HEX.fullmatch(value))


def is_captured_at(value: str | None) -> bool:
    return bool(value) and bool(CAPTURED_AT.fullmatch(value))


def clean_label(label: str | None) -> str:
    """A short, printable name for a browser.

    Typed by a person and shown back to them, so it is trimmed and capped rather
    than trusted. An empty label is not an error: not everyone names their
    phone, and refusing the enrolment over it would be a poor trade.
    """
    text = " ".join((label or "").split())
    text = "".join(char for char in text if char.isprintable())
    return text[:MAX_LABEL_CHARS] or "this browser"


def enroll(conn, label: str | None) -> tuple[Device, bytes]:
    """Register a browser and hand back its key, once.

    The key is returned here and never again. It is stored because the unlocked
    server has to verify stamps with it, but there is no reason to put it in
    front of a person twice — a browser that lost it enrols again.
    """
    device_id = secrets.token_hex(8)
    secret = secrets.token_bytes(SECRET_BYTES)
    cleaned = clean_label(label)
    enrolled_at = utc_now()
    with conn:
        conn.execute(
            "INSERT INTO devices (id, label, secret, enrolled_at, last_seen) "
            "VALUES (?, ?, ?, ?, NULL)",
            (device_id, cleaned, secret, enrolled_at),
        )
    return Device(id=device_id, label=cleaned, enrolled_at=enrolled_at,
                  last_seen=None), secret


def list_devices(conn) -> list[Device]:
    return [
        Device(id=row["id"], label=row["label"], enrolled_at=row["enrolled_at"],
               last_seen=row["last_seen"])
        for row in conn.execute(
            "SELECT id, label, enrolled_at, last_seen FROM devices "
            "ORDER BY enrolled_at, id")
    ]


def secrets_by_id(conn) -> dict[str, bytes]:
    """Every verifying key, for one pass over the spool."""
    return {row["id"]: bytes(row["secret"])
            for row in conn.execute("SELECT id, secret FROM devices")}


def revoke(conn, device_id: str) -> bool:
    """Forget a browser. Notes it writes from now on will be held for review.

    Not retroactive, and the interface says so: notes it already wrote were
    genuine when they were checked, and are already in the record.
    """
    with conn:
        cursor = conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    return cursor.rowcount > 0


def touch(conn, device_id: str, when: str | None = None) -> None:
    """Record that a device was heard from, so a stale one is visible."""
    with conn:
        conn.execute("UPDATE devices SET last_seen = ? WHERE id = ?",
                     (when or utc_now(), device_id))
