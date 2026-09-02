"""Where Counselog keeps its files.

Both machines use this, so it must not assume the laptop's layout. Override with
COUNSELOG_HOME to keep a test or a second profile out of the real one.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV_HOME = "COUNSELOG_HOME"


def counselog_home() -> Path:
    """The directory holding the keyring and databases.

    Defaults to the XDG data directory. Created owner-only if absent: it sits
    next to encrypted notes, so it should never be world-readable, even though
    the files inside carry their own permissions.
    """
    override = os.environ.get(ENV_HOME)
    if override:
        home = Path(override).expanduser()
    else:
        base = os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share"
        home = Path(base).expanduser() / "counselog"
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    return home


def keyring_path() -> Path:
    return counselog_home() / "keyring.json"


def notes_db_path() -> Path:
    """The laptop's primary database — the source of truth."""
    return counselog_home() / "notes.db"


def mirror_db_path() -> Path:
    """The desktop's mirror, readable only while the laptop lends it the key."""
    return counselog_home() / "mirror.db"


def spool_db_path() -> Path:
    """Notes written while the database was locked, each sealed individually."""
    return counselog_home() / "spool.db"


def spool_public_key_path() -> Path:
    """The public half of the spool keypair.

    Outside the encrypted database on purpose: a locked server must be able to
    seal a note it has no way to reopen. Publishing it costs nothing — it can
    only be used to write.
    """
    return counselog_home() / "spool.pub"
