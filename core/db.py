"""Encrypted database: connection, schema, and the rules the schema enforces.

Both machines use this. The laptop's copy is the source of truth; the desktop's
mirror holds the same shape so reports can be generated without shipping note
text back and forth (spec §4).

The database is encrypted as a whole by SQLCipher, keyed directly with the
32-byte DEK. There is no second layer of per-column encryption: inside an
already-encrypted file it would add complexity without adding protection
(Law 9). What matters is that the DEK never touches disk, and that decryption
happens only in memory.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path
from typing import Iterator

import sqlcipher3

SCHEMA_VERSION = 3


class DatabaseError(Exception):
    """Something went wrong opening or preparing the database."""


class WrongKey(DatabaseError):
    """The key did not open this database."""


@contextlib.contextmanager
def hushed_stderr() -> Iterator[None]:
    """Silence fd 2 for the duration of a block.

    SQLCipher reports a failed decryption from its C layer straight to fd 2, so
    Python-level redirection cannot catch it. Trying a key that turns out to be
    wrong is a *normal* path — unlocking walks the keyring until something works
    — and without this guard every unlock would print C error spew at a user who
    did nothing wrong (Law 6).
    """
    saved = os.dup(2)
    try:
        with open(os.devnull, "wb") as null:
            os.dup2(null.fileno(), 2)
        yield
    finally:
        os.dup2(saved, 2)
        os.close(saved)


SCHEMA = """
CREATE TABLE schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- People the supervisor writes notes about.
CREATE TABLE people (
    id           INTEGER PRIMARY KEY,
    display_name TEXT NOT NULL UNIQUE,
    aliases      TEXT NOT NULL DEFAULT '[]',   -- JSON array, used for bin resolution
    -- Free text, written the way people write it: 'she/her', 'they/them'.
    -- NULL means never asked; '' means explicitly not stated. The distinction
    -- matters: recording "not stated" for someone nobody ever asked about would
    -- be inventing a considered choice that was never made.
    pronouns     TEXT,
    active       INTEGER NOT NULL DEFAULT 1,   -- soft delete when someone leaves
    created_at   TEXT NOT NULL
);

-- Bins are 'self', 'team', or one per person. Modelling them as a kind plus an
-- optional person reference keeps 'self' and 'team' from needing fake person
-- rows (spec §5).
CREATE TABLE bins (
    id        INTEGER PRIMARY KEY,
    kind      TEXT NOT NULL CHECK (kind IN ('self', 'team', 'person')),
    person_id INTEGER REFERENCES people(id),
    CHECK (
        (kind = 'person' AND person_id IS NOT NULL) OR
        (kind IN ('self', 'team') AND person_id IS NULL)
    )
);
-- 'self' and 'team' are singletons; each person gets at most one bin.
CREATE UNIQUE INDEX bins_singleton ON bins(kind) WHERE kind IN ('self', 'team');
CREATE UNIQUE INDEX bins_person    ON bins(person_id) WHERE person_id IS NOT NULL;

CREATE TABLE notes (
    id            INTEGER PRIMARY KEY,
    captured_at   TEXT NOT NULL,               -- ISO 8601 UTC. Immutable, see trigger.
    backdated_at  TEXT,                        -- when the event happened, if not today
    source_type   TEXT NOT NULL CHECK (source_type IN ('text_prompt', 'file_import')),
    source_trust  TEXT NOT NULL DEFAULT 'self_authored'
                  CHECK (source_trust IN ('self_authored', 'third_party')),
    raw_text      TEXT NOT NULL,
    processed     INTEGER NOT NULL DEFAULT 0,  -- has bin-tagging run
    tombstoned_at TEXT                         -- set when the body is purged
);
CREATE INDEX notes_captured_at ON notes(captured_at);
CREATE INDEX notes_unprocessed ON notes(processed) WHERE processed = 0;

-- captured_at is the one field that must never change: it is what makes the
-- record worth anything in an HR conversation. Corrections go to backdated_at
-- or a new note. Enforced here rather than by convention, because convention is
-- not enforcement (spec §6).
CREATE TRIGGER notes_captured_at_is_immutable
BEFORE UPDATE OF captured_at ON notes
WHEN OLD.captured_at IS NOT NEW.captured_at
BEGIN
    SELECT RAISE(ABORT, 'captured_at cannot be changed. Use backdated_at to record when something happened, or write a new note.');
END;

-- Deleting a note would break the hash chain and destroy the evidence that
-- nothing else was altered. Tombstoning clears the body and keeps the link.
CREATE TRIGGER notes_cannot_be_deleted
BEFORE DELETE ON notes
BEGIN
    SELECT RAISE(ABORT, 'Notes cannot be deleted, because that would break the record. Clear the text with a tombstone instead.');
END;

CREATE TABLE note_tags (
    note_id    INTEGER NOT NULL REFERENCES notes(id),
    bin_id     INTEGER NOT NULL REFERENCES bins(id),
    confidence REAL,                           -- NULL when matched exactly, not inferred
    PRIMARY KEY (note_id, bin_id)
);

-- The tamper-evidence chain. One entry per note, in the order they were
-- written. See core/chain.py for why body and link hashes are separate.
CREATE TABLE note_chain (
    seq        INTEGER PRIMARY KEY,            -- 1-based and contiguous
    note_id    INTEGER NOT NULL UNIQUE REFERENCES notes(id),
    body_hash  TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    hashed_at  TEXT NOT NULL
);

-- Chain entries are append-only. Rewriting history is exactly what the chain
-- exists to detect, so the database refuses to help.
CREATE TRIGGER chain_is_append_only_update
BEFORE UPDATE ON note_chain
BEGIN
    SELECT RAISE(ABORT, 'The note chain cannot be edited.');
END;

CREATE TRIGGER chain_is_append_only_delete
BEFORE DELETE ON note_chain
BEGIN
    SELECT RAISE(ABORT, 'The note chain cannot be edited.');
END;

-- Devices allowed to write notes while the database is locked. Each holds a
-- random key, kept in that browser, used to prove a spooled note came from it.
-- The verifying copy lives here, inside the encrypted database, so only an
-- unlocked server can check it — which is the whole point: the locked server
-- accepts, and the unlocked server judges.
CREATE TABLE devices (
    id          TEXT PRIMARY KEY,
    label       TEXT NOT NULL,
    secret      BLOB NOT NULL,
    enrolled_at TEXT NOT NULL,
    last_seen   TEXT
);

-- The private half of the spool keypair. The public half sits outside the
-- encrypted database, because a locked server must be able to seal a note it
-- cannot reopen.
CREATE TABLE spool_identity (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    private_key BLOB NOT NULL,
    created_at  TEXT NOT NULL
);

-- Spooled entries that failed a check at drain time. Kept rather than merely
-- reported: an entry that fails is evidence someone wrote to the spool who
-- should not have, and evidence that evaporates when the service restarts is
-- not evidence. The text is deliberately not stored — an entry that failed its
-- checks has not earned a place in the record.
CREATE TABLE spool_quarantine (
    seq             INTEGER PRIMARY KEY,   -- position in the spool it came from
    device_id       TEXT NOT NULL,
    reason          TEXT NOT NULL,
    received_at     TEXT NOT NULL,         -- when the locked server took it in
    noticed_at      TEXT NOT NULL,         -- when the unlocked server caught it
    acknowledged_at TEXT                   -- set when the user has seen it
);

-- Signatures over a chain head (phase 7). Stored now so signing needs no
-- migration of a live encrypted database later.
CREATE TABLE signatures (
    id         INTEGER PRIMARY KEY,
    covers_seq INTEGER NOT NULL REFERENCES note_chain(seq),
    algorithm  TEXT NOT NULL,
    pubkey_id  TEXT NOT NULL,
    signature  BLOB NOT NULL,
    signed_at  TEXT NOT NULL
);
"""


# Applied in order to bring an older database up to date. Each entry must be
# safe to run on a database that already holds notes, and must never touch the
# chain — altering a hashed field during a migration would make every note after
# it look tampered with.
MIGRATIONS: dict[int, tuple[str, ...]] = {
    3: (
        """CREATE TABLE spool_quarantine (
               seq             INTEGER PRIMARY KEY,
               device_id       TEXT NOT NULL,
               reason          TEXT NOT NULL,
               received_at     TEXT NOT NULL,
               noticed_at      TEXT NOT NULL,
               acknowledged_at TEXT
           )""",
    ),
    2: (
        "ALTER TABLE people ADD COLUMN pronouns TEXT",
        """CREATE TABLE devices (
               id          TEXT PRIMARY KEY,
               label       TEXT NOT NULL,
               secret      BLOB NOT NULL,
               enrolled_at TEXT NOT NULL,
               last_seen   TEXT
           )""",
        """CREATE TABLE spool_identity (
               id          INTEGER PRIMARY KEY CHECK (id = 1),
               private_key BLOB NOT NULL,
               created_at  TEXT NOT NULL
           )""",
    ),
}


def _migrate(conn: "sqlcipher3.Connection", found: int) -> None:
    """Bring a database forward, one version at a time.

    Runs inside a transaction per version, so a failure leaves the database at
    the last version that fully applied rather than half-way through one.
    """
    for version in range(found + 1, SCHEMA_VERSION + 1):
        statements = MIGRATIONS.get(version)
        if statements is None:
            raise DatabaseError(f"No migration to schema version {version}.")
        with conn:
            for statement in statements:
                conn.execute(statement)
            conn.execute(
                "UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
                (str(version),),
            )


def _key_pragma(dek: bytes) -> str:
    """Raw-key form: the DEK *is* the key, with no passphrase KDF in between.

    The DEK already comes from a wrapped-key envelope, so putting SQLCipher's
    own KDF in front of it would stretch something that is already uniformly
    random — cost without benefit.
    """
    return f"""PRAGMA key = "x'{dek.hex()}'";"""


def _prepare(conn: "sqlcipher3.Connection", dek: bytes) -> None:
    conn.execute(_key_pragma(dek))
    # Enforce the REFERENCES clauses above; SQLite ignores them otherwise.
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL keeps a reader (the phase 6 web UI) from colliding with a writer (the
    # CLI). The -wal file is encrypted too, and is gitignored.
    conn.execute("PRAGMA journal_mode = WAL")


def connect(path: Path | str, dek: bytes) -> "sqlcipher3.Connection":
    """Open an existing encrypted database.

    Raises WrongKey rather than leaking SQLCipher's C-level error text, so
    callers can say something a person can act on.
    """
    path = Path(path)
    if not path.exists():
        raise DatabaseError(f"No database at {path}. Run `counselog init` first.")

    conn = sqlcipher3.connect(str(path))
    conn.row_factory = sqlcipher3.Row
    try:
        with hushed_stderr():
            _prepare(conn, dek)
            conn.execute("SELECT count(*) FROM sqlite_master").fetchone()
    except sqlcipher3.DatabaseError as exc:
        conn.close()
        raise WrongKey("That key does not open this database.") from exc

    _check_version(conn)
    return conn


def create(path: Path | str, dek: bytes) -> "sqlcipher3.Connection":
    """Create and initialise a new encrypted database."""
    path = Path(path)
    if path.exists():
        raise DatabaseError(f"A database already exists at {path}.")

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    conn = sqlcipher3.connect(str(path))
    conn.row_factory = sqlcipher3.Row
    try:
        _prepare(conn, dek)
        conn.executescript(SCHEMA)
        conn.execute(
            "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)",
            (str(SCHEMA_VERSION),),
        )
        # The two fixed bins from spec §5. Person bins are added with people.
        conn.executemany("INSERT INTO bins (kind, person_id) VALUES (?, NULL)",
                         [("self",), ("team",)])
        conn.commit()
    except BaseException:
        conn.close()
        path.unlink(missing_ok=True)  # never leave a half-built database behind
        raise
    os.chmod(path, 0o600)
    return conn


def rekey(conn: "sqlcipher3.Connection", new_dek: bytes) -> None:
    """Re-encrypt the database under a new key, in place.

    The other half of key rotation. The keyring must be re-wrapped in the same
    operation, or the database becomes unopenable — which is why the CLI keeps
    the two together and never exposes this on its own.
    """
    conn.execute(f"""PRAGMA rekey = "x'{new_dek.hex()}'";""")


def _check_version(conn: "sqlcipher3.Connection") -> None:
    row = conn.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'"
    ).fetchone()
    if row is None:
        raise DatabaseError("This database is missing its schema version.")
    found = int(row["value"])
    if found > SCHEMA_VERSION:
        raise DatabaseError(
            f"This database was written by a newer version of Counselog "
            f"(schema {found}, this build understands {SCHEMA_VERSION})."
        )
    if found < SCHEMA_VERSION:
        _migrate(conn, found)
