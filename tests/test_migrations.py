"""Bringing an older database forward.

The database on the laptop holds the only copy of the notes, so a migration is
the one operation that can destroy the whole record if it goes wrong. Up to now
each migration was checked by hand against a database built by the previous
release; that does not survive the release after next, so it is checked here.

Older versions are made by taking a current database apart, which is the only
honest way to do it without keeping a museum of old schemas in the repository.
Each test says which version it is imitating and what that version lacked.
"""

import pytest
import sqlcipher3

from core import db, devices, intake, models

KEY = bytes(range(32))


@pytest.fixture
def path(tmp_path):
    return tmp_path / "notes.db"


def _raw(path):
    """Open without the version check, so a database can be taken apart."""
    conn = sqlcipher3.connect(str(path))
    conn.row_factory = sqlcipher3.Row
    conn.execute(f"""PRAGMA key = "x'{KEY.hex()}'";""")
    return conn


def _rewind_to(path, version: int) -> None:
    """Turn a current database into what `version` would have left behind."""
    conn = _raw(path)
    try:
        if version < 3:
            conn.execute("DROP TABLE spool_quarantine")
        if version < 2:
            conn.execute("DROP TABLE devices")
            conn.execute("DROP TABLE spool_identity")
            conn.execute("ALTER TABLE people DROP COLUMN pronouns")
        conn.execute("UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
                     (str(version),))
        conn.commit()
    finally:
        conn.close()


def _tables(conn) -> set[str]:
    return {row["name"] for row in
            conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _version(conn) -> int:
    return int(conn.execute(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'").fetchone()["value"])


@pytest.fixture
def with_a_note(path):
    """A database with something in it worth not destroying."""
    conn = db.create(path, KEY)
    try:
        models.add_note(conn, "Ada pushed back on the timeline.")
    finally:
        conn.close()
    return path


# ── coming forward ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("version, missing", [
    (1, "pronouns, devices and the spool keypair"),
    (2, "the quarantine"),
])
def test_an_older_database_is_brought_up_to_date_on_connect(with_a_note, version,
                                                            missing):
    _rewind_to(with_a_note, version)
    conn = db.connect(with_a_note, KEY)
    try:
        assert _version(conn) == db.SCHEMA_VERSION, f"came from {version}"
        assert {"devices", "spool_identity", "spool_quarantine"} <= _tables(conn), missing
    finally:
        conn.close()


@pytest.mark.parametrize("version", [1, 2])
def test_the_notes_survive_the_migration(with_a_note, version):
    """The whole point. A migration that loses a note is worse than no tool."""
    _rewind_to(with_a_note, version)
    conn = db.connect(with_a_note, KEY)
    try:
        stored = models.list_notes(conn)
        assert [note.raw_text for note in stored] == ["Ada pushed back on the timeline."]
        assert models.verify(conn).ok, "the chain must still check out afterwards"
    finally:
        conn.close()


def test_the_new_tables_work_after_a_migration_not_just_exist(with_a_note):
    """A table with the wrong shape passes a name check and fails in use."""
    _rewind_to(with_a_note, 1)
    conn = db.connect(with_a_note, KEY)
    try:
        device, secret = devices.enroll(conn, "Phone")
        assert devices.secrets_by_id(conn) == {device.id: secret}
        intake.ensure_identity(conn, with_a_note.parent / "spool.pub")
        assert len(intake.private_key(conn)) == 32
        conn.execute("UPDATE people SET pronouns = 'they/them' WHERE 0")
    finally:
        conn.close()


def test_migrating_twice_is_not_an_error(with_a_note):
    """Opening a database is not a one-time event, and neither is this path."""
    _rewind_to(with_a_note, 1)
    db.connect(with_a_note, KEY).close()
    conn = db.connect(with_a_note, KEY)
    try:
        assert _version(conn) == db.SCHEMA_VERSION
    finally:
        conn.close()


# ── refusing to go backwards ─────────────────────────────────────────────────


def test_a_database_from_a_newer_build_is_refused(with_a_note):
    """Opening it would be a guess about a schema this build has never seen."""
    conn = _raw(with_a_note)
    conn.execute("UPDATE schema_meta SET value = ? WHERE key = 'schema_version'",
                 (str(db.SCHEMA_VERSION + 1),))
    conn.commit()
    conn.close()

    with pytest.raises(db.DatabaseError, match="newer version"):
        db.connect(with_a_note, KEY)


def test_a_database_with_no_version_at_all_is_refused(with_a_note):
    conn = _raw(with_a_note)
    conn.execute("DELETE FROM schema_meta WHERE key = 'schema_version'")
    conn.commit()
    conn.close()

    with pytest.raises(db.DatabaseError, match="missing its schema version"):
        db.connect(with_a_note, KEY)


def test_a_missing_migration_is_reported_rather_than_skipped(with_a_note, monkeypatch):
    """A gap in the table must stop the open, not quietly stamp a new version.

    Stamping without running anything would leave a database claiming a shape it
    does not have, and the failure would surface much later, somewhere else.
    """
    monkeypatch.setitem(db.MIGRATIONS, 3, None)
    _rewind_to(with_a_note, 2)
    with pytest.raises(db.DatabaseError, match="No migration to schema version 3"):
        db.connect(with_a_note, KEY)
