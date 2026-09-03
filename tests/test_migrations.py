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

from core import chain, db, devices, intake, models

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
        if version < 4:
            # The index goes first — SQLite will not drop a column an index
            # still refers to. Neither column is last in its table, which also
            # matters: dropping a trailing column whose definition is preceded
            # by a comment block leaves a dangling comma and SQLite refuses the
            # whole statement.
            conn.execute("DROP INDEX IF EXISTS notes_one_revision")
            conn.execute("ALTER TABLE notes DROP COLUMN supersedes")
            conn.execute("ALTER TABLE note_chain DROP COLUMN canon_version")
            _rehash_under_version_one(conn)
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


def _rehash_under_version_one(conn) -> None:
    """Rewrite the chain the way a database that predates revisions held it.

    Rewinding the schema is not enough on its own. A note written by this build
    was hashed with `supersedes` in the bytes; a real older database has bodies
    hashed without it. Leaving the newer hashes in place would make the test
    assert something no older database ever contained — and would have hidden
    whether a genuinely old record still verifies after coming forward, which is
    the one thing that matters for a database already holding notes.

    The append-only triggers have to come off to do this, which is the point:
    nothing outside a test can rewrite these rows.
    """
    conn.execute("DROP TRIGGER chain_is_append_only_update")
    conn.execute("DROP TRIGGER chain_is_append_only_delete")

    previous = chain.GENESIS_HASH
    rows = conn.execute(
        "SELECT c.seq, n.* FROM note_chain c JOIN notes n ON n.id = c.note_id "
        "ORDER BY c.seq").fetchall()
    for row in rows:
        body = chain.body_hash(
            note_id=int(row["id"]),
            captured_at=row["captured_at"],
            backdated_at=row["backdated_at"],
            source_type=row["source_type"],
            source_trust=row["source_trust"],
            raw_text=row["raw_text"],
            version=1,
        )
        entry = chain.link_hash(previous, body)
        conn.execute(
            "UPDATE note_chain SET body_hash = ?, prev_hash = ?, entry_hash = ? "
            "WHERE seq = ?", (body, previous, entry, int(row["seq"])))
        previous = entry

    conn.executescript("""
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
    """)


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
    (3, "the revision columns"),
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


@pytest.mark.parametrize("version", [1, 2, 3])
def test_the_notes_survive_the_migration(with_a_note, version):
    """The whole point. A migration that loses a note is worse than no tool.

    Including that a note hashed under the *old* serialisation still verifies
    after coming forward — which is what every database already holding notes is
    about to do.
    """
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
