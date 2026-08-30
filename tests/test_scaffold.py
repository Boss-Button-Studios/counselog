"""Phase 0 scaffold checks.

These pin down the environment assumptions the rest of the build rests on. If
one of these fails, stop and fix the environment before writing more code —
every later phase assumes them.
"""

import os
import secrets
import sqlite3
import subprocess
import sys

import pytest
import sqlcipher3

RAW_KEY_PRAGMA = 'PRAGMA key = "x\'{}\'";'


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "t.db")


def _make_db(path: str, dek: bytes, text: str = "hello") -> None:
    con = sqlcipher3.connect(path)
    con.execute(RAW_KEY_PRAGMA.format(dek.hex()))
    con.execute("CREATE TABLE notes (id INTEGER PRIMARY KEY, raw_text TEXT)")
    con.execute("INSERT INTO notes (raw_text) VALUES (?)", (text,))
    con.commit()
    con.close()


def test_sqlcipher_is_v4(db_path):
    """We rely on SQLCipher 4.x page format and PRAGMA semantics."""
    version = sqlcipher3.connect(":memory:").execute("PRAGMA cipher_version").fetchone()[0]
    assert version.startswith("4.")


def test_correct_key_round_trips(db_path):
    dek = secrets.token_bytes(32)
    _make_db(db_path, dek, "Sarah pushed back on the Q3 timeline.")
    con = sqlcipher3.connect(db_path)
    con.execute(RAW_KEY_PRAGMA.format(dek.hex()))
    assert con.execute("SELECT raw_text FROM notes").fetchone()[0].startswith("Sarah")
    con.close()


def test_wrong_key_is_rejected(db_path, hushed_stderr):
    dek = secrets.token_bytes(32)
    _make_db(db_path, dek)
    con = sqlcipher3.connect(db_path)
    with hushed_stderr():
        con.execute(RAW_KEY_PRAGMA.format(secrets.token_bytes(32).hex()))
        with pytest.raises(sqlcipher3.DatabaseError):
            con.execute("SELECT raw_text FROM notes").fetchone()
    con.close()


def test_database_is_opaque_on_disk(db_path):
    """No plaintext, and no SQLite magic header — encrypted from byte 0."""
    secret = "Sarah pushed back on the Q3 timeline."
    _make_db(db_path, secrets.token_bytes(32), secret)
    blob = open(db_path, "rb").read()
    assert secret.encode() not in blob
    assert not blob.startswith(b"SQLite format 3\x00")
    with pytest.raises(sqlite3.DatabaseError):
        sqlite3.connect(db_path).execute("SELECT name FROM sqlite_master").fetchall()


def test_trial_unlock_loop_stays_quiet(db_path, capfd, hushed_stderr):
    """Regression guard for a phase 0 finding.

    Unlock tries each keyring entry until one works, so wrong keys are the
    EXPECTED path, not an error case. SQLCipher's C layer writes decrypt
    failures straight to fd 2, which contextlib.redirect_stderr cannot catch.
    Without the fd-level guard the user sees 'ERROR CORE ... hmac check failed'
    on every single unlock, violating Law 6.
    """
    dek = secrets.token_bytes(32)
    _make_db(db_path, dek)

    def try_key(key: bytes) -> bool:
        con = sqlcipher3.connect(db_path)
        try:
            con.execute(RAW_KEY_PRAGMA.format(key.hex()))
            con.execute("SELECT count(*) FROM sqlite_master").fetchone()
            return True
        except sqlcipher3.DatabaseError:
            return False
        finally:
            con.close()

    with hushed_stderr():
        results = [try_key(secrets.token_bytes(32)) for _ in range(3)] + [try_key(dek)]

    assert results == [False, False, False, True]
    assert "ERROR CORE" not in capfd.readouterr().err


def test_yubikey_extra_is_not_required_on_the_desktop():
    """core/ must import without the [yubikey] extra installed.

    The desktop never has a key. If an eager `import ykman` creeps into core/,
    a desktop install breaks — so this guards the lazy-import convention.
    """
    result = subprocess.run(
        [sys.executable, "-c", "import core, core.crypto, desktop"],
        capture_output=True,
        text=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    assert result.returncode == 0, result.stderr
