"""Phase 2: key rotation.

Rotation is the most dangerous thing this tool does. It re-encrypts the database
and rewrites the keyring, and getting only half of that done leaves notes that
open with nothing. These tests exist mostly to prove the failure modes are safe.
"""

import pytest
from click.testing import CliRunner

from core import db, models
from core.crypto import Keyring, PasswordFactor, UnlockFailed
from core.paths import keyring_path, notes_db_path
from laptop.cli import cli

OLD = "old-password"
NEW = "new-password"


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "data"))
    runner = CliRunner()

    def _run(args, stdin=""):
        return runner.invoke(cli, args, input=stdin, catch_exceptions=False)

    return _run


@pytest.fixture
def ready(run):
    run(["keys", "init", "--factor", "password", "--label", "test"], stdin=f"{OLD}\n{OLD}\n")
    run(["init", "--unlock-with", "password"], stdin=f"{OLD}\n")
    run(["note", "-m", "a note worth keeping", "--unlock-with", "password"], stdin=f"{OLD}\n")
    return run


def _dek(password):
    return Keyring.load(keyring_path()).unlock(PasswordFactor(password))


# confirm, unlock, then the re-registration prompt (password twice)
ROTATE_INPUT = f"y\n{OLD}\n{NEW}\n{NEW}\n"


def test_rotation_re_encrypts_and_keeps_notes_readable(ready):
    old_dek = _dek(OLD)
    result = ready(["keys", "rotate", "--unlock-with", "password"], stdin=ROTATE_INPUT)
    assert result.exit_code == 0, result.output
    assert "Rotated" in result.output

    new_dek = _dek(NEW)
    assert new_dek != old_dek

    conn = db.connect(notes_db_path(), new_dek)
    assert len(models.list_notes(conn)) == 1
    assert models.verify(conn).ok  # the chain survives re-encryption
    conn.close()


def test_the_old_key_no_longer_opens_the_database(ready):
    old_dek = _dek(OLD)
    ready(["keys", "rotate", "--unlock-with", "password"], stdin=ROTATE_INPUT)
    with pytest.raises(db.WrongKey):
        db.connect(notes_db_path(), old_dek)


def test_the_old_password_no_longer_unlocks(ready):
    ready(["keys", "rotate", "--unlock-with", "password"], stdin=ROTATE_INPUT)
    with pytest.raises(UnlockFailed):
        _dek(OLD)


def test_rotation_keeps_a_backup_of_the_old_keyring(ready):
    """If rotation half-fails, the user needs a way back."""
    result = ready(["keys", "rotate", "--unlock-with", "password"], stdin=ROTATE_INPUT)
    backups = list(keyring_path().parent.glob("keyring.json.before-rotation-*"))
    assert len(backups) == 1
    assert str(backups[0]) in result.output


def test_rotation_warns_the_backup_is_still_sensitive(ready):
    """That backup can still unwrap the old key. Say so."""
    result = ready(["keys", "rotate", "--unlock-with", "password"], stdin=ROTATE_INPUT)
    assert "delete it once" in result.output


def test_rotation_warns_about_the_desktop_copy(ready):
    """The mirror is encrypted with the same key and will stop opening."""
    result = ready(["keys", "rotate", "--unlock-with", "password"], stdin="n\n")
    assert "desktop" in result.output


def test_declining_changes_nothing(ready):
    old_dek = _dek(OLD)
    result = ready(["keys", "rotate", "--unlock-with", "password"], stdin="n\n")
    assert result.exit_code != 0
    assert _dek(OLD) == old_dek
    db.connect(notes_db_path(), old_dek).close()


def test_a_wrong_password_aborts_before_anything_changes(ready):
    old_dek = _dek(OLD)
    result = ready(["keys", "rotate", "--unlock-with", "password"], stdin="y\nwrong\n")
    assert result.exit_code != 0
    assert _dek(OLD) == old_dek
    db.connect(notes_db_path(), old_dek).close()


def test_rotation_works_before_a_database_exists(run):
    """Rotating a keyring alone must not fall over on a missing database."""
    run(["keys", "init", "--factor", "password", "--label", "test"], stdin=f"{OLD}\n{OLD}\n")
    result = run(["keys", "rotate", "--unlock-with", "password"], stdin=ROTATE_INPUT)
    assert result.exit_code == 0, result.output
    assert _dek(NEW) is not None


def test_every_registered_factor_is_listed_before_confirming(ready):
    """You must know what you need in hand before you start."""
    ready(["keys", "add", "--factor", "password", "--label", "backup",
           "--unlock-with", "password"], stdin=f"{OLD}\nbackup\nbackup\n")
    result = ready(["keys", "rotate", "--unlock-with", "password"], stdin="n\n")
    assert "2 in total" in result.output
    assert "backup" in result.output
