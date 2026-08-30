"""Phase 2: the capture, people, and verify commands.

Driven through the CLI because the risks here are interaction risks: losing a
note to a bad prompt, or being told the record is fine when it is not.
"""

import pytest
from click.testing import CliRunner

from core import db, models
from core.crypto import Keyring, PasswordFactor
from core.paths import keyring_path, notes_db_path
from laptop.cli import cli

PASSWORD = "swordfish"


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "data"))
    runner = CliRunner()

    def _run(args, stdin=""):
        return runner.invoke(cli, args, input=stdin, catch_exceptions=False)

    return _run


@pytest.fixture
def ready(run):
    """A keyring and an empty database, unlocked by password."""
    run(["keys", "init", "--factor", "password", "--label", "test"],
        stdin=f"{PASSWORD}\n{PASSWORD}\n")
    run(["init", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    return run


def _note(run, text, *extra):
    return run(["note", "-m", text, "--unlock-with", "password", *extra],
               stdin=f"{PASSWORD}\n")


def _open_raw():
    """Open the database the way an attacker holding the key would."""
    dek = Keyring.load(keyring_path()).unlock(PasswordFactor(PASSWORD))
    return db.connect(notes_db_path(), dek)


# ── setup ────────────────────────────────────────────────────────────────────


def test_init_creates_the_database(ready):
    assert notes_db_path().exists()


def test_init_refuses_to_overwrite(ready):
    result = ready(["init", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert result.exit_code != 0
    assert "already exists" in result.output


def test_init_needs_a_keyring_first(run):
    result = run(["init"], stdin="")
    assert result.exit_code != 0
    assert "keys init" in result.output


def test_commands_refuse_a_wrong_password(ready):
    result = ready(["note", "-m", "hello", "--unlock-with", "password"], stdin="wrong\n")
    assert result.exit_code != 0
    assert "did not unlock" in result.output


# ── capture ──────────────────────────────────────────────────────────────────


def test_a_note_is_saved_and_timestamped(ready):
    result = _note(ready, "Sarah pushed back on the Q3 timeline.")
    assert result.exit_code == 0
    assert "Saved note 1" in result.output


def test_an_empty_note_is_refused(ready):
    result = _note(ready, "   ")
    assert result.exit_code != 0
    assert "discarded" in result.output


def test_backdating_is_recorded_separately(ready):
    """The claim about the past must not overwrite when it was written."""
    result = _note(ready, "writing up last week's retro", "--backdated", "2026-08-20")
    assert "recorded as happening 2026-08-20" in result.output

    conn = _open_raw()
    note = models.get_note(conn, 1)
    conn.close()
    assert note.backdated_at.startswith("2026-08-20")
    assert not note.captured_at.startswith("2026-08-20")


def test_pasted_invisible_characters_are_removed_and_reported(ready):
    """Silently altering pasted text would be worse than not altering it."""
    result = _note(ready, "Sarah​ said﻿ yes")
    assert "removed 2 invisible" in result.output

    conn = _open_raw()
    assert models.get_note(conn, 1).raw_text == "Sarah said yes"
    conn.close()


def test_import_reads_a_file(ready, tmp_path):
    path = tmp_path / "retro.md"
    path.write_text("# Retro\n\nWent well.", encoding="utf-8")
    result = ready(["import", str(path), "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert result.exit_code == 0
    assert "as note 1" in result.output


def test_import_marks_third_party_documents(ready, tmp_path):
    """Spec §10: know which notes you did not write, before it matters."""
    path = tmp_path / "self-review.md"
    path.write_text("My self review.", encoding="utf-8")
    result = ready(["import", str(path), "--third-party", "--unlock-with", "password"],
                   stdin=f"{PASSWORD}\n")
    assert "written by someone else" in result.output

    conn = _open_raw()
    assert models.get_note(conn, 1).source_trust == models.TRUST_THIRD_PARTY
    conn.close()


def test_import_rejects_a_binary_file(ready, tmp_path):
    path = tmp_path / "photo.png"
    path.write_bytes(b"\x89PNG\r\n\x1a\n\xff\xfe")
    result = ready(["import", str(path), "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert result.exit_code != 0
    assert "not readable as text" in result.output


def test_import_rejects_an_oversized_file(ready, tmp_path):
    path = tmp_path / "dump.txt"
    path.write_text("x" * 1_000_001, encoding="utf-8")
    result = ready(["import", str(path), "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert result.exit_code != 0
    assert "larger than" in result.output


# ── verification ─────────────────────────────────────────────────────────────


def test_verify_passes_on_an_untouched_record(ready):
    for i in range(3):
        _note(ready, f"note {i}")
    result = ready(["verify", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert result.exit_code == 0
    assert "unaltered" in result.output


def test_verify_states_its_own_limits(ready):
    """The tool must not let a clean result imply more than it proves."""
    _note(ready, "a note")
    output = ready(["verify", "--unlock-with", "password"], stdin=f"{PASSWORD}\n").output
    assert "does not show that" in output
    assert "true" in output


def test_verify_catches_an_edited_note(ready):
    _note(ready, "Sarah handled the escalation well.")
    conn = _open_raw()
    conn.execute("UPDATE notes SET raw_text = 'Sarah handled it badly.' WHERE id = 1")
    conn.commit()
    conn.close()

    result = ready(["verify", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert result.exit_code != 0
    assert "text has been changed" in result.output


def test_verify_catches_a_fabricated_note(ready):
    """Appending straight to the table, bypassing the chain entirely."""
    _note(ready, "genuine")
    conn = _open_raw()
    conn.execute(
        "INSERT INTO notes (captured_at, backdated_at, source_type, source_trust, "
        "raw_text, processed) VALUES ('2026-07-01T09:00:00+00:00', NULL, "
        "'text_prompt', 'self_authored', 'fabricated', 0)"
    )
    conn.commit()
    conn.close()

    result = ready(["verify", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert result.exit_code != 0
    assert "not in the chain at all" in result.output


def test_verify_on_an_empty_database(ready):
    result = ready(["verify", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert result.exit_code == 0
    assert "No notes yet" in result.output


# ── forgetting ───────────────────────────────────────────────────────────────


def test_forget_clears_the_text_but_keeps_the_record(ready):
    _note(ready, "about someone who has left")
    _note(ready, "about someone still here")
    result = ready(["forget", "1", "--unlock-with", "password"], stdin=f"{PASSWORD}\ny\n")
    assert result.exit_code == 0

    verified = ready(["verify", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert verified.exit_code == 0
    assert "cleared" in verified.output


def test_forget_shows_the_note_before_destroying_it(ready):
    """An irreversible action must show what it is about to destroy."""
    _note(ready, "the text that is about to vanish")
    result = ready(["forget", "1", "--unlock-with", "password"], stdin=f"{PASSWORD}\nn\n")
    assert "the text that is about to vanish" in result.output
    assert result.exit_code != 0  # declined

    conn = _open_raw()
    assert models.get_note(conn, 1).raw_text != ""
    conn.close()


def test_forget_does_not_launder_a_fabrication(ready):
    """Clearing a smuggled note must not make verification go quiet."""
    _note(ready, "genuine")
    conn = _open_raw()
    conn.execute(
        "INSERT INTO notes (captured_at, backdated_at, source_type, source_trust, "
        "raw_text, processed) VALUES ('2026-07-01T09:00:00+00:00', NULL, "
        "'text_prompt', 'self_authored', 'fabricated', 0)"
    )
    conn.commit()
    conn.close()

    ready(["forget", "2", "--unlock-with", "password"], stdin=f"{PASSWORD}\ny\n")
    result = ready(["verify", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert result.exit_code != 0


# ── people ───────────────────────────────────────────────────────────────────


def test_adding_a_person_lists_their_aliases(ready):
    result = ready(["people", "add", "Sarah K.", "--alias", "Sarah", "--alias", "SK",
                    "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert result.exit_code == 0
    assert "Sarah" in result.output and "SK" in result.output


def test_duplicate_people_are_refused(ready):
    args = ["people", "add", "Sarah K.", "--unlock-with", "password"]
    ready(args, stdin=f"{PASSWORD}\n")
    result = ready(args, stdin=f"{PASSWORD}\n")
    assert result.exit_code != 0
    assert "already on the list" in result.output


def test_removing_a_person_keeps_their_notes(ready):
    ready(["people", "add", "Sarah K.", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    _note(ready, "a note about Sarah")
    result = ready(["people", "remove", "1", "--unlock-with", "password"],
                   stdin=f"{PASSWORD}\ny\n")
    assert "notes are kept" in result.output

    # Check for the absence of a table ROW, not of the string "Sarah" — the
    # empty-list hint uses "Sarah K." as its worked example.
    listed = ready(["people", "list", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert "Nobody added yet" in listed.output
    assert "active" not in listed.output
    with_left = ready(["people", "list", "--all", "--unlock-with", "password"],
                      stdin=f"{PASSWORD}\n")
    assert "left" in with_left.output


def test_people_list_is_helpful_when_empty(ready):
    result = ready(["people", "list", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert "Nobody added yet" in result.output


def test_status_reports_readiness(ready):
    output = ready(["status"]).output
    assert "1 registered key" in output
    assert "present" in output
