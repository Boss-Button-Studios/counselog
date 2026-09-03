"""Phase 6 part 3, slice 4: checking the record from the browser.

`models.verify` has existed since phase 2 and was reachable only from the CLI.
The check itself is already well tested; what is tested here is the page — that
it reports a break rather than swallowing it, and that it repeats the limits the
CLI states.

That last part is not decoration. A tool that lets a reassuring result imply
more than it checked is worse than one that checks nothing, because it will be
believed. The chain shows a note has not changed. It does not show the note is
true, and it does not show when the events in it happened.
"""

import re

import pytest
from click.testing import CliRunner

from core import db, models
from core.crypto import Keyring, PasswordFactor
from core.paths import keyring_path, notes_db_path
from laptop.cli import cli
from web.app import create_app

PASSPHRASE = "correct horse battery staple"
TAILSCALE = {"REMOTE_ADDR": "127.0.0.1", "HTTP_TAILSCALE_USER_LOGIN": "you@example.com"}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELOG_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "data"))
    CliRunner().invoke(cli, ["keys", "init", "--factor", "password", "--label", "web"],
                       input=f"{PASSPHRASE}\n{PASSPHRASE}\n", catch_exceptions=False)
    CliRunner().invoke(cli, ["init", "--unlock-with", "password"],
                       input=f"{PASSPHRASE}\n", catch_exceptions=False)
    return tmp_path


@pytest.fixture
def dek(home):
    return Keyring.load(keyring_path()).unlock(PasswordFactor(PASSPHRASE))


@pytest.fixture
def client(home):
    app = create_app()
    app.testing = True
    return app.test_client()


def sign_in(client):
    page = client.get("/signin", environ_overrides=TAILSCALE)
    token = re.search(r'name="_csrf" value="([^"]+)"',
                      page.get_data(as_text=True)).group(1)
    return client.post("/signin", data={"passphrase": PASSPHRASE, "_csrf": token},
                       environ_overrides=TAILSCALE)


def text_of(response) -> str:
    """What a reader sees, with the markup taken out.

    Emphasis lands mid-sentence here — "it does <strong>not</strong> show" — so
    asserting against raw HTML would be asserting about where the tags are
    rather than about what the page says.
    """
    without_tags = re.sub(r"<[^>]+>", " ", response.get_data(as_text=True))
    return " ".join(without_tags.split())


def verify_page(client):
    return text_of(client.get("/verify", environ_overrides=TAILSCALE))


@pytest.fixture
def written(dek):
    conn = db.connect(notes_db_path(), dek)
    try:
        return [models.add_note(conn, "Ada pushed back on the timeline."),
                models.add_note(conn, "Tom asked for Friday off.")]
    finally:
        conn.close()


# ── a clean record ───────────────────────────────────────────────────────────


def test_an_intact_record_is_reported_as_intact(client, written):
    sign_in(client)
    assert "All 2 notes are unaltered since they were written" in verify_page(client)


def test_an_empty_record_says_there_is_nothing_to_check(client, dek):
    """Not "all 0 notes are unaltered", which sounds like a result."""
    sign_in(client)
    page = verify_page(client)
    assert "nothing to check" in page
    assert "unaltered" not in page


def test_the_page_states_what_it_does_not_show(client, written):
    """The reason a green result here is safe to show at all."""
    sign_in(client)
    page = verify_page(client)
    assert "does not show that what they say is true" in page
    assert "does not show exactly when the events in them happened" in page


def test_a_cleared_note_is_reported_as_no_longer_checkable(client, written, dek):
    """Its text was destroyed on purpose, so it cannot be rechecked."""
    conn = db.connect(notes_db_path(), dek)
    try:
        models.tombstone_note(conn, written[0].id)
    finally:
        conn.close()

    sign_in(client)
    page = verify_page(client)
    assert "unaltered" in page, "the rest of the record still checks out"
    assert "text can no longer be checked" in page


# ── a record that has been interfered with ───────────────────────────────────


def test_an_altered_note_is_reported_rather_than_passed_over(client, written, dek):
    conn = db.connect(notes_db_path(), dek)
    try:
        conn.execute("UPDATE notes SET raw_text = ? WHERE id = ?",
                     ("something else entirely", written[0].id))
        conn.commit()
    finally:
        conn.close()

    sign_in(client)
    page = verify_page(client)
    assert "Problems found in 1 place" in page
    assert "text has been changed" in page
    assert "provably as written" in page, "says what has actually been lost"


def test_a_note_that_was_never_recorded_here_is_called_out(client, written, dek):
    """Fabricated notes were the attack phase 2 found while writing its tests.

    Walking the chain alone never visits a row inserted straight into the table,
    so history could be *added to* even though it could not be altered.
    """
    conn = db.connect(notes_db_path(), dek)
    try:
        conn.execute(
            "INSERT INTO notes (captured_at, source_type, source_trust, raw_text, "
            "processed) VALUES ('2026-01-01T00:00:00+00:00', 'text_prompt', "
            "'self_authored', 'planted', 0)")
        conn.commit()
    finally:
        conn.close()

    sign_in(client)
    page = verify_page(client)
    assert "Problems found" in page
    assert "never recorded through Counselog" in page


def test_every_break_is_listed_not_just_the_first(client, written, dek):
    """A reader deserves the shape of the damage, not one line of it."""
    conn = db.connect(notes_db_path(), dek)
    try:
        for note in written:
            conn.execute("UPDATE notes SET raw_text = ? WHERE id = ?",
                         (f"changed {note.id}", note.id))
        conn.commit()
    finally:
        conn.close()

    sign_in(client)
    assert "Problems found in 2 places" in verify_page(client)


# ── the fingerprint ──────────────────────────────────────────────────────────


def test_the_chain_head_is_shown_and_is_the_real_one(client, written, dek):
    """The value worth keeping somewhere other than this machine."""
    conn = db.connect(notes_db_path(), dek)
    try:
        head = models.chain_head(conn)
    finally:
        conn.close()

    sign_in(client)
    assert head.entry_hash in verify_page(client)


def test_the_page_explains_what_keeping_the_fingerprint_is_for(client, written):
    """A rewritten chain verifies clean; only an older copy of this contradicts it."""
    sign_in(client)
    page = verify_page(client)
    assert "writing down somewhere other than this machine" in page
    assert "rewrite of the whole chain is internally consistent" in page


def test_no_fingerprint_is_shown_for_an_empty_record(client, dek):
    sign_in(client)
    assert "fingerprint" not in verify_page(client).lower()


# ── who may check ────────────────────────────────────────────────────────────


def test_checking_the_record_needs_a_session(client, written):
    response = client.get("/verify", environ_overrides=TAILSCALE)
    assert response.status_code == 302
    assert "/signin" in response.headers["Location"]


def test_the_page_agrees_with_the_command_line(client, written, dek):
    """Two interfaces onto one check must not give two different answers."""
    conn = db.connect(notes_db_path(), dek)
    try:
        result = models.verify(conn)
    finally:
        conn.close()

    sign_in(client)
    page = verify_page(client)
    assert result.ok
    assert f"All {result.checked} notes are unaltered" in page
