"""Phase 6 part 3: reading notes back, and clearing one.

Until this existed the tool could capture a note, protect it and prove it had
not been altered — but not show it to anyone, in either interface. So most of
what matters here is unglamorous: that the right notes appear, that the text
survives being displayed, and that the one destructive control cannot be reached
by accident or by anyone who has not unlocked the notes.
"""

import pytest
from click.testing import CliRunner

from core import db, models
from core.crypto import Keyring, PasswordFactor
from core.display import friendly_time, preview
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


@pytest.fixture
def written(dek):
    """Three notes, one of them backdated."""
    conn = db.connect(notes_db_path(), dek)
    try:
        first = models.add_note(conn, "Ada pushed back on the timeline.")
        second = models.add_note(conn, "Tom asked for Friday off.",
                                 backdated_at="2026-08-01T09:00:00+00:00")
        third = models.add_note(conn, "Two things:\nthe timeline\nthe handover")
        return first, second, third
    finally:
        conn.close()


def sign_in(client):
    page = client.get("/signin", environ_overrides=TAILSCALE)
    import re
    token = re.search(r'name="_csrf" value="([^"]+)"',
                      page.get_data(as_text=True)).group(1)
    return client.post("/signin", data={"passphrase": PASSPHRASE, "_csrf": token},
                       environ_overrides=TAILSCALE)


def token_on(client, path):
    import re
    page = client.get(path, environ_overrides=TAILSCALE)
    return re.search(r'name="_csrf" value="([^"]+)"', page.get_data(as_text=True)).group(1)


def text_of(response) -> str:
    return " ".join(response.get_data(as_text=True).split())


def get(client, path):
    return client.get(path, environ_overrides=TAILSCALE)


# ── the list ─────────────────────────────────────────────────────────────────


def test_every_note_appears(client, written):
    sign_in(client)
    page = text_of(get(client, "/notes"))
    assert "Ada pushed back" in page
    assert "Tom asked for Friday off" in page
    assert "the handover" in page


def test_the_newest_note_is_first(client, written):
    """The note you want is nearly always the recent one."""
    sign_in(client)
    page = text_of(get(client, "/notes"))
    assert page.index("Two things") < page.index("Ada pushed back")


def test_a_backdated_note_is_marked_as_such(client, written):
    """Backdating is the user's claim about the past, not a fact about the note."""
    sign_in(client)
    assert "backdated" in text_of(get(client, "/notes"))


def test_an_empty_record_says_so_rather_than_showing_nothing(client, dek):
    sign_in(client)
    assert "Nothing yet" in text_of(get(client, "/notes"))


# ── one note ─────────────────────────────────────────────────────────────────


def test_a_note_is_shown_in_full_with_its_line_breaks(client, written):
    """The list truncates; the note itself must not."""
    _, _, third = written
    sign_in(client)
    body = get(client, f"/notes/{third.id}").get_data(as_text=True)
    assert "Two things:\nthe timeline\nthe handover" in body


def test_a_note_shows_when_it_was_written_as_well_as_when_it_happened(client, written):
    _, second, _ = written
    sign_in(client)
    page = text_of(get(client, f"/notes/{second.id}"))
    assert "Written" in page
    assert "recorded as happening 2026-08-01" in page


def test_an_untagged_note_says_it_will_not_appear_in_a_report(client, written):
    """Phase 4 learned this the hard way: a note in no bin vanishes silently."""
    first, _, _ = written
    sign_in(client)
    assert "will not appear in a report" in text_of(get(client, f"/notes/{first.id}"))


def test_a_tag_matched_by_name_is_not_dressed_up_as_a_guess(client, written, dek):
    """Exact matches carry no confidence, and the page must not invent one."""
    first, _, _ = written
    conn = db.connect(notes_db_path(), dek)
    try:
        models.add_person(conn, "Ada L.", aliases=["Ada"])
        models.set_tags(conn, first.id, [("self", None), ("person:1", 0.9)])
    finally:
        conn.close()

    sign_in(client)
    page = text_of(get(client, f"/notes/{first.id}"))
    assert "matched by name" in page
    assert "Ada L." in page, "a person bin is shown by name, not as person:1"
    assert "90% sure" in page


def test_a_note_that_does_not_exist_says_so(client, written):
    sign_in(client)
    assert get(client, "/notes/9999").status_code == 404


# ── clearing one ─────────────────────────────────────────────────────────────


def test_clearing_asks_first(client, written):
    """The one irreversible control here, on a device that is easy to mis-tap."""
    first, _, _ = written
    sign_in(client)
    page = text_of(get(client, f"/notes/{first.id}/clear"))
    assert "Clear this note permanently?" in page
    assert "Ada pushed back" in page, "shown while the question is being asked"

    body = get(client, f"/notes/{first.id}").get_data(as_text=True)
    assert "Ada pushed back" in body, "asking must not have cleared it"


def test_clearing_removes_the_text_and_keeps_the_place(client, written, dek):
    first, _, _ = written
    sign_in(client)
    client.post(f"/notes/{first.id}/clear",
                data={"_csrf": token_on(client, f"/notes/{first.id}/clear")},
                environ_overrides=TAILSCALE)

    conn = db.connect(notes_db_path(), dek)
    try:
        cleared = models.get_note(conn, first.id)
        assert cleared.tombstoned and cleared.raw_text == ""
        assert len(models.list_notes(conn)) == 3, "it keeps its place"
    finally:
        conn.close()


def test_the_record_still_verifies_after_clearing(client, written, dek):
    """The whole reason deletion is a tombstone and not a delete."""
    first, _, _ = written
    sign_in(client)
    client.post(f"/notes/{first.id}/clear",
                data={"_csrf": token_on(client, f"/notes/{first.id}/clear")},
                environ_overrides=TAILSCALE)

    conn = db.connect(notes_db_path(), dek)
    try:
        assert models.verify(conn).ok
    finally:
        conn.close()


def test_a_cleared_note_is_shown_as_cleared_not_as_blank(client, written):
    """An empty row reads as a rendering fault. This has to be legible."""
    first, _, _ = written
    sign_in(client)
    client.post(f"/notes/{first.id}/clear",
                data={"_csrf": token_on(client, f"/notes/{first.id}/clear")},
                environ_overrides=TAILSCALE)

    assert "cleared" in text_of(get(client, "/notes")).lower()
    detail = text_of(get(client, f"/notes/{first.id}"))
    assert "The text is gone; its place in the record remains." in detail
    assert "Clear this note" not in detail, "nothing left to clear"


def test_clearing_twice_is_not_an_error(client, written):
    """A double tap, or a reloaded confirmation page."""
    first, _, _ = written
    sign_in(client)
    for _ in range(2):
        response = client.post(
            f"/notes/{first.id}/clear",
            data={"_csrf": token_on(client, f"/notes/{first.id}")},
            environ_overrides=TAILSCALE)
        assert response.status_code == 302


def test_clearing_needs_the_form_token(client, written, dek):
    first, _, _ = written
    sign_in(client)
    assert client.post(f"/notes/{first.id}/clear",
                       environ_overrides=TAILSCALE).status_code == 400

    conn = db.connect(notes_db_path(), dek)
    try:
        assert not models.get_note(conn, first.id).tombstoned
    finally:
        conn.close()


# ── correcting one ───────────────────────────────────────────────────────────


def test_the_note_page_offers_a_correction(client, written):
    first, _, _ = written
    sign_in(client)
    assert "Correct this note" in text_of(get(client, f"/notes/{first.id}"))


def test_the_edit_form_says_what_an_edit_does_not_do(client, written):
    """"Edit" normally means the old version is gone. Here it is not, and
    someone has to be told that before they rely on it."""
    first, _, _ = written
    sign_in(client)
    page = text_of(get(client, f"/notes/{first.id}/edit"))
    assert "does not unsay anything" in page
    assert "clear the note" in page.lower()


def test_saving_a_correction_shows_the_new_text(client, written, dek):
    first, _, _ = written
    sign_in(client)
    response = client.post(f"/notes/{first.id}/edit",
                           data={"text": "Ada pushed back, and was right to.",
                                 "_csrf": token_on(client, f"/notes/{first.id}/edit")},
                           environ_overrides=TAILSCALE, follow_redirects=True)
    assert "Ada pushed back, and was right to." in text_of(response)

    conn = db.connect(notes_db_path(), dek)
    try:
        assert models.verify(conn).ok, "the record still checks out"
        assert models.get_note(conn, first.id).raw_text.endswith("timeline.")
    finally:
        conn.close()


def test_the_list_shows_the_correction_and_marks_it_edited(client, written):
    first, _, _ = written
    sign_in(client)
    client.post(f"/notes/{first.id}/edit",
                data={"text": "Ada pushed back, and was right to.",
                      "_csrf": token_on(client, f"/notes/{first.id}/edit")},
                environ_overrides=TAILSCALE)
    page = text_of(get(client, "/notes"))
    assert "Ada pushed back, and was right to." in page
    assert "edited" in page
    assert page.count("Ada pushed back") == 1, "one row per note, not one per version"


def test_an_earlier_version_is_still_reachable_and_says_it_is_earlier(client, written):
    first, _, _ = written
    sign_in(client)
    client.post(f"/notes/{first.id}/edit",
                data={"text": "Ada pushed back, and was right to.",
                      "_csrf": token_on(client, f"/notes/{first.id}/edit")},
                environ_overrides=TAILSCALE)
    page = text_of(get(client, f"/notes/{first.id}"))
    assert "This is an earlier version" in page
    assert "Ada pushed back on the timeline." in page, "its own text is still there"


def test_an_earlier_version_cannot_be_corrected_again(client, written):
    """Two corrections of one note leave no single answer to what it says now."""
    first, _, _ = written
    sign_in(client)
    client.post(f"/notes/{first.id}/edit",
                data={"text": "first correction",
                      "_csrf": token_on(client, f"/notes/{first.id}/edit")},
                environ_overrides=TAILSCALE)
    assert "Correct this note" not in text_of(get(client, f"/notes/{first.id}"))


def test_a_refused_correction_keeps_the_draft(client, written):
    first, _, _ = written
    sign_in(client)
    response = client.post(f"/notes/{first.id}/edit",
                           data={"text": "Ada pushed back on the timeline.",
                                 "_csrf": token_on(client, f"/notes/{first.id}/edit")},
                           environ_overrides=TAILSCALE)
    assert response.status_code == 400
    assert "same text" in text_of(response)


def test_a_cleared_note_offers_no_correction(client, written):
    first, _, _ = written
    sign_in(client)
    client.post(f"/notes/{first.id}/clear",
                data={"_csrf": token_on(client, f"/notes/{first.id}/clear")},
                environ_overrides=TAILSCALE)
    assert get(client, f"/notes/{first.id}/edit").status_code == 302


def test_correcting_needs_the_form_token(client, written, dek):
    first, _, _ = written
    sign_in(client)
    assert client.post(f"/notes/{first.id}/edit", data={"text": "hijacked"},
                       environ_overrides=TAILSCALE).status_code == 400
    conn = db.connect(notes_db_path(), dek)
    try:
        assert len(models.list_notes(conn, include_replaced=True)) == 3
    finally:
        conn.close()


# ── who may read ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("path", ["/notes", "/notes/1", "/notes/1/clear",
                                  "/notes/1/edit"])
def test_reading_notes_needs_a_session(client, written, path):
    """Reaching the page proves nothing about being allowed to read anything."""
    response = get(client, path)
    assert response.status_code == 302
    assert "/signin" in response.headers["Location"]


def test_note_text_never_reaches_a_locked_browser(client, written):
    for path in ("/notes", "/notes/1"):
        assert b"Ada pushed back" not in get(client, path).data


# ── the shared display helpers ───────────────────────────────────────────────


def test_a_preview_is_one_line(written):
    assert "\n" not in preview("Two things:\nthe timeline\nthe handover")


def test_a_cleared_note_previews_as_cleared_not_as_empty():
    assert preview("") == "(cleared)"


def test_a_time_that_will_not_parse_is_shown_rather_than_hidden():
    """Seeing the odd value is what lets anyone work out why it is odd."""
    assert friendly_time("not a timestamp") == "not a timestamp"
