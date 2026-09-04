"""Phase 6 part 4: the digest and the dashboard, in the browser.

The record could be written to, read back and checked, but never *read out* —
there was no way to see everything written about one person in one place, which
is the whole reason the notes are sorted into bins at all.

What these tests guard is mostly honesty. A digest is a document somebody may
carry into a difficult conversation, so it must not silently drop a note, must
not present a model's guess as a checked fact, and must not show one date range
under the heading of another.
"""

import re

import pytest
from click.testing import CliRunner

from core import db, models, revisions, tags
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


@pytest.fixture
def record(dek):
    """Ada with three notes about her, one of each kind of answer."""
    conn = db.connect(notes_db_path(), dek)
    try:
        ada = models.add_person(conn, "Ada L.", aliases=["Ada"])
        key = f"person:{ada.id}"

        matched = models.add_note(conn, "Ada raised the timeline again.",
                                  captured_at="2026-03-01T09:00:00+00:00")
        tags.set_tags(conn, matched.id, [(key, None)])

        guessed = models.add_note(conn, "The timeline slipped a week.",
                                  captured_at="2026-03-05T09:00:00+00:00")
        tags.set_tags(conn, guessed.id, [(key, 0.62)])

        checked = models.add_note(conn, "Handover went well.",
                                  captured_at="2026-03-09T09:00:00+00:00")
        tags.set_tags(conn, checked.id, [(key, 0.5)])
        tags.confirm_tag(conn, checked.id, key)

        return {"person": ada, "matched": matched, "guessed": guessed,
                "checked": checked}
    finally:
        conn.close()


def sign_in(client):
    page = client.get("/signin", environ_overrides=TAILSCALE)
    token = re.search(r'name="_csrf" value="([^"]+)"',
                      page.get_data(as_text=True)).group(1)
    return client.post("/signin", data={"passphrase": PASSPHRASE, "_csrf": token},
                       environ_overrides=TAILSCALE)


def get(client, path):
    return client.get(path, environ_overrides=TAILSCALE)


def text_of(response) -> str:
    return " ".join(response.get_data(as_text=True).split())


def open_record(dek):
    return db.connect(notes_db_path(), dek)


# ── who may read a report ────────────────────────────────────────────────────


def test_reports_are_behind_the_passphrase(client, record):
    """The pages that gather the most in one place are not the exception."""
    for path in ("/reports", f"/reports/{record['person'].id}"):
        response = get(client, path)
        assert response.status_code == 302
        assert "/signin" in response.headers["Location"]


def test_reports_are_not_reachable_from_off_the_tailnet(client, record):
    sign_in(client)
    assert client.get("/reports", environ_overrides={"REMOTE_ADDR": "127.0.0.1"}
                      ).status_code == 403


# ── the dashboard ────────────────────────────────────────────────────────────


def test_the_dashboard_shows_a_count_and_a_recency(client, record):
    sign_in(client)
    page = text_of(get(client, "/reports"))
    assert "Ada L." in page
    assert "3 notes" in page
    assert "days ago" in page or "today" in page or "yesterday" in page


def test_someone_with_no_notes_is_shown_as_such_rather_than_left_out(client, record, dek):
    """The point of the page is what you have *not* written down."""
    conn = open_record(dek)
    try:
        models.add_person(conn, "Zed Q.")
    finally:
        conn.close()

    sign_in(client)
    page = text_of(get(client, "/reports"))
    assert "Zed Q." in page
    assert "nothing written yet" in page


def test_unsorted_notes_are_declared_on_the_dashboard(client, record, dek):
    """An empty digest must not be readable as 'nothing was ever written'."""
    conn = open_record(dek)
    try:
        models.add_note(conn, "not sorted into anything yet")
    finally:
        conn.close()

    sign_in(client)
    assert "not been sorted into a bin yet" in text_of(get(client, "/reports"))


def test_a_date_the_dashboard_cannot_read_is_shown_as_it_stands(client, record, dek):
    """Seeing the odd value is what lets anyone work out why it is odd."""
    conn = open_record(dek)
    try:
        odd = models.add_note(conn, "dated by hand, badly", backdated_at="last tuesday")
        tags.set_tags(conn, odd.id, [(f"person:{record['person'].id}", None)])
    finally:
        conn.close()

    sign_in(client)
    page = text_of(get(client, "/reports"))
    assert "last tuesday, which is not a date" in page


def test_an_empty_list_of_people_says_where_to_start(client, dek):
    sign_in(client)
    assert "Nobody on the list yet" in text_of(get(client, "/reports"))


# ── the digest ───────────────────────────────────────────────────────────────


def test_every_note_appears_in_full_and_in_order(client, record):
    sign_in(client)
    page = text_of(get(client, f"/reports/{record['person'].id}"))
    assert "Ada raised the timeline again." in page
    assert "The timeline slipped a week." in page
    assert page.index("Ada raised") < page.index("Handover went well")


def test_the_page_says_what_it_stands_on(client, record):
    """One checked, one matched by name, one that is only the model's guess."""
    sign_in(client)
    page = text_of(get(client, f"/reports/{record['person'].id}"))
    assert "1 you checked yourself" in page
    assert "1 matched one of their names exactly" in page
    assert "1 rests on the model's judgment alone" in page


def test_an_unchecked_note_is_marked_where_it_sits(client, record):
    sign_in(client)
    page = text_of(get(client, f"/reports/{record['person'].id}"))
    assert "the model's guess, 62% sure" in page
    assert "you checked this" in page
    assert "matched by name" in page


def test_a_cleared_note_is_shown_as_having_existed(client, record, dek):
    conn = open_record(dek)
    try:
        models.tombstone_note(conn, record["matched"].id)
    finally:
        conn.close()

    sign_in(client)
    page = text_of(get(client, f"/reports/{record['person'].id}"))
    assert "Ada raised the timeline again." not in page
    assert "The text was cleared" in page
    assert "3 notes" in page  # still counted: it happened, and it is not hidden


def test_a_corrected_note_shows_only_what_it_says_now(client, record, dek):
    conn = open_record(dek)
    try:
        revisions.revise(conn, record["matched"].id, "Ada raised the timeline twice.")
    finally:
        conn.close()

    sign_in(client)
    page = text_of(get(client, f"/reports/{record['person'].id}"))
    assert "Ada raised the timeline twice." in page
    assert "Ada raised the timeline again." not in page
    assert "corrected" in page


def test_a_note_a_person_rejected_is_gone_from_the_digest(client, record, dek):
    conn = open_record(dek)
    try:
        tags.reject_tag(conn, record["guessed"].id, f"person:{record['person'].id}")
    finally:
        conn.close()

    sign_in(client)
    page = text_of(get(client, f"/reports/{record['person'].id}"))
    assert "The timeline slipped a week." not in page
    assert "2 notes" in page


def test_a_person_with_nothing_sorted_to_them_yet_is_told_why(client, record, dek):
    conn = open_record(dek)
    try:
        zed = models.add_person(conn, "Zed Q.")
    finally:
        conn.close()

    sign_in(client)
    page = text_of(get(client, f"/reports/{zed.id}"))
    assert "Nothing sorted to Zed Q. yet" in page


def test_an_empty_digest_does_not_head_a_summary_that_is_not_there(client, record, dek):
    """Found by opening a real record where nothing had been sorted yet: the
    heading rendered with nothing under it, announcing counts that did not
    exist."""
    conn = open_record(dek)
    try:
        zed = models.add_person(conn, "Zed Q.")
    finally:
        conn.close()

    sign_in(client)
    page = text_of(get(client, f"/reports/{zed.id}"))
    assert "What this is built on" not in page
    assert "Nothing sorted to Zed Q. yet" in page


def test_an_unknown_person_gets_a_page_not_a_crash(client, record):
    sign_in(client)
    assert get(client, "/reports/999").status_code == 404


# ── the date range ───────────────────────────────────────────────────────────


def test_a_range_narrows_the_digest_at_both_ends(client, record):
    sign_in(client)
    page = text_of(get(client, f"/reports/{record['person'].id}"
                               "?since=2026-03-05&until=2026-03-05"))
    assert "The timeline slipped a week." in page
    assert "Ada raised the timeline again." not in page
    assert "Handover went well." not in page


def test_an_empty_range_in_a_range_says_which_it_is(client, record):
    sign_in(client)
    page = text_of(get(client, f"/reports/{record['person'].id}?since=2026-06-01"))
    assert "in that range" in page


def test_a_date_that_is_not_a_date_shows_no_notes_at_all(client, record):
    """Showing a different range under the heading of the one asked for would be
    worse than an error: it looks fine."""
    sign_in(client)
    response = get(client, f"/reports/{record['person'].id}?since=last+tuesday")
    page = text_of(response)
    assert response.status_code == 400
    assert "year-month-day" in page
    assert "Ada raised the timeline again." not in page


def test_a_date_of_the_right_shape_that_never_happened_is_refused(client, record):
    sign_in(client)
    response = get(client, f"/reports/{record['person'].id}?since=2026-02-31")
    assert response.status_code == 400
    assert "year-month-day" in text_of(response)


def test_a_backwards_range_is_refused_rather_than_shown_empty(client, record):
    sign_in(client)
    response = get(client, f"/reports/{record['person'].id}"
                           "?since=2026-06-01&until=2026-01-01")
    assert response.status_code == 400
    assert "before the start" in text_of(response)


def test_a_refused_range_keeps_what_was_typed(client, record):
    """A form that clears itself while complaining throws away the work."""
    sign_in(client)
    page = get(client, f"/reports/{record['person'].id}?since=2026-13-01").get_data(as_text=True)
    assert 'value="2026-13-01"' in page


def test_the_range_form_is_folded_away_until_it_is_wanted(client, record):
    """Found by looking at the page on a phone: two date fields and a button
    pushed the notes themselves off the bottom of the screen."""
    sign_in(client)
    page = get(client, f"/reports/{record['person'].id}").get_data(as_text=True)
    assert '<details class="range" >' in page or '<details class="range">' in page
    assert "Narrow to a date range" in page


def test_a_range_in_force_is_shown_open_and_named(client, record):
    """Notes missing from a page must never be unexplained."""
    sign_in(client)
    page = get(client, f"/reports/{record['person'].id}"
                       "?since=2026-03-01&until=2026-03-31").get_data(as_text=True)
    assert '<details class="range" open>' in page
    assert "Showing" in page and "2026-03-01" in page and "2026-03-31" in page


def test_a_refused_range_leaves_the_form_open_to_be_corrected(client, record):
    sign_in(client)
    page = get(client, f"/reports/{record['person'].id}?since=nonsense").get_data(as_text=True)
    assert '<details class="range" open>' in page


def test_the_range_survives_in_the_address_so_it_can_be_kept(client, record):
    """A GET form: the digest you are reading has a link of its own."""
    sign_in(client)
    page = get(client, f"/reports/{record['person'].id}").get_data(as_text=True)
    assert 'method="get"' in page


# ── what the page promises ───────────────────────────────────────────────────


def test_the_digest_states_its_own_limits(client, record):
    sign_in(client)
    page = text_of(get(client, f"/reports/{record['person'].id}"))
    assert "what was written down, not what happened" in page
    assert "no model has read them" in page


def test_notes_are_reachable_from_the_digest(client, record):
    """Every claim on the page can be checked against the note itself."""
    sign_in(client)
    page = get(client, f"/reports/{record['person'].id}").get_data(as_text=True)
    assert f'/notes/{record["guessed"].id}' in page
