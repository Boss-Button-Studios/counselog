"""Sort new notes from the browser (web/sorting.py, web/views/sorting.py).

The model is replaced by a stand-in throughout, so these run in milliseconds.
What matters is what the run does around the model: that it files notes the way
`counselog tag` does, that it stops when the key goes, and that it never runs
twice at once.
"""

import threading

import pytest

from core import db, judgements, models, tags
from core.judgements import Judgement
from core.paths import notes_db_path
from desktop import tagger
from web import sorting
from web.sessions import BrowserSessions, NotSignedIn
from tests.test_web_notes import (TAILSCALE, client, dek, get, home, sign_in,  # noqa: F401
                                  text_of, token_on, written)


def _team_only(text, people, **_):
    """A stand-in model that says every note is about the team."""
    return tagger.Sorting(
        tags=[*tagger.match_aliases(text, people),
              tagger.Tag(bin_key="team", confidence=0.9, matched_by="model")],
        judgements=[Judgement("team", True, 0.9), Judgement("self", False, 0.9)])


@pytest.fixture
def model(monkeypatch):
    monkeypatch.setattr(tagger, "sort_note", _team_only)


def _sorter(client):
    return client.application.config["SORTER"]


def _press(client, path="/sort"):
    return client.post(path, data={"_csrf": token_on(client, "/sort")},
                       environ_overrides=TAILSCALE)


def _finish(client):
    _press(client)
    _sorter(client).join(timeout=10)


def _open(dek):
    return db.connect(notes_db_path(), dek)


# ── the run ──────────────────────────────────────────────────────────────────


def test_every_waiting_note_is_sorted(client, written, dek, model):
    sign_in(client)
    _finish(client)
    conn = _open(dek)
    try:
        assert models.unprocessed_notes(conn) == []
        assert all("team" in {key for key, _ in tags.tags_for_note(conn, n.id)}
                   for n in written)
    finally:
        conn.close()
    assert "Sorted all 3 notes" in text_of(get(client, "/sort"))


def test_the_noes_are_kept_too(client, written, dek, model):
    """The same filing as `counselog tag`: every answer, not only the yeses."""
    sign_in(client)
    _finish(client)
    conn = _open(dek)
    try:
        latest = judgements.latest_everywhere(conn)
        assert latest[(written[0].id, "self")].said_yes is False
    finally:
        conn.close()


def test_names_listed_are_matched(client, written, dek, model):
    conn = _open(dek)
    try:
        ada = models.add_person(conn, "Ada Lovelace", aliases=["Ada"])
    finally:
        conn.close()
    sign_in(client)
    _finish(client)
    conn = _open(dek)
    try:
        bins = {key for key, _ in tags.tags_for_note(conn, written[0].id)}
        assert f"person:{ada.id}" in bins
    finally:
        conn.close()


def test_a_model_that_is_not_there_stops_the_run_and_says_why(client, written, dek,
                                                             monkeypatch):
    def unavailable(*_, **__):
        raise tagger.TaggingUnavailable("The model is not running.")
    monkeypatch.setattr(tagger, "sort_note", unavailable)
    sign_in(client)
    _finish(client)
    page = text_of(get(client, "/sort"))
    assert "Sorted 0 of 3. Stopped: The model is not running." in page
    assert "3 notes are waiting to be sorted" in page


def test_an_unexpected_failure_keeps_what_was_done(client, written, dek, monkeypatch):
    calls = []

    def breaks_second_time(text, people, **kwargs):
        calls.append(text)
        if len(calls) == 2:
            raise RuntimeError("something odd, quoting the note")
        return _team_only(text, people)
    monkeypatch.setattr(tagger, "sort_note", breaks_second_time)
    sign_in(client)
    _finish(client)
    page = text_of(get(client, "/sort"))
    assert "Sorted 1 of 3. Stopped by something unexpected" in page
    assert "quoting the note" not in page


def test_a_note_in_no_bin_is_pointed_out(client, written, monkeypatch):
    monkeypatch.setattr(tagger, "sort_note",
                        lambda text, people, **_: tagger.Sorting(tags=[], judgements=[]))
    sign_in(client)
    _finish(client)
    assert "3 ended up in no bin" in text_of(get(client, "/sort"))


# ── stopping ─────────────────────────────────────────────────────────────────


@pytest.fixture
def held_model(monkeypatch):
    """A model that waits to be let go, so a test can act mid-run."""
    entered, release = threading.Event(), threading.Event()

    def waits(text, people, **_):
        entered.set()
        release.wait(10)
        return _team_only(text, people)
    monkeypatch.setattr(tagger, "sort_note", waits)
    return entered, release


def test_stop_ends_the_run_after_the_note_in_hand(client, written, held_model):
    entered, release = held_model
    sign_in(client)
    _press(client)
    assert entered.wait(10)
    assert "Sorting: 0 of 3 done" in text_of(get(client, "/sort"))
    _press(client, "/sort/stop")
    release.set()
    _sorter(client).join(10)
    page = text_of(get(client, "/sort"))
    assert "Sorted 1 of 3. Stopped when asked." in page


def test_lock_ends_the_run_and_drops_the_answer_in_hand(client, written, dek, held_model):
    """Locked while the model was thinking: nothing is written with a key
    nobody is holding any more."""
    entered, release = held_model
    sign_in(client)
    _press(client)
    assert entered.wait(10)
    client.post("/lock", data={"_csrf": token_on(client, "/sort")},
                environ_overrides=TAILSCALE)
    release.set()
    _sorter(client).join(10)
    progress = _sorter(client).progress()
    assert progress.done == 0 and progress.stopped_because == sorting.LOCKED
    conn = _open(dek)
    try:
        assert len(models.unprocessed_notes(conn)) == 3
    finally:
        conn.close()


def test_a_second_press_does_not_start_a_second_run(client, written, held_model):
    entered, release = held_model
    sign_in(client)
    _press(client)
    assert entered.wait(10)
    first = _sorter(client).progress()
    _press(client)
    assert _sorter(client).progress() is first
    release.set()
    _sorter(client).join(10)


def test_the_page_does_not_refresh_itself(client, written, held_model):
    """A page that reloaded on its own would keep the notes unlocked for as
    long as it was left open."""
    entered, release = held_model
    sign_in(client)
    _press(client)
    assert entered.wait(10)
    body = get(client, "/sort").get_data(as_text=True)
    release.set()
    _sorter(client).join(10)
    assert "http-equiv" not in body.lower()


# ── the pages ────────────────────────────────────────────────────────────────


def test_sorting_needs_the_notes_unlocked(client, written):
    assert get(client, "/sort").status_code == 302
    assert client.post("/sort", environ_overrides=TAILSCALE).status_code == 400  # no CSRF


def test_nothing_waiting_says_so_and_offers_no_button(client, dek):
    sign_in(client)
    page = text_of(get(client, "/sort"))
    assert "Every note is sorted" in page and "Sort them" not in page


def test_the_notes_page_says_how_many_are_waiting(client, written):
    sign_in(client)
    page = text_of(get(client, "/notes"))
    assert "3 notes are not sorted yet" in page and "Sort new notes" in page


# ── the lent key ─────────────────────────────────────────────────────────────


KEY = bytes(range(32))


def test_a_lent_key_outlasts_the_idle_timeout_but_not_the_sign_in():
    sessions = BrowserSessions(idle_seconds=0.05, absolute_seconds=0.3)
    sid = sessions.sign_in("you", KEY)
    lent = sessions.lend(sid)
    threading.Event().wait(0.1)
    with pytest.raises(NotSignedIn):
        sessions.key(sid)                # the browser has locked
    assert lent.dek == KEY               # the work carries on
    threading.Event().wait(0.25)
    assert lent.expired                  # but not past the sign-in's end


def test_signing_out_closes_the_lent_key():
    sessions = BrowserSessions()
    sid = sessions.sign_in("you", KEY)
    lent = sessions.lend(sid)
    sessions.sign_out(sid)
    with pytest.raises(Exception):
        lent.dek


def test_lock_closes_every_lent_key():
    sessions = BrowserSessions()
    lent = [sessions.lend(sessions.sign_in("you", KEY)) for _ in range(2)]
    sessions.lock_all()
    for copy in lent:
        with pytest.raises(Exception):
            copy.dek


def test_nothing_is_lent_without_a_session():
    with pytest.raises(NotSignedIn):
        BrowserSessions().lend("no-such-session")
