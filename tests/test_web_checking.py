"""The safety net, part 3: "Check the sorting" in the browser.

What matters: the queue reaches the page, each answer is stored as a person's
decision, neither answer is offered as the default, and nothing here can be
reached without unlocking or used to answer about text the record no longer
says.
"""

import re

import pytest

from core import checking, db, judgements, models, revisions, tags
from core.judgements import Judgement
from core.paths import notes_db_path
from tests.test_web_notes import (TAILSCALE, client, dek, get, home,  # noqa: F401
                                  sign_in, text_of, token_on)


@pytest.fixture
def record(dek):
    """Open the record the web pages read, for setting up and checking."""
    def opened():
        return db.connect(notes_db_path(), dek)
    return opened


def _sorted(record, text, tagged=(), said=(("self", False, 0.95), ("team", False, 0.95))):
    conn = record()
    try:
        note = models.add_note(conn, text)
        tags.set_tags(conn, note.id, list(tagged))
        judgements.record(conn, note.id, [Judgement(*a) for a in said],
                          model="m", method="test")
        return note.id
    finally:
        conn.close()


def _answer(client, note_id, bin_key, answer, **extra):
    token = token_on(client, "/check")
    return client.post(f"/check/{note_id}/{bin_key}",
                       data={"answer": answer, "_csrf": token, **extra},
                       environ_overrides=TAILSCALE)


def _decision(record, note_id, key):
    conn = record()
    try:
        return tags.decision_for(conn, note_id, key)
    finally:
        conn.close()


# ── the page ─────────────────────────────────────────────────────────────────

def test_a_note_in_no_bin_is_shown_with_both_questions(client, record):
    _sorted(record, "Quiet day, nothing much.")
    sign_in(client)
    page = text_of(get(client, "/check"))
    assert "Quiet day, nothing much." in page
    assert "in no bin, so it appears in no report" in page
    assert "about you" in page and "team as a whole" in page
    assert "The model said no, 95% sure." in page


def test_neither_answer_is_offered_as_the_default(client, record):
    """A pre-chosen answer gets confirmed by habit, and the checked answers
    would then only measure how often the model agrees with itself."""
    _sorted(record, "Quiet day.")
    sign_in(client)
    html = get(client, "/check").get_data(as_text=True)
    buttons = re.findall(r"<button[^>]*name=\"answer\"[^>]*>", html)
    assert len(buttons) == 4
    for question in ("self", "team"):
        pair = [b for b in buttons if f"hint-{question}" in b]
        assert len({re.sub(r'value="\w+"', "", b) for b in pair}) == 1, \
            "yes and no buttons must differ only in their value"
    assert not any("autofocus" in b or "checked" in b for b in buttons)


def test_every_answer_button_is_labelled_by_its_question(client, record):
    """Guideline 5: a screen reader hears the question, not just 'Yes'."""
    _sorted(record, "Quiet day.")
    sign_in(client)
    html = get(client, "/check").get_data(as_text=True)
    assert html.count("<fieldset>") == 2 and html.count("<legend>") == 2


def test_an_audited_note_says_why_it_is_here(client, record, monkeypatch):
    monkeypatch.setattr(checking, "AUDIT_ONE_IN", 1)
    _sorted(record, "Ada was great.", tagged=[("team", 0.95)],
            said=[("self", False, 0.95), ("team", True, 0.95)])
    sign_in(client)
    page = text_of(get(client, "/check"))
    assert "Picked at random: one note in 1" in page


def test_nothing_to_check_says_so(client, record):
    sign_in(client)
    assert "Nothing to check." in text_of(get(client, "/check"))


# ── answering ────────────────────────────────────────────────────────────────

def test_yes_files_the_note_as_a_persons_decision(client, record):
    note = _sorted(record, "Quiet day.")
    sign_in(client)
    assert _answer(client, note, "team", "yes").status_code == 302
    decision = _decision(record, note, "team")
    assert decision.included and decision.checked


def test_no_is_remembered_rather_than_forgotten(client, record):
    note = _sorted(record, "Quiet day.")
    sign_in(client)
    _answer(client, note, "self", "no")
    decision = _decision(record, note, "self")
    assert not decision.included and decision.checked


def test_answering_both_moves_on_to_the_next_note(client, record):
    first = _sorted(record, "First quiet day.")
    _sorted(record, "Second quiet day.")
    sign_in(client)
    _answer(client, first, "self", "no")
    assert "First quiet day." in text_of(get(client, "/check"))
    _answer(client, first, "team", "no")
    page = text_of(get(client, "/check"))
    assert "Second quiet day." in page and "First quiet day." not in page


@pytest.mark.parametrize("bin_key, answer", [
    ("person:1", "yes"), ("team", "maybe"), ("team", ""), ("self", "YES")])
def test_an_answer_out_of_place_is_refused(client, record, bin_key, answer):
    note = _sorted(record, "Quiet day.")
    sign_in(client)
    assert _answer(client, note, bin_key, answer).status_code in (400, 404)
    assert _decision(record, note, "team") is None
    assert _decision(record, note, "self") is None


def test_a_replaced_note_cannot_be_answered(client, record):
    note = _sorted(record, "Quiet day.")
    conn = record()
    try:
        revisions.revise(conn, note, "Quiet day, mostly.")
    finally:
        conn.close()
    sign_in(client)
    assert _answer(client, note, "team", "yes").status_code == 400
    assert _decision(record, note, "team") is None


def test_a_cleared_or_missing_note_cannot_be_answered(client, record):
    note = _sorted(record, "Quiet day.")
    conn = record()
    try:
        models.tombstone_note(conn, note)
    finally:
        conn.close()
    sign_in(client)
    assert _answer(client, note, "team", "yes").status_code == 400
    assert _answer(client, 9999, "team", "yes").status_code == 400


def test_an_answer_needs_the_form_token(client, record):
    note = _sorted(record, "Quiet day.")
    sign_in(client)
    response = client.post(f"/check/{note}/team", data={"answer": "yes"},
                           environ_overrides=TAILSCALE)
    assert response.status_code == 400
    assert _decision(record, note, "team") is None


# ── passing over ─────────────────────────────────────────────────────────────

def test_not_now_shows_the_next_and_then_says_the_rest_are_waiting(client, record):
    first = _sorted(record, "First quiet day.")
    second = _sorted(record, "Second quiet day.")
    sign_in(client)
    assert "Second quiet day." in text_of(get(client, f"/check?after={first}"))
    page = text_of(get(client, f"/check?after={second}"))
    assert "That was the last one" in page


def test_answering_after_passing_over_keeps_the_place(client, record):
    first = _sorted(record, "First quiet day.")
    second = _sorted(record, "Second quiet day.")
    sign_in(client)
    response = _answer(client, second, "self", "no", after=str(first))
    assert response.headers["Location"].endswith(f"/check?after={first}")


def test_an_unknown_place_starts_from_the_top(client, record):
    _sorted(record, "First quiet day.")
    sign_in(client)
    assert "First quiet day." in text_of(get(client, "/check?after=9999"))


# ── the count on the notes page ──────────────────────────────────────────────

def test_the_notes_page_says_how_many_are_in_no_bin(client, record):
    _sorted(record, "First quiet day.")
    _sorted(record, "Second quiet day.")
    sign_in(client)
    page = text_of(get(client, "/notes"))
    assert "2 notes are in no bin, so they appear in no report." in page


def test_the_count_is_absent_when_every_note_is_in_a_bin(client, record):
    _sorted(record, "The group.", tagged=[("team", 0.95)],
            said=[("self", False, 0.95), ("team", True, 0.95)])
    sign_in(client)
    assert "in no bin" not in text_of(get(client, "/notes"))


# ── who may check ────────────────────────────────────────────────────────────

def test_checking_needs_a_session(client, record):
    note = _sorted(record, "Quiet day.")
    response = get(client, "/check")
    assert response.status_code == 302 and "/signin" in response.headers["Location"]
    assert b"Quiet day" not in response.data
    assert client.post(f"/check/{note}/team", data={"answer": "yes"},
                       environ_overrides=TAILSCALE).status_code in (302, 400)
    assert _decision(record, note, "team") is None


# ── how far to trust the bins (part 5) ───────────────────────────────────────

def test_the_reports_page_shows_progress_towards_a_trust_figure(client, record):
    sign_in(client)
    page = text_of(get(client, "/reports"))
    assert "How far the sorting can be trusted" in page
    assert "Notes about you: 0 of the 10 random checks needed" in page
    assert "Notes about the team: 0 of the 10 random checks needed" in page


def test_the_reports_page_shows_the_figure_once_there_is_one(client, record, monkeypatch):
    monkeypatch.setattr(checking, "AUDIT_ONE_IN", 1)
    for _ in range(10):
        note = _sorted(record, "Quiet day.")
        conn = record()
        try:
            tags.confirm_tag(conn, note, "team")
        finally:
            conn.close()
    sign_in(client)
    assert ("Of the last 10 notes checked at random, the sorting missed 10 that "
            "were about the team.") in text_of(get(client, "/reports"))
