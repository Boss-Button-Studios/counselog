"""Keeping what the model said: `core.judgements` and its wire format.

The point of schema 8 is that a no survives. These pin that it is stored as
given, read back in order, never edited, and that what arrives from the desktop
is held to a shape before any of it is stored.
"""

import pytest
import sqlcipher3

from core import db, judgements, models, protocol
from core.judgements import Judgement

KEY = bytes(range(32))


@pytest.fixture
def conn(tmp_path):
    c = db.create(tmp_path / "notes.db", KEY)
    models.add_note(c, "The group is finally talking to each other.")
    yield c
    c.close()


def _ids(conn):
    return models.list_notes(conn)[0].id


# ── storing ──────────────────────────────────────────────────────────────────

def test_a_run_is_stored_as_given(conn):
    note = _ids(conn)
    count = judgements.record(conn, note, [Judgement("self", False, 0.8),
                                           Judgement("team", True, None)],
                              model="gemma4:12b", method="json-note-first-1",
                              judged_at="2026-10-22T10:00:00+00:00")
    assert count == 2
    assert judgements.for_note(conn, note) == [
        judgements.RecordedJudgement(note, "self", False, 0.8, "gemma4:12b",
                                     "json-note-first-1", "2026-10-22T10:00:00+00:00"),
        judgements.RecordedJudgement(note, "team", True, None, "gemma4:12b",
                                     "json-note-first-1", "2026-10-22T10:00:00+00:00"),
    ]


def test_sorting_again_adds_rather_than_replaces(conn):
    """Two runs that disagree are a fact about the model worth keeping."""
    note = _ids(conn)
    judgements.record(conn, note, [Judgement("team", True, 0.9)], model="a", method="m",
                      judged_at="2026-10-01T00:00:00+00:00")
    judgements.record(conn, note, [Judgement("team", False, 0.7)], model="b", method="m",
                      judged_at="2026-10-02T00:00:00+00:00")
    assert [j.said_yes for j in judgements.for_note(conn, note)] == [True, False]
    assert judgements.latest(conn, note)["team"].model == "b"


def test_only_the_bins_the_model_is_asked_about_are_accepted(conn):
    with pytest.raises(ValueError, match="person:1"):
        judgements.record(conn, _ids(conn), [Judgement("person:1", True, 0.9)],
                          model="m", method="m")


def test_a_bad_row_stores_none_of_its_run(conn):
    """All of a run or nothing, so a note never holds half an answer."""
    note = _ids(conn)
    with pytest.raises(sqlcipher3.IntegrityError):
        judgements.record(conn, note, [Judgement("self", True, 0.5),
                                       Judgement("team", True, 1.5)],
                          model="m", method="m")
    assert judgements.for_note(conn, note) == []


def test_answers_cannot_be_edited_or_deleted(conn):
    note = _ids(conn)
    judgements.record(conn, note, [Judgement("self", True, 0.5)], model="m", method="m")
    with pytest.raises(sqlcipher3.IntegrityError, match="cannot be edited"):
        conn.execute("UPDATE model_judgements SET confidence = 0.99")
    with pytest.raises(sqlcipher3.IntegrityError, match="cannot be deleted"):
        conn.execute("DELETE FROM model_judgements")


def test_an_answer_never_changes_a_tag(conn):
    """Recording is evidence, not a decision."""
    from core import tags
    note = _ids(conn)
    judgements.record(conn, note, [Judgement("team", True, 0.9)], model="m", method="m")
    assert tags.tags_for_note(conn, note) == []


# ── from the wire ────────────────────────────────────────────────────────────

def test_answers_from_the_desktop_are_read():
    parsed = protocol.parse_judgements({"3": [
        {"bin": "self", "said_yes": False, "confidence": 0.8},
        {"bin": "team", "said_yes": True, "confidence": None}]})
    assert parsed == {3: [("self", False, 0.8), ("team", True, None)]}


@pytest.mark.parametrize("bad", [
    [],
    {"x": []},
    {"1": "self"},
    {"1": [{"bin": "person:1", "said_yes": True, "confidence": 0.5}]},
    {"1": [{"bin": "self", "said_yes": "yes", "confidence": 0.5}]},
    {"1": [{"bin": "self", "said_yes": True, "confidence": 1.5}]},
    {"1": [{"bin": "self", "said_yes": True, "confidence": True}]},
    {"1": [{"bin": "self", "said_yes": True, "confidence": 0.5},
           {"bin": "self", "said_yes": False, "confidence": 0.5}]},
    {"1": [{"bin": "self", "said_yes": True, "confidence": 0.5}] * 3},
])
def test_malformed_answers_are_refused(bad):
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_judgements(bad)


def test_which_model_and_method_are_read():
    assert protocol.parse_sorting_source(
        {"model": "deepseek-r1:14b", "method": "json-note-first-1"}) == (
        "deepseek-r1:14b", "json-note-first-1")


@pytest.mark.parametrize("source", [
    {"method": "json-note-first-1"},
    {"model": "m", "method": None},
    {"model": "has spaces", "method": "m"},
    {"model": "m", "method": "Upper"},
    {"model": "m" * 200, "method": "m"},
    {"model": "m\n", "method": "m"},
])
def test_an_odd_model_or_method_is_refused(source):
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_sorting_source(source)
