"""The safety net, part 5: how far the bins can be trusted.

The figure is only honest if it counts the audit sample and nothing else, so
most of these check what is left out: answers checked for other reasons, notes
with no model answer, notes nobody has answered, replaced notes.
"""

import pytest

from core import checking, db, judgements, models, revisions, tags, trust
from core.judgements import Judgement

KEY = bytes(range(32))


@pytest.fixture
def conn(tmp_path):
    connection = db.create(tmp_path / "notes.db", KEY)
    yield connection
    connection.close()


@pytest.fixture
def everything_drawn(monkeypatch):
    monkeypatch.setattr(checking, "AUDIT_ONE_IN", 1)


@pytest.fixture
def nothing_drawn(monkeypatch):
    monkeypatch.setattr(checking, "AUDIT_ONE_IN", 10**12)


def _checked(conn, model_said, person_said, bin_key="team"):
    """A note the model answered and a person then answered."""
    note = models.add_note(conn, "A note.")
    tags.set_tags(conn, note.id, [(bin_key, 0.95)] if model_said else [])
    judgements.record(conn, note.id, [Judgement(bin_key, model_said, 0.95)],
                      model="m", method="test")
    (tags.confirm_tag if person_said else tags.reject_tag)(conn, note.id, bin_key)
    return note.id


def _team(conn):
    return {f.bin_key: f for f in trust.trust(conn)}["team"]


def test_misses_and_wrong_additions_are_counted_apart(conn, everything_drawn):
    for model, person in [(False, True), (False, True), (True, False),
                          (True, True), (False, False)]:
        _checked(conn, model, person)
    figure = _team(conn)
    assert (figure.checked, figure.missed, figure.added) == (5, 2, 1)


def test_answers_checked_for_other_reasons_are_not_counted(conn, nothing_drawn):
    """They were asked because the model had probably gone wrong; counting
    them would make it look worse than it is."""
    for _ in range(12):
        _checked(conn, False, True)
    assert _team(conn).checked == 0


def test_a_drawn_note_nobody_answered_is_not_counted(conn, everything_drawn):
    note = models.add_note(conn, "A note.")
    tags.set_tags(conn, note.id, [])
    judgements.record(conn, note.id, [Judgement("team", False, 0.9)], model="m", method="t")
    assert _team(conn).checked == 0


def test_a_note_with_no_model_answer_is_not_counted(conn, everything_drawn):
    """A note sorted before answers were kept: a missing tag might be a no, or
    might be nothing, and the figure must not guess."""
    note = models.add_note(conn, "A note.")
    tags.set_tags(conn, note.id, [])
    tags.confirm_tag(conn, note.id, "team")
    assert _team(conn).checked == 0


def test_a_replaced_note_is_not_counted(conn, everything_drawn):
    note = _checked(conn, False, True)
    revisions.revise(conn, note, "A note, corrected.")
    assert _team(conn).checked == 0


def test_the_latest_model_answer_is_the_one_scored(conn, everything_drawn):
    note = _checked(conn, False, True)
    judgements.record(conn, note, [Judgement("team", True, 0.9)], model="m2", method="t")
    assert _team(conn).missed == 0


def test_only_the_most_recent_window_is_counted(conn, everything_drawn):
    for _ in range(trust.WINDOW):
        _checked(conn, False, True)          # older: all missed
    for _ in range(5):
        _checked(conn, True, True)           # newer: all right
    figure = _team(conn)
    assert figure.checked == trust.WINDOW and figure.missed == trust.WINDOW - 5


def test_the_bins_are_measured_separately(conn, everything_drawn):
    _checked(conn, False, True, bin_key="self")
    figures = {f.bin_key: f for f in trust.trust(conn)}
    assert figures["self"].missed == 1 and figures["team"].checked == 0


# ── saying it ────────────────────────────────────────────────────────────────

def test_below_the_minimum_only_progress_is_shown(conn, everything_drawn):
    for _ in range(trust.MIN_SAMPLE - 1):
        _checked(conn, False, True)
    line = trust.describe(_team(conn))
    assert f"{trust.MIN_SAMPLE - 1} of the {trust.MIN_SAMPLE} random checks" in line
    assert "missed" not in line


def test_at_the_minimum_the_figure_is_shown(conn, everything_drawn):
    for _ in range(trust.MIN_SAMPLE - 2):
        _checked(conn, True, True)
    _checked(conn, False, True)
    _checked(conn, True, False)
    assert trust.describe(_team(conn)) == (
        f"Of the last {trust.MIN_SAMPLE} notes checked at random, the sorting "
        "missed 1 that was about the team and filed 1 as about the team that was not.")


def test_a_clean_record_says_so(conn, everything_drawn):
    for _ in range(trust.MIN_SAMPLE):
        _checked(conn, False, False)
    assert "got every one right" in trust.describe(_team(conn))


def test_an_empty_record_has_progress_not_a_figure(conn):
    assert all(not figure.enough for figure in trust.trust(conn))
