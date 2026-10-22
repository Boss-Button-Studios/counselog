"""The parts of `bench/` a score depends on: reading the test set, and counting.

The bench scripts themselves talk to a model and stay out of `pytest`. But the
reader that feeds them and the arithmetic that scores them are ordinary logic,
and a quiet bug in either produces a believable wrong number — which is worse
than a crash, because a measurement is the thing nobody re-derives.
"""

from pathlib import Path

import pytest

from bench import pmo
from bench.notes import cases
from bench.scoring import REVIEW_THRESHOLD, Decision, score
from desktop.tagger import DEFAULT_THRESHOLD

ENTRY = """### 2026-07-02 — Maria Chen (Senior PM)
**Category:** Project Update | **Sentiment:** Positive
Maria closed out the phase early.
**Follow-up:** Mention it.

---
"""


def _write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "notes.md"
    path.write_text(text, encoding="utf-8")
    return path


# ── reading the PMO set ──────────────────────────────────────────────────────

def test_the_shipped_set_reads_whole():
    notes = pmo.load()
    assert len(notes) == sum(pmo.SOURCES.values())
    assert {n.person for n in notes} == {"Maria Chen", "Devon Walker", "Priya Nair",
                                        "Jordan Lee", "Sam Okafor", None}


def test_headings_give_the_first_label():
    by_subject = {n.subject: n for n in pmo.load() if not n.arguable}
    assert by_subject[pmo.TEAM_WIDE].expected == {"team"}
    assert by_subject[pmo.SELF_NOTE].expected == {"self"}
    assert by_subject["Maria Chen"].expected == set()


def test_only_the_body_reaches_the_model():
    """Category, sentiment and visibility are the generator's labels; showing
    them would hand the model the answer."""
    notes = pmo.load()
    assert notes[0].category == "Project Update" and notes[0].sentiment == "Positive"
    private = next(n for n in notes if n.private)
    for note in (notes[0], private):
        assert not any(word in note.text for word in ("Category", "Follow-up", "Visibility"))


def test_a_note_body_is_sanitized(tmp_path):
    hidden = ENTRY.replace("closed out", "closed\u200b out")
    assert "\u200b" not in pmo.load_file(_write(tmp_path, hidden), 1)[0].text


@pytest.mark.parametrize("heading, subject", [
    ("### 2026-07-02 — Team-wide", "Team-wide"),
    ("### 2026-07-02 — Self-note", "Self-note"),
])
def test_entries_without_a_person_are_read(tmp_path, heading, subject):
    text = ENTRY.replace("### 2026-07-02 — Maria Chen (Senior PM)", heading)
    note = pmo.load_file(_write(tmp_path, text), 1)[0]
    assert note.subject == subject and note.person is None


def test_a_private_entry_is_marked_and_its_body_kept(tmp_path):
    text = ENTRY.replace("Positive\n", "Positive\n**Visibility:** Private\n")
    note = pmo.load_file(_write(tmp_path, text), 1)[0]
    assert note.private and note.text == "Maria closed out the phase early."


@pytest.mark.parametrize("broken, says", [
    (ENTRY.replace("### 2026-07-02", "### July 2"), "heading"),
    (ENTRY.replace("— Maria Chen (Senior PM)", "— Team wide"), "heading"),
    (ENTRY.replace("**Category:** Project Update | ", ""), "Category"),
    (ENTRY.replace("**Follow-up:** Mention it.\n", ""), "without a Follow-up"),
    (ENTRY.replace("**Sentiment:** Positive", "**Sentiment:** Upbeat"), "Category"),
    (ENTRY.replace("Positive\n", "Positive\n**Visibility:** Team\n"), "Visibility"),
])
def test_a_malformed_entry_stops_the_read(tmp_path, broken, says):
    with pytest.raises(pmo.MalformedTestSet, match=says):
        pmo.load_file(_write(tmp_path, broken), 1)


def test_a_truncated_copy_is_caught_not_measured(tmp_path):
    with pytest.raises(pmo.MalformedTestSet, match="expected 2 entries, found 1"):
        pmo.load_file(_write(tmp_path, ENTRY), 2)


def _one_file_set(tmp_path, monkeypatch, text, arguable):
    _write(tmp_path, text)
    monkeypatch.setattr(pmo, "SOURCES", {"notes.md": text.count("### ")})
    monkeypatch.setattr(pmo, "ARGUABLE", arguable)
    return lambda: pmo.load(tmp_path)


def test_a_label_for_a_missing_entry_is_refused(tmp_path, monkeypatch):
    """Labels are keyed by date and subject; one that matches nothing is a typo
    that would silently leave its note with the heading's label."""
    load = _one_file_set(tmp_path, monkeypatch, ENTRY,
                         {("2026-07-02", "Maria"): ({"self"}, "")})
    with pytest.raises(pmo.MalformedTestSet, match="Maria"):
        load()


def test_same_day_entries_are_told_apart_by_subject(tmp_path, monkeypatch):
    second = ENTRY.replace("Maria Chen (Senior PM)", "Team-wide")
    load = _one_file_set(tmp_path, monkeypatch, ENTRY + second, {})
    assert [n.subject for n in load()] == ["Maria Chen", "Team-wide"]

    load = _one_file_set(tmp_path, monkeypatch, ENTRY + ENTRY, {})
    with pytest.raises(pmo.MalformedTestSet, match="share a date and subject"):
        load()


def test_sets_combine_without_losing_any():
    assert len(cases("all")) == len(cases("labelled")) + len(cases("pmo"))
    with pytest.raises(ValueError):
        cases("everything")


# ── counting ─────────────────────────────────────────────────────────────────

def test_the_bench_reviews_at_the_threshold_that_ships():
    assert REVIEW_THRESHOLD == DEFAULT_THRESHOLD


def test_review_is_counted_the_way_the_product_reviews(capsys):
    decisions = [
        Decision("n1", "team", False, False, True, 0.60),   # wrong yes, caught
        Decision("n2", "team", False, False, True, 0.95),   # wrong yes, trusted
        Decision("n3", "self", True, False, True, 0.70),    # right yes, held
        Decision("n4", "self", True, False, False, 0.99),   # wrong no
        Decision("n5", "self", False, False, False, 0.99),  # right no
        Decision("n6", "team", True, True, False, 0.99),    # arguable: not scored
    ]
    score("x", decisions, seconds=6.0, notes=6)
    out = capsys.readouterr().out
    assert "2/5 decisions right" in out
    assert "wrong yes: 2, of which review catches 1 and trusts 1" in out
    assert "right yes: 1, of which review holds 1" in out
    assert "wrong no:  1" in out
    assert "arguable n6 team" in out
