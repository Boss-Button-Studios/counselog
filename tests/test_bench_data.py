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
    assert len(notes) == pmo.ENTRIES
    assert {n.person for n in notes} == {"Maria Chen", "Devon Walker", "Priya Nair",
                                        "Jordan Lee", "Sam Okafor"}


def test_only_the_body_reaches_the_model():
    """Category and sentiment are the generator's labels; showing them would
    hand the model the answer."""
    first = pmo.load()[0]
    assert "Category" not in first.text and "Follow-up" not in first.text
    assert first.category == "Project Update" and first.sentiment == "Positive"


def test_a_note_body_is_sanitized(tmp_path, monkeypatch):
    monkeypatch.setattr(pmo, "ENTRIES", 1)
    monkeypatch.setattr(pmo, "ARGUABLE", {})
    hidden = ENTRY.replace("closed out", "closed​ out")
    assert "​" not in pmo.load(_write(tmp_path, hidden))[0].text


@pytest.mark.parametrize("broken, says", [
    (ENTRY.replace("### 2026-07-02", "### July 2"), "heading"),
    (ENTRY.replace("**Category:** Project Update | ", ""), "Category"),
    (ENTRY.replace("**Follow-up:** Mention it.\n", ""), "without a Follow-up"),
    (ENTRY.replace("**Sentiment:** Positive", "**Sentiment:** Upbeat"), "Category"),
])
def test_a_malformed_entry_stops_the_read(tmp_path, monkeypatch, broken, says):
    monkeypatch.setattr(pmo, "ENTRIES", 1)
    monkeypatch.setattr(pmo, "ARGUABLE", {})
    with pytest.raises(pmo.MalformedTestSet, match=says):
        pmo.load(_write(tmp_path, broken))


def test_a_truncated_copy_is_caught_not_measured(tmp_path, monkeypatch):
    monkeypatch.setattr(pmo, "ENTRIES", 2)
    monkeypatch.setattr(pmo, "ARGUABLE", {})
    with pytest.raises(pmo.MalformedTestSet, match="expected 2 entries, found 1"):
        pmo.load(_write(tmp_path, ENTRY))


def test_a_label_for_a_missing_date_is_refused(tmp_path, monkeypatch):
    """Labels are keyed by date; one that matches nothing is a typo that would
    silently leave its note labelled "neither"."""
    monkeypatch.setattr(pmo, "ENTRIES", 1)
    monkeypatch.setattr(pmo, "ARGUABLE", {"2026-07-03": ({"self"}, "")})
    with pytest.raises(pmo.MalformedTestSet, match="2026-07-03"):
        pmo.load(_write(tmp_path, ENTRY))


def test_sets_combine_without_losing_any():
    assert len(cases("all")) == len(cases("labelled")) + len(cases("pmo"))
    with pytest.raises(ValueError):
        cases("everything")


# ── counting ─────────────────────────────────────────────────────────────────

def test_the_bench_reviews_at_the_threshold_that_ships():
    assert REVIEW_THRESHOLD == DEFAULT_THRESHOLD


def test_review_is_counted_the_way_the_product_reviews(capsys):
    decisions = [
        Decision(1, "team", False, False, True, 0.60),   # wrong yes, caught
        Decision(2, "team", False, False, True, 0.95),   # wrong yes, trusted
        Decision(3, "self", True, False, True, 0.70),    # right yes, held
        Decision(4, "self", True, False, False, 0.99),   # wrong no
        Decision(5, "self", False, False, False, 0.99),  # right no
        Decision(6, "team", True, True, False, 0.99),    # arguable: not scored
    ]
    score("x", decisions, seconds=6.0, notes=6)
    out = capsys.readouterr().out
    assert "2/5 decisions right" in out
    assert "wrong yes: 2, of which review catches 1 and trusts 1" in out
    assert "right yes: 1, of which review holds 1" in out
    assert "wrong no:  1" in out
    assert "arguable note  6" in out
