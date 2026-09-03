"""Phase 6 part 3, slice 5: who decided a note belongs in a bin.

A corrected note is re-sorted from scratch — deliberately, because the machine's
time is what it is there for. That decision is what makes provenance necessary
rather than tidy. Without it every typo fix would discard a judgment a person
made and hand the question straight back to the model, and a rejection would be
recorded nowhere at all, so the same wrong bin could be suggested week after
week.

It is also what lets a report say how much of what it stands on someone actually
checked, which is the difference between a document that can be relied on in a
difficult conversation and one that cannot.
"""

import pytest

from core import db, models, revisions, tags

KEY = bytes(range(32))


@pytest.fixture
def conn(tmp_path):
    connection = db.create(tmp_path / "notes.db", KEY)
    models.add_person(connection, "Ada L.", aliases=["Ada"])
    yield connection
    connection.close()


@pytest.fixture
def note(conn):
    return models.add_note(conn, "Ada pushed back on the timeline.")


def keys_in(conn, note_id):
    return sorted(key for key, _ in tags.tags_for_note(conn, note_id))


def decision_for(conn, note_id, key):
    for decision in tags.tag_decisions(conn, note_id):
        if decision.key == key:
            return decision
    return None


# ── where a tag came from ────────────────────────────────────────────────────


def test_an_exact_name_match_is_recorded_as_such(conn, note):
    """It is reliable, but nobody read it. That is not the same as checked."""
    tags.set_tags(conn, note.id, [("person:1", None)])
    decision = decision_for(conn, note.id, "person:1")
    assert decision.decided_by == tags.BY_ALIAS
    assert not decision.checked


def test_a_guess_is_recorded_as_the_models(conn, note):
    tags.set_tags(conn, note.id, [("team", 0.6)])
    decision = decision_for(conn, note.id, "team")
    assert decision.decided_by == tags.BY_MODEL
    assert not decision.checked


def test_confirming_records_that_a_person_looked(conn, note):
    tags.set_tags(conn, note.id, [("team", 0.6)])
    tags.confirm_tag(conn, note.id, "team")
    decision = decision_for(conn, note.id, "team")
    assert decision.checked and decision.included


def test_a_confirmed_tag_stops_looking_like_a_guess(conn, note):
    """The gap that made every confirmation before this unrecoverable.

    Writing 1.0 left a number where a decision belonged, and a later reader
    could not tell it from a model that happened to sound certain.
    """
    tags.set_tags(conn, note.id, [("team", 0.6)])
    tags.confirm_tag(conn, note.id, "team")
    assert decision_for(conn, note.id, "team").confidence is None


# ── a rejection is an answer, and is remembered ──────────────────────────────


def test_rejecting_keeps_the_note_out_of_the_bin(conn, note):
    tags.set_tags(conn, note.id, [("team", 0.6)])
    tags.reject_tag(conn, note.id, "team")
    assert "team" not in keys_in(conn, note.id)


def test_a_rejected_bin_does_not_list_the_note(conn, note):
    tags.set_tags(conn, note.id, [("team", 0.6)])
    tags.reject_tag(conn, note.id, "team")
    assert tags.notes_for_bin(conn, "team") == []


def test_a_rejection_is_recorded_rather_than_deleted(conn, note):
    """Deleting the row said nothing, so the same suggestion came back."""
    tags.set_tags(conn, note.id, [("team", 0.6)])
    tags.reject_tag(conn, note.id, "team")
    decision = decision_for(conn, note.id, "team")
    assert decision is not None and decision.decision == tags.EXCLUDED
    assert decision.checked


def test_sorting_again_does_not_reinstate_a_rejected_bin(conn, note):
    """The model may suggest it again; it may not overrule the answer it got."""
    tags.set_tags(conn, note.id, [("team", 0.6)])
    tags.reject_tag(conn, note.id, "team")
    tags.set_tags(conn, note.id, [("team", 0.95)])
    assert "team" not in keys_in(conn, note.id)


# ── re-sorting leaves a person's judgment alone ──────────────────────────────


def test_sorting_again_replaces_what_sorting_decided(conn, note):
    """Correcting an alias and running again must converge, not accumulate."""
    tags.set_tags(conn, note.id, [("team", 0.6)])
    tags.set_tags(conn, note.id, [("self", 0.8)])
    assert keys_in(conn, note.id) == ["self"]


def test_sorting_again_does_not_undo_a_confirmation(conn, note):
    tags.set_tags(conn, note.id, [("team", 0.6)])
    tags.confirm_tag(conn, note.id, "team")
    tags.set_tags(conn, note.id, [("self", 0.9)])          # the model changes its mind
    assert "team" in keys_in(conn, note.id)
    assert decision_for(conn, note.id, "team").checked


def test_a_confirmed_tag_does_not_return_to_the_review_queue(conn, note):
    """Otherwise every correction hands back questions already answered."""
    tags.set_tags(conn, note.id, [("team", 0.4)])
    tags.confirm_tag(conn, note.id, "team")
    tags.set_tags(conn, note.id, [("team", 0.4)])
    assert tags.tags_needing_review(conn, 0.7) == []


def test_an_excluded_bin_is_never_offered_for_review(conn, note):
    tags.set_tags(conn, note.id, [("team", 0.4)])
    tags.reject_tag(conn, note.id, "team")
    assert tags.tags_needing_review(conn, 0.7) == []


# ── across a correction ──────────────────────────────────────────────────────


def test_a_correction_inherits_decisions_with_their_provenance(conn, note):
    """Copying a judgment as the model's would let sorting throw it away."""
    tags.set_tags(conn, note.id, [("team", 0.6)])
    tags.confirm_tag(conn, note.id, "team")
    tags.reject_tag(conn, note.id, "self")

    revised = revisions.revise(conn, note.id, "Ada pushed back, and was right to.")
    assert decision_for(conn, revised.id, "team").checked
    assert decision_for(conn, revised.id, "self").decision == tags.EXCLUDED


def test_a_typo_fix_does_not_cost_you_your_answers(conn, note):
    """The whole point of the slice, end to end.

    Correct a note, let sorting disagree with you on both counts, and your
    answers still stand.
    """
    tags.set_tags(conn, note.id, [("person:1", None), ("team", 0.55)])
    tags.confirm_tag(conn, note.id, "team")
    tags.reject_tag(conn, note.id, "self")

    revised = revisions.revise(conn, note.id, "Ada pushed back, and was right to.")
    tags.set_tags(conn, revised.id,
                  [("person:1", None), ("team", 0.3), ("self", 0.9)])

    assert keys_in(conn, revised.id) == ["person:1", "team"]
    assert tags.tags_needing_review(conn, 0.7) == []


def test_a_correction_is_still_queued_for_sorting(conn, note):
    """Carrying decisions forward must not look like the note was processed."""
    tags.set_tags(conn, note.id, [("team", 0.6)])
    revised = revisions.revise(conn, note.id, "Ada pushed back, and was right to.")
    assert [n.id for n in models.unprocessed_notes(conn)] == [revised.id]


# ── what a report will need to say ───────────────────────────────────────────


def test_a_note_can_report_how_much_of_it_was_checked(conn):
    """The sentence a digest has to be able to make about itself."""
    checked = models.add_note(conn, "you looked at this one")
    tags.set_tags(conn, checked.id, [("team", 0.55)])
    tags.confirm_tag(conn, checked.id, "team")

    unchecked = models.add_note(conn, "nobody looked at this one")
    tags.set_tags(conn, unchecked.id, [("team", 1.0)])

    assert any(d.checked for d in tags.tag_decisions(conn, checked.id))
    assert not any(d.checked for d in tags.tag_decisions(conn, unchecked.id))


def test_an_exact_match_is_not_counted_as_checked(conn, note):
    """Reliable is not the same as read. A report should not conflate them."""
    tags.set_tags(conn, note.id, [("person:1", None)])
    assert not any(d.checked for d in tags.tag_decisions(conn, note.id))
