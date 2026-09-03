"""Phase 6 part 3, slice 3: correcting a note without rewriting the record.

An edit appends. The correction is a new note pointing back at the one it
replaces, so the original keeps its text, its hash and its place in the chain.
Most of these tests are about the seam that creates: the record has to keep
verifying, the old version has to stay provable, and everything that reads notes
has to read the current one.

The last group is why `supersedes` is hashed. It decides which text the record
currently *says*, so leaving it outside the chain would let a note be hidden
behind a fabricated revision with `verify` still reporting clean.
"""

import pytest

from core import chain, db, models, revisions
from core.revisions import RevisionError

KEY = bytes(range(32))


@pytest.fixture
def conn(tmp_path):
    connection = db.create(tmp_path / "notes.db", KEY)
    yield connection
    connection.close()


@pytest.fixture
def note(conn):
    return models.add_note(conn, "Ada pushed back on the timline.")


# ── what an edit does ────────────────────────────────────────────────────────


def test_a_correction_becomes_what_the_note_says(conn, note):
    revised = revisions.revise(conn, note.id, "Ada pushed back on the timeline.")
    assert revised.raw_text == "Ada pushed back on the timeline."
    assert revised.supersedes == note.id


def test_the_original_text_survives_untouched(conn, note):
    """An edit corrects the record. It does not unsay anything."""
    revisions.revise(conn, note.id, "Ada pushed back on the timeline.")
    assert models.get_note(conn, note.id).raw_text == "Ada pushed back on the timline."


def test_the_record_still_verifies_after_an_edit(conn, note):
    revisions.revise(conn, note.id, "Ada pushed back on the timeline.")
    result = models.verify(conn)
    assert result.ok, result.breaks


def test_a_correction_can_itself_be_corrected(conn, note):
    first = revisions.revise(conn, note.id, "Ada pushed back on the timeline.")
    second = revisions.revise(conn, first.id, "Ada pushed back, and was right to.")
    thread = revisions.thread_for(conn, note.id)
    assert [n.id for n in thread.revisions] == [note.id, first.id, second.id]
    assert thread.current.id == second.id
    assert thread.edit_count == 2
    assert models.verify(conn).ok


def test_the_same_note_cannot_be_corrected_twice_into_a_fork(conn, note):
    """Two corrections of one note leave no single answer to what it says."""
    revisions.revise(conn, note.id, "first correction")
    with pytest.raises(RevisionError, match="already been corrected"):
        revisions.revise(conn, note.id, "second correction")


def test_a_correction_keeps_its_own_time(conn):
    """captured_at is when this was written. It is never a convenient fiction."""
    original = models.add_note(conn, "as written",
                               captured_at="2020-01-01T00:00:00+00:00")
    revised = revisions.revise(conn, original.id, "as corrected")
    assert revised.captured_at != original.captured_at


def test_a_correction_inherits_backdating_and_provenance(conn):
    original = models.add_note(conn, "from a file", source_type=models.SOURCE_FILE,
                               source_trust=models.TRUST_THIRD_PARTY,
                               backdated_at="2026-08-01T09:00:00+00:00")
    revised = revisions.revise(conn, original.id, "from a file, corrected")
    assert revised.backdated_at == original.backdated_at
    assert revised.source_type == models.SOURCE_FILE
    assert revised.source_trust == models.TRUST_THIRD_PARTY


# ── what an edit refuses ─────────────────────────────────────────────────────


def test_a_cleared_note_cannot_be_corrected(conn, note):
    """There is no text to correct, and inventing one would be a forgery."""
    models.tombstone_note(conn, note.id)
    with pytest.raises(RevisionError, match="cleared"):
        revisions.revise(conn, note.id, "putting words back")


def test_an_empty_correction_is_refused(conn, note):
    with pytest.raises(RevisionError, match="needs some text"):
        revisions.revise(conn, note.id, "   \n ")


def test_correcting_to_the_same_text_is_refused(conn, note):
    """A revision that changes nothing is noise in a record read under scrutiny."""
    with pytest.raises(RevisionError, match="same text"):
        revisions.revise(conn, note.id, note.raw_text)


# ── what reads notes reads the current one ───────────────────────────────────


def test_the_list_shows_the_correction_not_the_original(conn, note):
    revisions.revise(conn, note.id, "Ada pushed back on the timeline.")
    listed = models.list_notes(conn)
    assert [n.raw_text for n in listed] == ["Ada pushed back on the timeline."]


def test_the_replaced_note_is_still_there_when_asked_for(conn, note):
    revisions.revise(conn, note.id, "corrected")
    assert len(models.list_notes(conn, include_replaced=True)) == 2


def test_a_thread_sits_where_the_original_was_written(conn):
    """Correcting last month's note must not move it to the top of today."""
    older = models.add_note(conn, "older", captured_at="2026-01-01T00:00:00+00:00")
    models.add_note(conn, "newer", captured_at="2026-06-01T00:00:00+00:00")
    revisions.revise(conn, older.id, "older, corrected")

    order = [thread.current.raw_text for thread in revisions.threads(conn)]
    assert order == ["older, corrected", "newer"]


def test_a_correction_stays_in_the_bins_the_original_was_in(conn, note):
    """Otherwise a note vanishes from its reports the moment it is corrected."""
    models.add_person(conn, "Ada L.", aliases=["Ada"])
    models.set_tags(conn, note.id, [("self", None), ("person:1", 0.9)])

    revised = revisions.revise(conn, note.id, "Ada pushed back on the timeline.")
    assert {key for key, _ in models.tags_for_note(conn, revised.id)} == {
        "self", "person:1"}
    assert [n.id for n in models.notes_for_bin(conn, "person:1")] == [revised.id]


def test_a_correction_is_queued_for_tagging_again(conn, note):
    """The text changed, so which bins it belongs in may have changed too."""
    models.set_tags(conn, note.id, [("self", None)])
    revised = revisions.revise(conn, note.id, "actually this was about the team")
    assert [n.id for n in models.unprocessed_notes(conn)] == [revised.id]


def test_a_replaced_note_is_not_sent_to_the_model_again(conn, note):
    revisions.revise(conn, note.id, "corrected")
    assert note.id not in [n.id for n in models.unprocessed_notes(conn)]


# ── why supersedes is hashed ─────────────────────────────────────────────────


def test_pointing_a_note_at_another_to_hide_it_breaks_the_chain(conn):
    """The attack the canon version bump exists to stop.

    Marking a note as replaced hides it from every list and every report. If the
    link were outside the hash, that could be done to a record that still
    verified clean — the tool would be vouching for a history it was no longer
    showing.
    """
    first = models.add_note(conn, "the note to bury")
    second = models.add_note(conn, "an ordinary note")
    assert models.verify(conn).ok

    conn.execute("UPDATE notes SET supersedes = ? WHERE id = ?", (first.id, second.id))
    conn.commit()

    result = models.verify(conn)
    assert not result.ok
    assert any(problem.note_id == second.id for problem in result.breaks)


def test_unlinking_a_correction_also_breaks_the_chain(conn, note):
    """The same move in reverse: bringing a replaced note back as current."""
    revisions.revise(conn, note.id, "corrected")
    conn.execute("UPDATE notes SET supersedes = NULL WHERE supersedes IS NOT NULL")
    conn.commit()
    assert not models.verify(conn).ok


def test_an_entry_records_which_serialisation_it_was_hashed_under(conn, note):
    """Recorded rather than guessed.

    Trying each version until one matched would let an attacker choose the
    serialisation that ignores the field they changed. Storing it removes the
    choice — and the chain's append-only trigger means the stored answer cannot
    be walked back either, so downgrading an entry to the rules that predate a
    field is refused by the database rather than merely detected afterwards.
    """
    row = conn.execute("SELECT canon_version FROM note_chain WHERE note_id = ?",
                       (note.id,)).fetchone()
    assert int(row["canon_version"]) == chain.CANON_VERSION

    with pytest.raises(Exception, match="chain cannot be edited"):
        conn.execute("UPDATE note_chain SET canon_version = 1 WHERE note_id = ?",
                     (note.id,))


def test_the_original_canonical_form_is_unchanged_by_the_new_field(conn):
    """Old chains stay verifiable: v1 bytes are exactly what they always were."""
    v1 = chain.canonical_note(
        note_id=7, captured_at="2026-01-01T00:00:00+00:00", backdated_at=None,
        source_type="text_prompt", source_trust="self_authored", raw_text="hi",
        version=1)
    assert v1.startswith(chain.length_prefixed(b"counselog-note-v1"))
    # v1 ignores the field entirely — it is appended only from v2.
    assert v1 == chain.canonical_note(
        note_id=7, captured_at="2026-01-01T00:00:00+00:00", backdated_at=None,
        source_type="text_prompt", source_trust="self_authored", raw_text="hi",
        supersedes=99, version=1)
