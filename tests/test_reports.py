"""Phase 6 part 4: the per-person digest and the recency dashboard.

Two things are being protected here. The first is that a digest is *complete*:
every note sorted to someone appears, in the order things happened, including
the ones nobody has checked and the ones whose text has been cleared. A digest
that quietly drops a note reads as evidence of what was written, and is not.

The second is that it never overstates itself. A note is in a bin because a
person said so, because a name matched exactly, or because the model guessed —
three different qualities of fact, counted separately, so nobody reads a page
of model guesses as a page somebody checked.
"""

from datetime import date, datetime, timezone

import pytest

from core import db, models, reports, tags

KEY = bytes(range(32))


@pytest.fixture
def conn(tmp_path):
    connection = db.create(tmp_path / "notes.db", KEY)
    yield connection
    connection.close()


@pytest.fixture
def ada(conn):
    return models.add_person(conn, "Ada L.", aliases=["Ada"])


def note_about(conn, person, text, *, at=None, confidence=None):
    """A note, sorted to one person the way tagging would sort it."""
    note = models.add_note(conn, text, captured_at=at)
    tags.set_tags(conn, note.id, [(f"person:{person.id}", confidence)])
    return note


# ── tidy: spacing only, and always the same answer ───────────────────────────


def test_trailing_whitespace_and_blank_runs_go():
    assert reports.tidy("one   \n\n\n\ntwo") == "one\n\ntwo"


def test_leading_and_trailing_blank_lines_go():
    assert reports.tidy("\n\n  \nsomething\n\n \n") == "something"


def test_bullets_are_written_one_way():
    """Three days of notes should not read as three different documents."""
    assert reports.tidy("* one\n+ two\n- three") == "- one\n- two\n- three"


def test_indented_bullets_keep_their_indent():
    assert reports.tidy("- one\n  * under it") == "- one\n  - under it"


def test_emphasis_and_arithmetic_are_not_bullets():
    """A marker only counts with a space after it, or *this* becomes a list."""
    assert reports.tidy("*emphasis* matters\n2 + 2 = 4") == "*emphasis* matters\n2 + 2 = 4"


def test_the_words_are_never_touched():
    original = "Ada said the timeline slips.  She wants Friday."
    assert reports.tidy(original) == original


def test_tidy_is_idempotent():
    """Law 7: two readers of one note must not see different text."""
    messy = "\n* one   \n\n\n+ two\n\n"
    once = reports.tidy(messy)
    assert reports.tidy(once) == once


def test_tidy_of_nothing_is_nothing():
    """A cleared note has no text at all, and must not raise on the way in."""
    assert reports.tidy("") == ""


# ── the digest: everything, in the order it happened ─────────────────────────


def test_notes_appear_oldest_first(conn, ada):
    note_about(conn, ada, "second", at="2026-03-02T09:00:00+00:00")
    note_about(conn, ada, "first", at="2026-03-01T09:00:00+00:00")

    digest = reports.digest(conn, ada.id)
    assert [e.text for e in digest.excerpts] == ["first", "second"]


def test_a_backdated_note_sits_where_it_happened_and_says_so(conn, ada):
    note_about(conn, ada, "written today", at="2026-03-10T09:00:00+00:00")
    backdated = models.add_note(conn, "happened in January",
                                captured_at="2026-03-11T09:00:00+00:00",
                                backdated_at="2026-01-04T09:00:00+00:00")
    tags.set_tags(conn, backdated.id, [(f"person:{ada.id}", None)])

    digest = reports.digest(conn, ada.id)
    assert [e.text for e in digest.excerpts] == ["happened in January", "written today"]
    assert digest.excerpts[0].backdated is True
    assert digest.excerpts[1].backdated is False


def test_a_corrected_note_shows_its_new_text_at_its_original_time(conn, ada):
    """Correcting last month's note must not move it to the top of today."""
    from core import revisions

    old = note_about(conn, ada, "Ada asked for Thursday",
                     at="2026-03-01T09:00:00+00:00")
    note_about(conn, ada, "unrelated, later", at="2026-03-05T09:00:00+00:00")
    revisions.revise(conn, old.id, "Ada asked for Friday")

    digest = reports.digest(conn, ada.id)
    assert [e.text for e in digest.excerpts] == ["Ada asked for Friday", "unrelated, later"]
    assert digest.excerpts[0].edited is True


def test_a_replaced_note_does_not_appear_beside_its_correction(conn, ada):
    from core import revisions

    original = note_about(conn, ada, "first attempt")
    revisions.revise(conn, original.id, "second attempt")

    digest = reports.digest(conn, ada.id)
    assert digest.total == 1


def test_a_bin_someone_rejected_is_not_in_their_digest(conn, ada):
    """A person's answer stands. The model may suggest it again; it may not win."""
    note = note_about(conn, ada, "not about Ada at all", confidence=0.4)
    tags.reject_tag(conn, note.id, f"person:{ada.id}")

    assert reports.digest(conn, ada.id).total == 0


def test_a_cleared_note_is_shown_and_marked_rather_than_dropped(conn, ada):
    """Silently omitting it would make the digest look more complete than it is."""
    note = note_about(conn, ada, "something that had to go")
    models.tombstone_note(conn, note.id)

    digest = reports.digest(conn, ada.id)
    assert digest.total == 1
    assert digest.cleared == 1
    assert digest.excerpts[0].cleared is True
    assert digest.excerpts[0].text == ""


def test_notes_about_someone_else_stay_out(conn, ada):
    tom = models.add_person(conn, "Tom R.")
    note_about(conn, ada, "about Ada")
    note_about(conn, tom, "about Tom")

    assert [e.text for e in reports.digest(conn, ada.id).excerpts] == ["about Ada"]


def test_an_unsorted_note_is_in_nobody_s_digest(conn, ada):
    models.add_note(conn, "never tagged")
    assert reports.digest(conn, ada.id).total == 0
    assert reports.unsorted_count(conn) == 1


# ── what the digest stands on ────────────────────────────────────────────────


def test_a_corrected_note_is_not_counted_as_being_in_no_bin(conn, ada):
    """Found by playtesting a real record. A correction queues for sorting again
    *and* carries the original's bins forward, so it is already on the digest.
    Counting it as unsorted told the reader a note they could see was missing."""
    from core import revisions

    original = note_about(conn, ada, "first attempt")
    revisions.revise(conn, original.id, "second attempt")

    assert reports.digest(conn, ada.id).total == 1
    assert reports.unsorted_count(conn) == 0


def test_a_note_a_person_excluded_everywhere_counts_as_being_in_no_bin(conn, ada):
    """A rejection is an answer, not a tag: the note is in no digest."""
    note = note_about(conn, ada, "not about Ada", confidence=0.4)
    tags.reject_tag(conn, note.id, f"person:{ada.id}")

    assert reports.unsorted_count(conn) == 1


def test_the_three_kinds_of_answer_are_counted_apart(conn, ada):
    """Checked, matched by name and guessed are not the same fact."""
    note_about(conn, ada, "name was in the text", confidence=None)
    note_about(conn, ada, "the model thought so", confidence=0.62)
    confirmed = note_about(conn, ada, "you said yes", confidence=0.5)
    tags.confirm_tag(conn, confirmed.id, f"person:{ada.id}")

    digest = reports.digest(conn, ada.id)
    assert (digest.total, digest.matched, digest.guessed, digest.checked) == (3, 1, 1, 1)


def test_an_exact_name_match_does_not_count_as_checked(conn, ada):
    """It is reliable, but nobody read it. Conflating them overstates the page."""
    note_about(conn, ada, "Ada was there", confidence=None)
    digest = reports.digest(conn, ada.id)
    assert digest.matched == 1
    assert digest.checked == 0
    assert digest.excerpts[0].checked is False


def test_a_guess_keeps_the_number_the_model_gave(conn, ada):
    note_about(conn, ada, "maybe about Ada", confidence=0.62)
    excerpt = reports.digest(conn, ada.id).excerpts[0]
    assert excerpt.decided_by == tags.BY_MODEL
    assert excerpt.confidence == pytest.approx(0.62)


# ── the date range ───────────────────────────────────────────────────────────


def test_both_ends_of_the_range_are_whole_days(conn, ada):
    note_about(conn, ada, "just before", at="2026-02-28T23:59:59+00:00")
    note_about(conn, ada, "first moment", at="2026-03-01T00:00:00+00:00")
    note_about(conn, ada, "last moment", at="2026-03-31T23:59:59+00:00")
    note_about(conn, ada, "just after", at="2026-04-01T00:00:00+00:00")

    digest = reports.digest(conn, ada.id, since=date(2026, 3, 1), until=date(2026, 3, 31))
    assert [e.text for e in digest.excerpts] == ["first moment", "last moment"]


def test_one_open_end_still_filters_the_other(conn, ada):
    note_about(conn, ada, "old", at="2026-01-01T09:00:00+00:00")
    note_about(conn, ada, "new", at="2026-06-01T09:00:00+00:00")

    assert [e.text for e in reports.digest(conn, ada.id, since=date(2026, 3, 1)).excerpts] == ["new"]
    assert [e.text for e in reports.digest(conn, ada.id, until=date(2026, 3, 1)).excerpts] == ["old"]


def test_a_backwards_range_is_refused_rather_than_shown_empty(conn, ada):
    """Empty because nothing was written and empty because the range is nonsense
    want very different reactions from the reader."""
    with pytest.raises(reports.ReportError):
        reports.digest(conn, ada.id, since=date(2026, 6, 1), until=date(2026, 1, 1))


def test_an_unknown_person_is_refused(conn):
    with pytest.raises(reports.ReportError):
        reports.digest(conn, 999)


# ── the dashboard ────────────────────────────────────────────────────────────


NOW = datetime(2026, 3, 20, 12, 0, tzinfo=timezone.utc)


def test_people_never_written_about_come_first(conn, ada):
    forgotten = models.add_person(conn, "Zed Q.")
    note_about(conn, ada, "recent", at="2026-03-19T09:00:00+00:00")

    rows = reports.activity(conn, now=NOW)
    assert rows[0].person.id == forgotten.id
    assert rows[0].never is True
    assert rows[0].days_since is None


def test_the_longest_silence_is_nearest_the_top(conn, ada):
    tom = models.add_person(conn, "Tom R.")
    note_about(conn, ada, "yesterday", at="2026-03-19T09:00:00+00:00")
    note_about(conn, tom, "a while ago", at="2026-02-01T09:00:00+00:00")

    rows = reports.activity(conn, now=NOW)
    assert [row.person.id for row in rows] == [tom.id, ada.id]
    assert rows[0].days_since == 47
    assert rows[1].days_since == 1


def test_the_count_is_of_notes_that_stand(conn, ada):
    """Replaced versions are not extra notes about someone."""
    from core import revisions

    first = note_about(conn, ada, "one", at="2026-03-01T09:00:00+00:00")
    note_about(conn, ada, "two", at="2026-03-02T09:00:00+00:00")
    revisions.revise(conn, first.id, "one, corrected")

    row = next(r for r in reports.activity(conn, now=NOW) if r.person.id == ada.id)
    assert row.note_count == 2


def test_someone_who_left_the_team_still_has_a_line(conn, ada):
    """Their notes stay readable, so their count stays true."""
    note_about(conn, ada, "before they left", at="2026-03-01T09:00:00+00:00")
    models.set_person_active(conn, ada.id, False)

    rows = reports.activity(conn, now=NOW)
    assert [row.person.id for row in rows] == [ada.id]
    assert rows[0].person.active is False


def test_recency_follows_a_backdated_note(conn, ada):
    """The gap being measured is since something happened, not since it was typed."""
    backdated = models.add_note(conn, "happened in January",
                                captured_at="2026-03-19T09:00:00+00:00",
                                backdated_at="2026-01-19T09:00:00+00:00")
    tags.set_tags(conn, backdated.id, [(f"person:{ada.id}", None)])

    row = reports.activity(conn, now=NOW)[0]
    assert row.days_since == 60


def test_a_note_dated_in_the_future_reads_as_today(conn, ada):
    """A typo, not a fact about the future. '-30 days ago' helps nobody."""
    ahead = models.add_note(conn, "typo in the date",
                            captured_at="2026-03-19T09:00:00+00:00",
                            backdated_at="2026-04-19T09:00:00+00:00")
    tags.set_tags(conn, ahead.id, [(f"person:{ada.id}", None)])

    assert reports.activity(conn, now=NOW)[0].days_since == 0


def test_a_date_nothing_can_read_gives_no_count_rather_than_a_wrong_one(conn, ada):
    """`backdated_at` is free text at the database level. A gap measured from
    something that is not a date would be a number with no meaning."""
    odd = models.add_note(conn, "dated by hand, badly",
                          captured_at="2026-03-19T09:00:00+00:00",
                          backdated_at="last tuesday")
    tags.set_tags(conn, odd.id, [(f"person:{ada.id}", None)])

    row = reports.activity(conn, now=NOW)[0]
    assert row.note_count == 1
    assert row.days_since is None
    assert row.never is False


def test_an_empty_list_of_people_is_not_an_error(conn):
    assert reports.activity(conn, now=NOW) == []
