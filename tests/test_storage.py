"""Phase 2: schema rules, sanitization, and the tamper-evidence chain.

The chain tests deliberately attack the database the way someone holding the key
would — direct SQL against the decrypted connection. Anything less would only be
testing that our own writer is self-consistent.
"""

import secrets

import pytest
import sqlcipher3

from core import chain, db, models
from core.sanitize import describe_changes, sanitize


@pytest.fixture
def conn(tmp_path):
    connection = db.create(tmp_path / "notes.db", secrets.token_bytes(32))
    yield connection
    connection.close()


# ── schema rules ─────────────────────────────────────────────────────────────


def test_captured_at_cannot_be_edited(conn):
    """Spec §6: the field that makes the record worth anything in an HR case."""
    note = models.add_note(conn, "something happened")
    with pytest.raises(sqlcipher3.DatabaseError, match="captured_at cannot be changed"):
        conn.execute("UPDATE notes SET captured_at = '1999-01-01T00:00:00+00:00' WHERE id = ?",
                     (note.id,))


def test_editing_other_fields_still_works(conn):
    """The trigger must be narrow — tagging updates `processed` constantly."""
    note = models.add_note(conn, "something happened")
    conn.execute("UPDATE notes SET processed = 1 WHERE id = ?", (note.id,))
    assert models.get_note(conn, note.id).processed


def test_notes_cannot_be_deleted(conn):
    note = models.add_note(conn, "inconvenient truth")
    with pytest.raises(sqlcipher3.DatabaseError, match="cannot be deleted"):
        conn.execute("DELETE FROM notes WHERE id = ?", (note.id,))


def test_chain_is_append_only(conn):
    models.add_note(conn, "one")
    with pytest.raises(sqlcipher3.DatabaseError, match="cannot be edited"):
        conn.execute("UPDATE note_chain SET body_hash = 'x' WHERE seq = 1")
    with pytest.raises(sqlcipher3.DatabaseError, match="cannot be edited"):
        conn.execute("DELETE FROM note_chain WHERE seq = 1")


def test_self_and_team_bins_are_singletons(conn):
    for kind in ("self", "team"):
        with pytest.raises(sqlcipher3.IntegrityError):
            conn.execute("INSERT INTO bins (kind, person_id) VALUES (?, NULL)", (kind,))


def test_a_person_bin_needs_a_person(conn):
    with pytest.raises(sqlcipher3.IntegrityError):
        conn.execute("INSERT INTO bins (kind, person_id) VALUES ('person', NULL)")


def test_a_fixed_bin_cannot_name_a_person(conn):
    person = models.add_person(conn, "Sarah K.")
    with pytest.raises(sqlcipher3.IntegrityError):
        conn.execute("INSERT INTO bins (kind, person_id) VALUES ('self', ?)", (person.id,))


def test_one_bin_per_person(conn):
    person = models.add_person(conn, "Sarah K.")
    with pytest.raises(sqlcipher3.IntegrityError):
        conn.execute("INSERT INTO bins (kind, person_id) VALUES ('person', ?)", (person.id,))


def test_wrong_key_cannot_open(tmp_path):
    path = tmp_path / "n.db"
    db.create(path, secrets.token_bytes(32)).close()
    with pytest.raises(db.WrongKey):
        db.connect(path, secrets.token_bytes(32))


def test_opening_a_missing_database_says_what_to_run(tmp_path):
    with pytest.raises(db.DatabaseError, match="counselog init"):
        db.connect(tmp_path / "nope.db", secrets.token_bytes(32))


def test_rekey_swaps_the_key(tmp_path):
    path = tmp_path / "n.db"
    old, new = secrets.token_bytes(32), secrets.token_bytes(32)
    conn = db.create(path, old)
    models.add_note(conn, "before rotation")
    db.rekey(conn, new)
    conn.close()

    with pytest.raises(db.WrongKey):
        db.connect(path, old)
    reopened = db.connect(path, new)
    assert len(models.list_notes(reopened)) == 1
    reopened.close()


# ── the chain ────────────────────────────────────────────────────────────────


def test_an_intact_history_verifies(conn):
    for i in range(5):
        models.add_note(conn, f"note {i}")
    result = models.verify(conn)
    assert result.ok
    assert result.checked == 5


def test_editing_a_note_body_is_caught(conn):
    """The attack the chain exists for: someone with the key rewrites history."""
    models.add_note(conn, "Sarah handled the escalation well.")
    models.add_note(conn, "second note")
    conn.execute("UPDATE notes SET raw_text = 'Sarah handled the escalation badly.' WHERE id = 1")
    conn.commit()

    result = models.verify(conn)
    assert not result.ok
    assert result.breaks[0].seq == 1
    assert "text has been changed" in result.breaks[0].reason


def test_backdating_a_note_after_the_fact_is_caught(conn):
    """backdated_at is inside the hash, so quietly moving it shows up."""
    models.add_note(conn, "a note")
    conn.execute("UPDATE notes SET backdated_at = '2020-01-01T00:00:00+00:00' WHERE id = 1")
    conn.commit()
    assert not models.verify(conn).ok


def test_a_note_with_no_chain_entry_is_caught(conn):
    """Fabricating a note by writing straight to the table must not verify.

    Walking the chain alone would never visit such a note, so appended
    fabrications would pass silently. Verification cross-checks that every note
    is accounted for by an entry.
    """
    models.add_note(conn, "legitimate")
    conn.execute(
        "INSERT INTO notes (captured_at, backdated_at, source_type, source_trust, "
        "raw_text, processed) VALUES ('2026-08-30T00:00:00+00:00', NULL, 'text_prompt', "
        "'self_authored', 'smuggled in', 0)"
    )
    conn.commit()

    result = models.verify(conn)
    assert not result.ok
    smuggled = [b for b in result.breaks if b.note_id == 2]
    assert smuggled and "not in the chain at all" in smuggled[0].reason


def test_a_tombstoned_note_keeps_the_chain_intact(conn):
    """The reason body and link hashes are separate.

    Clearing a body must not make the whole history look forged — otherwise
    honouring a deletion request would destroy the evidence for everything else.
    """
    models.add_note(conn, "about someone who has left")
    models.add_note(conn, "about someone still here")
    models.tombstone_note(conn, 1)

    result = models.verify(conn)
    assert result.ok
    assert result.tombstoned == 1
    assert models.get_note(conn, 1).raw_text == ""


def test_tombstoning_does_not_hide_tampering_elsewhere(conn):
    models.add_note(conn, "one")
    models.add_note(conn, "two")
    models.tombstone_note(conn, 1)
    conn.execute("UPDATE notes SET raw_text = 'edited' WHERE id = 2")
    conn.commit()

    result = models.verify(conn)
    assert not result.ok
    assert any(b.note_id == 2 for b in result.breaks)


def test_tombstoning_twice_is_refused(conn):
    models.add_note(conn, "one")
    models.tombstone_note(conn, 1)
    with pytest.raises(models.ModelError, match="already cleared"):
        models.tombstone_note(conn, 1)


def test_the_chain_survives_reopening_the_database(tmp_path):
    """Hashes must be stable across processes, not just within one."""
    path, dek = tmp_path / "n.db", secrets.token_bytes(32)
    first = db.create(path, dek)
    models.add_note(first, "written in one session")
    first.close()

    second = db.connect(path, dek)
    models.add_note(second, "written in another")
    assert models.verify(second).ok
    assert models.chain_head(second).seq == 2
    second.close()


def test_chain_links_actually_reference_each_other(conn):
    models.add_note(conn, "one")
    models.add_note(conn, "two")
    first, second = models.chain_entries(conn)
    assert first.prev_hash == chain.GENESIS_HASH
    assert second.prev_hash == first.entry_hash


def test_every_break_is_reported_not_just_the_first(conn):
    for i in range(4):
        models.add_note(conn, f"note {i}")
    conn.execute("UPDATE notes SET raw_text = 'x' WHERE id IN (1, 3)")
    conn.commit()
    assert len({b.note_id for b in models.verify(conn).breaks}) == 2


# ── canonical form ───────────────────────────────────────────────────────────


def test_field_boundaries_are_unambiguous():
    """Length-prefixing stops one note being made to hash like another.

    Without it, fields that run together could be re-split differently and
    collide — the classic concatenation ambiguity.
    """
    a = chain.body_hash(note_id=1, captured_at="2026-01-01", backdated_at=None,
                        source_type="text_prompt", source_trust="self_authored",
                        raw_text="abc")
    b = chain.body_hash(note_id=1, captured_at="2026-01-01ab", backdated_at=None,
                        source_type="text_prompt", source_trust="self_authored",
                        raw_text="c")
    assert a != b


def test_identical_notes_hash_identically():
    fields = dict(note_id=7, captured_at="2026-01-01", backdated_at=None,
                  source_type="text_prompt", source_trust="self_authored", raw_text="hi")
    assert chain.body_hash(**fields) == chain.body_hash(**fields)


# ── sanitization ─────────────────────────────────────────────────────────────


@pytest.mark.parametrize("char, name", [
    ("​", "zero-width space"),
    ("‍", "zero-width joiner"),
    ("﻿", "byte order mark"),
    ("‮", "right-to-left override"),
    ("⁠", "word joiner"),
    ("\x00", "null"),
    ("\x1b", "escape"),
])
def test_invisible_characters_are_stripped(char, name):
    assert sanitize(f"Sarah{char} said yes") == "Sarah said yes", name


def test_newlines_and_tabs_survive():
    """Notes are prose. Losing line breaks would mangle every multi-line note."""
    assert sanitize("line one\nline two\tindented") == "line one\nline two\tindented"


def test_line_endings_are_normalised():
    assert sanitize("a\r\nb") == "a\nb"
    assert sanitize("a\rb") == "a\nb"  # lone CR must not weld the lines together


def test_text_is_nfc_normalised():
    decomposed, composed = "café", "café"
    assert sanitize(decomposed) == composed


def test_sanitize_is_idempotent():
    messy = "Sarah​ said﻿ yes\r\nand‮ no"
    assert sanitize(sanitize(messy)) == sanitize(messy)


def test_stored_text_is_the_sanitized_text(conn):
    """The chain must hash what is stored, not what was typed."""
    note = models.add_note(conn, "Sarah​ said﻿ yes")
    assert note.raw_text == "Sarah said yes"
    assert models.verify(conn).ok


def test_user_is_told_what_changed():
    messy = "a​b"
    assert "1 invisible" in describe_changes(messy, sanitize(messy))
    assert describe_changes("clean", "clean") is None


# ── people ───────────────────────────────────────────────────────────────────


def test_adding_a_person_creates_their_bin(conn):
    person = models.add_person(conn, "Sarah K.", ["Sarah", "SK"])
    assert models.bin_for_person(conn, person.id) > 0


def test_display_name_is_always_an_alias(conn):
    """Matching should not depend on remembering to repeat the name."""
    person = models.add_person(conn, "Sarah K.", ["Sarah"])
    assert "Sarah K." in person.aliases


def test_aliases_are_deduplicated_case_insensitively(conn):
    person = models.add_person(conn, "Sarah K.", ["Sarah", "sarah", "SARAH"])
    assert len([a for a in person.aliases if a.casefold() == "sarah"]) == 1


def test_duplicate_people_are_refused(conn):
    models.add_person(conn, "Sarah K.")
    with pytest.raises(models.ModelError, match="already on the list"):
        models.add_person(conn, "Sarah K.")


def test_people_are_deactivated_not_deleted(conn):
    """Their notes and chain entries must outlive their employment."""
    person = models.add_person(conn, "Sarah K.")
    models.set_person_active(conn, person.id, False)
    assert models.list_people(conn) == []
    assert len(models.list_people(conn, include_inactive=True)) == 1


def test_a_note_needs_text(conn):
    for empty in ("", "   ", "\n"):
        with pytest.raises(models.ModelError, match="needs some text"):
            models.add_note(conn, empty)


def test_notes_are_ordered_by_when_things_happened(conn):
    """Backdated notes belong where the event was, not where it was typed."""
    models.add_note(conn, "typed first, happened later")
    models.add_note(conn, "typed second, happened earlier",
                    backdated_at="2020-01-01T00:00:00+00:00")
    assert [n.id for n in models.list_notes(conn)] == [2, 1]
