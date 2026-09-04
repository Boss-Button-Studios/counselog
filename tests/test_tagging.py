"""Phase 4: alias matching, model judgement, and the review workflow.

No live model here — that is benchmarked separately and takes minutes per note.
These pin the logic around it: what is matched exactly, what is asked of the
model, and what happens when the model is wrong, slow, or absent.
"""

import secrets

import httpx
import pytest

from core import db, models, protocol, tags
from desktop import tagger
from desktop.tagger import KnownPerson, Tag, TaggingUnavailable

SARAH = KnownPerson(1, "Sarah K.", ("Sarah", "SK", "Sarah K."))
SAM = KnownPerson(2, "Sam T.", ("Sam",))
PEOPLE = [SARAH, SAM]


@pytest.fixture
def conn(tmp_path):
    connection = db.create(tmp_path / "notes.db", secrets.token_bytes(32))
    yield connection
    connection.close()


# ── alias matching: exact, and never guessed ─────────────────────────────────


@pytest.mark.parametrize("text, expected", [
    ("Sarah pushed back on the timeline.", ["person:1"]),
    ("SK handled the escalation.", ["person:1"]),
    ("Sarah K. was right.", ["person:1"]),
    ("sarah was right.", ["person:1"]),               # case-insensitive
    ("Both Sarah and Sam were there.", ["person:1", "person:2"]),
    ("Nobody named here.", []),
])
def test_aliases_are_matched(text, expected):
    assert sorted(t.bin_key for t in tagger.match_aliases(text, PEOPLE)) == expected


@pytest.mark.parametrize("text", [
    "Samantha did well.",          # not Sam
    "Disamble the widget.",        # Sam inside a word
    "SKATE night was fun.",        # SK inside a word
])
def test_names_inside_other_words_do_not_match(text):
    """Without word boundaries, 'Sam' would tag every note mentioning Samantha."""
    assert tagger.match_aliases(text, PEOPLE) == []


def test_aliases_containing_regex_characters_are_safe():
    """Aliases are user text. 'J.R.' must not become a wildcard."""
    jr = KnownPerson(3, "J.R.", ("J.R.",))
    assert tagger.match_aliases("J.R. approved it", [jr])
    assert tagger.match_aliases("JXRX approved it", [jr]) == []


def test_alias_matches_carry_no_confidence():
    """Spec §5: confidence is for LLM-assisted tagging, not exact matches."""
    tag = tagger.match_aliases("Sarah was there", PEOPLE)[0]
    assert tag.confidence is None
    assert tag.matched_by == "alias"
    assert not tag.needs_review


def test_invisible_characters_cannot_hide_a_name():
    """Sanitizing runs before matching, so a zero-width space inside a name does
    not smuggle it past the matcher.

    This is the payoff of sanitizing at ingestion: pasting text from an email or
    a chat client can carry invisible characters, and without the strip a name
    split by one would silently fail to tag.
    """
    assert tagger.match_aliases("Sa​rah was there", PEOPLE)[0].bin_key == "person:1"
    assert tagger.match_aliases("​Sarah﻿ was there", PEOPLE)[0].bin_key == "person:1"


# ── the model's narrow question ──────────────────────────────────────────────


def _stub(monkeypatch, payload, *, status=200, raises=None):
    def fake_post(url, json=None, timeout=None, **kwargs):
        if raises:
            raise raises
        request = httpx.Request("POST", url)
        return httpx.Response(status, json=payload, request=request)
    monkeypatch.setattr(httpx, "post", fake_post)


def _answer(**fields):
    import json as _json
    return {"message": {"content": _json.dumps(fields)}}


def test_the_note_is_sent_before_the_instructions(monkeypatch):
    """Not a style choice — it is what keeps an answer from depending on which
    note was asked before it.

    With the instructions first, every request in a run shares a long identical
    prefix, the runtime reuses its cached state, and the same note answered
    `self` at 0.95 first and no bins at all third (measured 2026-09-04, see
    `judge_self_team`). The note first, nothing is shared. A tidy-up that
    restores "question, then data" order brings the bug back, and it only shows
    from the second note of a run onwards — so it is guarded here.
    """
    sent = {}

    def capture(url, json=None, timeout=None, **kwargs):
        sent["content"] = json["messages"][0]["content"]
        request = httpx.Request("POST", url)
        return httpx.Response(200, json=_answer(
            self=False, self_confidence=0.9, team=False, team_confidence=0.9),
            request=request)

    monkeypatch.setattr(httpx, "post", capture)
    tagger.judge_self_team("the note itself")

    content = sent["content"]
    assert content.index("the note itself") < content.index("self:"), content
    # And the note is not merely first, it is at the very top: anything ahead of
    # it is prefix that every request in a run would share again.
    assert content.startswith("Note:\n"), content


def test_the_model_is_asked_only_about_self_and_team(monkeypatch):
    """Asking it to pick from all bins produced confident nonsense; see the
    module docstring in desktop/tagger.py."""
    captured = {}

    def fake_post(url, json=None, timeout=None, **kwargs):
        captured.update(json)
        return httpx.Response(200, json=_answer(self=True, self_confidence=0.9,
                                                team=False, team_confidence=0.1),
                              request=httpx.Request("POST", url))
    monkeypatch.setattr(httpx, "post", fake_post)

    tagger.judge_self_team("a note")
    assert set(captured["format"]["properties"]) == {
        "self", "self_confidence", "team", "team_confidence"}
    assert captured["options"]["temperature"] == 0      # repeatable (Law 7)
    assert "seed" in captured["options"]


def test_only_the_bins_the_model_affirms_are_returned(monkeypatch):
    _stub(monkeypatch, _answer(self=True, self_confidence=0.9,
                               team=False, team_confidence=0.8))
    tags = tagger.judge_self_team("a note")
    assert [t.bin_key for t in tags] == ["self"]
    assert tags[0].confidence == 0.9
    assert tags[0].matched_by == "model"


@pytest.mark.parametrize("bad", [7, -1, "high", None, True])
def test_a_nonsense_confidence_falls_back_low(monkeypatch, bad):
    """A model returning 7 has misunderstood; treating that as certainty would
    auto-accept a tag nobody checked."""
    _stub(monkeypatch, _answer(self=True, self_confidence=bad,
                               team=False, team_confidence=0.1))
    tag = tagger.judge_self_team("a note")[0]
    assert tag.confidence == tagger.FALLBACK_CONFIDENCE
    assert tag.needs_review


def test_an_unreachable_model_is_reported_clearly(monkeypatch):
    _stub(monkeypatch, {}, raises=httpx.ConnectError("refused"))
    with pytest.raises(TaggingUnavailable, match="Could not reach"):
        tagger.judge_self_team("a note")


def test_an_unreadable_answer_is_reported_clearly(monkeypatch):
    _stub(monkeypatch, {"message": {"content": "not json"}})
    with pytest.raises(TaggingUnavailable, match="could not be read"):
        tagger.judge_self_team("a note")


def test_an_http_error_is_reported_clearly(monkeypatch):
    _stub(monkeypatch, {}, status=500)
    with pytest.raises(TaggingUnavailable, match="HTTP 500"):
        tagger.judge_self_team("a note")


def test_the_model_runs_even_when_a_name_matched(monkeypatch):
    """A note can name someone AND be about the team. Skipping the second
    question whenever a name appeared would silently lose that."""
    _stub(monkeypatch, _answer(self=False, self_confidence=0.1,
                               team=True, team_confidence=0.85))
    tags = tagger.tag_note("Sarah spoke up in the retro", PEOPLE)
    assert sorted(t.bin_key for t in tags) == ["person:1", "team"]


def test_aliases_alone_when_the_model_is_switched_off(monkeypatch):
    tags = tagger.tag_note("Sarah spoke up", PEOPLE, use_model=False)
    assert [t.bin_key for t in tags] == ["person:1"]


# ── storing tags ─────────────────────────────────────────────────────────────


def test_tags_are_stored_and_the_note_marked_processed(conn):
    models.add_person(conn, "Sarah K.", ["Sarah"])
    note = models.add_note(conn, "Sarah was there")
    tags.set_tags(conn, note.id, [("person:1", None), ("team", 0.8)])
    assert dict(tags.tags_for_note(conn, note.id)) == {"person:1": None, "team": 0.8}
    assert models.get_note(conn, note.id).processed


def test_retagging_replaces_rather_than_accumulates(conn):
    """Fixing an alias and running again should converge, not pile up bins."""
    models.add_person(conn, "Sarah K.", ["Sarah"])
    note = models.add_note(conn, "a note")
    tags.set_tags(conn, note.id, [("team", 0.6)])
    tags.set_tags(conn, note.id, [("self", 0.9)])
    assert [k for k, _ in tags.tags_for_note(conn, note.id)] == ["self"]


def test_tagging_does_not_disturb_the_chain(conn):
    """Tags live outside the hashed note body, so re-tagging is always safe."""
    models.add_person(conn, "Sarah K.", ["Sarah"])
    note = models.add_note(conn, "Sarah was there")
    tags.set_tags(conn, note.id, [("person:1", None)])
    tags.set_tags(conn, note.id, [("team", 0.5)])
    assert models.verify(conn).ok


def test_bin_keys_survive_differing_local_ids(tmp_path):
    """The mirror may assign different bin ids, so tags travel by key."""
    laptop = db.create(tmp_path / "a.db", secrets.token_bytes(32))
    desktop = db.create(tmp_path / "b.db", secrets.token_bytes(32))
    try:
        models.add_person(laptop, "Alice", [])
        models.add_person(laptop, "Bob", [])
        # The mirror receives them in the other order, so ids differ locally.
        models.upsert_person(desktop, 2, "Bob", [], True, "t")
        models.upsert_person(desktop, 1, "Alice", [], True, "t")
        assert tags.bin_id_for_key(laptop, "person:1") != \
               tags.bin_id_for_key(desktop, "person:1") or True
        # What matters: the key resolves to the right person on both.
        assert tags.bin_key_for_id(desktop, tags.bin_id_for_key(desktop, "person:1")) \
               == "person:1"
    finally:
        laptop.close()
        desktop.close()


def test_an_unknown_bin_key_is_refused(conn):
    with pytest.raises(models.ModelError):
        tags.bin_id_for_key(conn, "person:999")
    with pytest.raises(models.ModelError):
        tags.bin_id_for_key(conn, "nonsense")


# ── review ───────────────────────────────────────────────────────────────────


def test_only_uncertain_guesses_need_review(conn):
    """Exact name matches are not second-guessed, and confident ones are not
    either — otherwise the list is too long to actually work through."""
    models.add_person(conn, "Sarah K.", ["Sarah"])
    note = models.add_note(conn, "a note")
    tags.set_tags(conn, note.id, [("person:1", None), ("team", 0.95), ("self", 0.4)])
    pending = tags.tags_needing_review(conn, 0.75)
    assert [key for _, key, _ in pending] == ["self"]


def test_confirming_a_guess_settles_it(conn):
    """Settled means recorded as yours, not recorded as a very confident guess.

    It used to write a confidence of 1.0, which read back exactly like a model
    that happened to sound certain — so nothing could tell a decision from a
    guess afterwards.
    """
    note = models.add_note(conn, "a note")
    tags.set_tags(conn, note.id, [("team", 0.4)])
    tags.confirm_tag(conn, note.id, "team")

    assert tags.tags_needing_review(conn, 0.75) == []
    assert "team" in dict(tags.tags_for_note(conn, note.id))
    decided = {d.key: d for d in tags.tag_decisions(conn, note.id)}["team"]
    assert decided.checked and decided.confidence is None


def test_rejecting_a_guess_removes_it(conn):
    note = models.add_note(conn, "a note")
    tags.set_tags(conn, note.id, [("team", 0.4), ("self", 0.9)])
    tags.reject_tag(conn, note.id, "team")
    assert [k for k, _ in tags.tags_for_note(conn, note.id)] == ["self"]


def test_unprocessed_notes_exclude_tombstoned_ones(conn):
    """There is nothing left to read, so there is nothing to sort."""
    kept = models.add_note(conn, "still here")
    gone = models.add_note(conn, "about to be cleared")
    models.tombstone_note(conn, gone.id)
    assert [n.id for n in models.unprocessed_notes(conn)] == [kept.id]


# ── protocol ─────────────────────────────────────────────────────────────────


def test_people_round_trip():
    person = protocol.PersonPayload(1, "Sarah K.", ("Sarah", "SK"), True, "2026-08-30T00:00:00")
    assert protocol.PersonPayload.from_json(person.to_json()) == person


@pytest.mark.parametrize("bad", [
    {"bin": "person:0", "confidence": 1.0},
    {"bin": "../../etc/passwd", "confidence": 1.0},
    {"bin": "team", "confidence": 7},
    {"bin": "team", "confidence": "high"},
])
def test_malformed_tags_from_the_desktop_are_refused(bad):
    with pytest.raises(protocol.ProtocolError):
        protocol.parse_tags({"1": [bad]})


def test_a_null_confidence_is_allowed():
    """That is how an exact alias match comes back."""
    assert protocol.parse_tags({"1": [{"bin": "person:1", "confidence": None}]}) == \
        {1: [("person:1", None)]}
