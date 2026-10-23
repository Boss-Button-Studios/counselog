"""The safety net, part 2: which sorting answers are put to a person.

The queue is computed, not stored, so these build a record and read the queue
off it: each kind appears when it should, leaves once a person answers, and the
audit sample is the same every time it is drawn.
"""

import hashlib

import pytest

from core import checking, db, judgements, models, revisions, tags
from core.judgements import Judgement

KEY = bytes(range(32))
THRESHOLD = 0.75


@pytest.fixture
def conn(tmp_path):
    connection = db.create(tmp_path / "notes.db", KEY)
    models.add_person(connection, "Ada L.", aliases=["Ada"])
    yield connection
    connection.close()


def _ada(conn):
    return f"{tags.PERSON_PREFIX}{models.list_people(conn)[0].id}"


def _sorted(conn, text, *, tagged=(), said=()):
    """A note sorted the way `counselog tag` does it: tags, then answers."""
    note = models.add_note(conn, text)
    tags.set_tags(conn, note.id, list(tagged))
    if said:
        judgements.record(conn, note.id, [Judgement(*answer) for answer in said],
                          model="m", method="test")
    return note.id


def _queue(conn, one_in=1_000_000):
    """The queue with the audit drawn so rarely that it never interferes,
    unless a test asks for it."""
    return {item.note.id: item for item in checking.to_check(conn, THRESHOLD, one_in=one_in)}


def _confident_noes():
    return [("self", False, 0.95), ("team", False, 0.95)]


# ── in no bin ────────────────────────────────────────────────────────────────

def test_a_note_in_no_bin_is_asked_about_both_bins(conn):
    note = _sorted(conn, "Quiet day.", said=_confident_noes())
    item = _queue(conn)[note]
    assert item.reason == checking.NO_BIN
    assert [(q.bin_key, q.model_said_yes) for q in item.questions] == [
        ("self", False), ("team", False)]


def test_a_note_in_any_bin_is_not_in_no_bin(conn):
    note = _sorted(conn, "Ada was great.", tagged=[(_ada(conn), None)], said=_confident_noes())
    assert note not in _queue(conn)
    assert checking.count_in_no_bin(conn) == 0


def test_a_note_sorted_before_answers_were_kept_still_counts_as_in_no_bin(conn):
    note = _sorted(conn, "Quiet day.")
    item = _queue(conn)[note]
    assert item.reason == checking.NO_BIN
    assert all(q.model_said_yes is None for q in item.questions)


def test_an_unsorted_note_waits_for_the_model_not_for_a_person(conn):
    models.add_note(conn, "Not sorted yet.")
    assert _queue(conn) == {}
    assert checking.count_in_no_bin(conn) == 0


def test_answering_both_bins_takes_the_note_off_the_queue_but_not_the_count(conn):
    """A note a person has said is about neither is settled, and still in no
    report — which the count exists to say."""
    note = _sorted(conn, "Quiet day.", said=_confident_noes())
    tags.reject_tag(conn, note, "self")
    assert [q.bin_key for q in _queue(conn)[note].questions] == ["team"]
    tags.reject_tag(conn, note, "team")
    assert note not in _queue(conn)
    assert checking.count_in_no_bin(conn) == 1


def test_confirming_a_bin_takes_the_note_out_of_no_bin(conn):
    note = _sorted(conn, "Quiet day.", said=_confident_noes())
    tags.confirm_tag(conn, note, "team")
    assert note not in _queue(conn)
    assert checking.count_in_no_bin(conn) == 0


# ── unsure ───────────────────────────────────────────────────────────────────

def test_an_unsure_no_is_asked_about(conn):
    """The case that could not be seen before answers were kept."""
    note = _sorted(conn, "Ada and the group.", tagged=[(_ada(conn), None)],
                   said=[("self", False, 0.95), ("team", False, 0.6)])
    item = _queue(conn)[note]
    assert [(q.bin_key, q.reason, q.model_said_yes, q.confidence) for q in item.questions] == [
        ("team", checking.UNSURE, False, 0.6)]


def test_an_unsure_yes_is_asked_about(conn):
    note = _sorted(conn, "The group.", tagged=[("team", 0.6)],
                   said=[("self", False, 0.95), ("team", True, 0.6)])
    assert [(q.bin_key, q.model_said_yes) for q in _queue(conn)[note].questions] == [
        ("team", True)]


def test_an_answer_with_no_number_is_unsure(conn):
    note = _sorted(conn, "Ada.", tagged=[(_ada(conn), None)],
                   said=[("self", False, None), ("team", False, 0.95)])
    assert [q.bin_key for q in _queue(conn)[note].questions] == ["self"]


def test_the_threshold_itself_is_sure(conn):
    note = _sorted(conn, "Ada.", tagged=[(_ada(conn), None)],
                   said=[("self", False, THRESHOLD), ("team", False, THRESHOLD)])
    assert note not in _queue(conn)


def test_an_unsure_yes_from_before_answers_were_kept_is_still_asked(conn):
    """`counselog review` already showed these; the queue must not lose them."""
    note = _sorted(conn, "The group.", tagged=[("team", 0.6)])
    assert [(q.bin_key, q.confidence) for q in _queue(conn)[note].questions] == [
        ("team", 0.6)]


def test_the_latest_answer_is_the_one_asked_about(conn):
    note = _sorted(conn, "Ada.", tagged=[(_ada(conn), None)],
                   said=[("self", False, 0.6), ("team", False, 0.95)])
    judgements.record(conn, note, [Judgement("self", False, 0.95),
                                   Judgement("team", False, 0.95)], model="m", method="test")
    assert note not in _queue(conn)


def test_a_persons_answer_settles_an_unsure_bin(conn):
    note = _sorted(conn, "The group.", tagged=[("team", 0.6)],
                   said=[("self", False, 0.95), ("team", True, 0.6)])
    tags.confirm_tag(conn, note, "team")
    assert note not in _queue(conn)


# ── the audit sample ─────────────────────────────────────────────────────────

def test_a_confident_answer_is_audited_when_the_note_is_drawn(conn):
    note = _sorted(conn, "Ada.", tagged=[(_ada(conn), None)], said=_confident_noes())
    item = _queue(conn, one_in=1)[note]
    assert item.reason == checking.AUDIT
    assert [q.bin_key for q in item.questions] == ["self", "team"]


def test_a_note_with_no_answers_on_record_is_not_audited(conn):
    """There is nothing to check a person's answer against."""
    note = _sorted(conn, "Ada.", tagged=[(_ada(conn), None)])
    assert note not in _queue(conn, one_in=1)


def test_one_note_can_be_asked_for_two_reasons(conn):
    note = _sorted(conn, "Ada.", tagged=[(_ada(conn), None)],
                   said=[("self", False, 0.95), ("team", False, 0.6)])
    item = _queue(conn, one_in=1)[note]
    assert [(q.bin_key, q.reason) for q in item.questions] == [
        ("self", checking.AUDIT), ("team", checking.UNSURE)]
    assert item.reason == checking.UNSURE


def test_the_sample_is_the_same_every_time(conn):
    for i in range(40):
        _sorted(conn, f"Ada, entry {i}.", tagged=[(_ada(conn), None)], said=_confident_noes())
    first = sorted(_queue(conn, one_in=4))
    assert first and first == sorted(_queue(conn, one_in=4))
    assert first != sorted(_queue(conn, one_in=5))


def test_the_sample_is_drawn_at_the_stated_rate():
    """Law 7: a probabilistic choice must follow its stated probability.
    10,000 hashes, one in ten: the count falls within four standard deviations
    (sd = 30), so a correct draw fails this about once in 16,000 runs."""
    drawn = sum(checking.in_audit_sample(hashlib.sha256(str(i).encode()).hexdigest(), 10)
                for i in range(10_000))
    assert abs(drawn - 1000) < 120


def test_the_sample_depends_on_the_hash_not_the_note_id():
    hashes = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(200)]
    assert ([checking.in_audit_sample(h, 10) for h in hashes]
            == [checking.in_audit_sample(h, 10) for h in hashes])
    assert checking.in_audit_sample(hashes[0], 1)


def test_a_rate_below_one_is_refused():
    with pytest.raises(ValueError):
        checking.in_audit_sample("ab" * 32, 0)


# ── what never queues ────────────────────────────────────────────────────────

def test_a_replaced_note_never_queues_only_its_correction(conn):
    note = _sorted(conn, "Quiet day.", said=_confident_noes())
    correction = revisions.revise(conn, note, "Quiet day, mostly.")
    tags.set_tags(conn, correction.id, [])
    assert sorted(_queue(conn)) == [correction.id]


def test_a_cleared_note_never_queues(conn):
    note = _sorted(conn, "Quiet day.", said=_confident_noes())
    models.tombstone_note(conn, note)
    assert _queue(conn, one_in=1) == {}
    assert checking.count_in_no_bin(conn) == 0


def test_the_queue_puts_what_matters_most_first(conn):
    audit = _sorted(conn, "Ada.", tagged=[(_ada(conn), None)], said=_confident_noes())
    unsure = _sorted(conn, "Ada again.", tagged=[(_ada(conn), None)],
                     said=[("self", False, 0.95), ("team", False, 0.5)])
    no_bin = _sorted(conn, "Quiet day.", said=_confident_noes())
    order = [item.note.id for item in checking.to_check(conn, THRESHOLD, one_in=1)]
    assert order == [no_bin, unsure, audit]


def test_an_empty_record_has_nothing_to_check(conn):
    assert checking.to_check(conn, THRESHOLD) == []
    assert checking.count_in_no_bin(conn) == 0
