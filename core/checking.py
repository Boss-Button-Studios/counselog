"""Which sorting answers a person should check, and why.

The model finds only about half of what belongs in `self` and `team` (measured,
`bench/README.md`), and a no makes no tag — so before this, a miss was never
shown to anyone. This works out, from the record, the questions worth putting to
a person. Three kinds, most important first:

  - **In no bin.** A sorted note that is in no bin of any kind appears in no
    report. Nothing else in the interface would ever bring it back.
  - **Unsure.** The model's answer, yes *or* no, was below the threshold, or it
    gave no usable number at all.
  - **Audit.** A fixed one in `AUDIT_ONE_IN` of the notes, whatever the model
    said. The first two kinds only ever show answers the model already doubted;
    a confident mistake would never be seen, and anything measured or trained
    from checked answers alone would inherit that blind spot. The audit sample
    is what makes "the sorting missed 6 of the last 40" an honest figure.

Nothing is stored. The queue is recomputed every time, so it can never drift
from the record it describes, and an answer leaves it the moment a person gives
one (a `note_tags` row with `decided_by = 'person'`, through `confirm_tag` or
`reject_tag`).

Only `self` and `team` are asked about here — they are the bins the model
judges. A person's bin is matched by name, and the fix for a missed name is an
alias, which corrects every note at once; that is the interface's job.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import TYPE_CHECKING

from core import judgements
from core.judgements import JUDGED_BINS, Judgement
from core.models import SUPERSEDED, Note, note_from_row
from core.tags import BY_MODEL, BY_PERSON, INCLUDED, bin_key_for_id

if TYPE_CHECKING:
    import sqlcipher3

# The reasons, in the order they are worth a person's time.
NO_BIN = "no-bin"
UNSURE = "unsure"
AUDIT = "audit"
_RANK = {NO_BIN: 0, UNSURE: 1, AUDIT: 2}

# Below this, the model's answer is put to a person. Lives here rather than in
# the tagger because it is a rule about checking, and the web pages and the CLI
# both apply it — the desktop's tagger reuses it, not the other way round.
REVIEW_THRESHOLD = 0.75

# One note in this many is drawn for the audit, decided 2026-10-23 as a first
# guess: enough to fill a useful sample within a few months of notes, few enough
# not to become a chore. Changing it changes which notes are drawn, so a trust
# figure measured before the change and one measured after are separate samples.
AUDIT_ONE_IN = 10

# Mixed into the sample hash so this draw cannot coincide with any other use of
# the same hashes. Bump the version to redraw the sample deliberately.
_AUDIT_LABEL = b"counselog audit sample v1\x00"


@dataclass(frozen=True)
class Question:
    """One bin to ask about, and what the model said, if anything.

    `model_said_yes` is None when no answer is on record for this bin — a note
    sorted before answers were kept, or one the model was never asked about.
    """

    bin_key: str
    reason: str
    model_said_yes: bool | None
    confidence: float | None


@dataclass(frozen=True)
class ToCheck:
    note: Note
    questions: tuple[Question, ...]

    @property
    def reason(self) -> str:
        """The most pressing reason any of this note's questions is here."""
        return min((q.reason for q in self.questions), key=_RANK.__getitem__)


def in_audit_sample(entry_hash: str, one_in: int = AUDIT_ONE_IN) -> bool:
    """Is this note one of the fixed sample, whatever the model said about it?

    Drawn from the note's chain entry hash rather than its id. Ids are 1, 2, 3
    in every record, so a draw on ids would audit the same positions everywhere
    and could line up with habits (a note every weekday). The entry hash is
    unique to this record and fixed once written, so the draw is the same on
    every visit (Law 7) and depends on nothing the model said, which is what
    makes the sample fair. A correction is a new note with a new hash and is
    drawn afresh.
    """
    if one_in < 1:
        raise ValueError("The audit rate must be one in at least 1.")
    digest = hashlib.sha256(_AUDIT_LABEL + entry_hash.encode("ascii")).digest()
    return int.from_bytes(digest[:8], "big") % one_in == 0


def live_notes(conn: "sqlcipher3.Connection") -> list[Note]:
    """The notes a person could be asked about: sorted, current, not cleared.

    An unsorted note is waiting for the model, not for a person; a replaced one
    is no longer what the record says; a cleared one has nothing left to read.
    """
    return [note_from_row(r) for r in conn.execute(
        "SELECT * FROM notes WHERE processed = 1 AND tombstoned_at IS NULL "
        f"AND NOT {SUPERSEDED} ORDER BY id")]


def audit_sample(conn: "sqlcipher3.Connection", one_in: int | None = None) -> set[int]:
    """The ids of every note drawn for the audit, current or not."""
    one_in = AUDIT_ONE_IN if one_in is None else one_in
    # A note with no chain entry is a broken record, and `verify` says so; here
    # it is simply not drawn, rather than failing the whole page.
    return {int(note_id) for note_id, entry_hash in
            conn.execute("SELECT note_id, entry_hash FROM note_chain")
            if in_audit_sample(entry_hash, one_in)}


def to_check(conn: "sqlcipher3.Connection", threshold: float = REVIEW_THRESHOLD, *,
             one_in: int | None = None) -> list[ToCheck]:
    """Every note with something worth a person's look, most pressing first.

    `one_in` defaults to `AUDIT_ONE_IN` read at call time, not bound as a
    default, so the page that says "one in N" and the draw it describes can
    never disagree.
    """
    notes = live_notes(conn)
    if not notes:
        return []
    included, decided_by_person, tagged = _tags(conn)
    answers = judgements.latest_everywhere(conn)
    drawn = audit_sample(conn, one_in)

    queue = []
    for note in notes:
        in_no_bin = note.id not in included
        sampled = note.id in drawn
        questions = []
        for key in JUDGED_BINS:
            if (note.id, key) in decided_by_person:
                continue  # a person has answered; that settles it
            answer = answers.get((note.id, key)) or tagged.get((note.id, key))
            reason = _reason(answer, threshold, in_no_bin, sampled)
            if reason:
                questions.append(Question(
                    bin_key=key, reason=reason,
                    model_said_yes=answer.said_yes if answer else None,
                    confidence=answer.confidence if answer else None))
        if questions:
            queue.append(ToCheck(note=note, questions=tuple(questions)))
    queue.sort(key=lambda item: (_RANK[item.reason], item.note.id))
    return queue


def count_in_no_bin(conn: "sqlcipher3.Connection") -> int:
    """How many sorted, current notes appear in no report at all.

    Counts every such note, including ones a person has already said are about
    neither `self` nor `team` — those are still in no bin, and the count is
    what tells the reader that a note can be missing from every digest.
    """
    row = conn.execute(
        "SELECT count(*) FROM notes WHERE processed = 1 AND tombstoned_at IS NULL "
        f"AND NOT {SUPERSEDED} AND id NOT IN "
        f"(SELECT note_id FROM note_tags WHERE decision = '{INCLUDED}')").fetchone()
    return int(row[0])


def _reason(answer: Judgement | None, threshold: float, in_no_bin: bool,
            sampled: bool) -> str | None:
    if in_no_bin:
        return NO_BIN
    if answer is not None and (answer.confidence is None or answer.confidence < threshold):
        return UNSURE
    if sampled and answer is not None:
        return AUDIT
    # No answer on record and the note is in some bin: there is nothing to
    # check against. The note was sorted before answers were kept.
    return None


def _tags(conn):
    """Which notes are in any bin, which bins a person decided, and the model's
    own tags — the only record of an answer for notes sorted before schema 8."""
    included: set[int] = set()
    by_person: set[tuple[int, str]] = set()
    tagged: dict[tuple[int, str], Judgement] = {}
    for row in conn.execute("SELECT note_id, bin_id, confidence, decided_by, decision "
                            "FROM note_tags"):
        note_id, key = int(row["note_id"]), bin_key_for_id(conn, int(row["bin_id"]))
        if row["decision"] == INCLUDED:
            included.add(note_id)
        if row["decided_by"] == BY_PERSON:
            by_person.add((note_id, key))
        elif row["decided_by"] == BY_MODEL:
            tagged[(note_id, key)] = Judgement(key, True, row["confidence"])
    return included, by_person, tagged


# ── wording, shared by the web page and `counselog review` ───────────────────
#
# One queue, described the same way in both interfaces, so that a person who
# uses both is never left wondering whether they are looking at two lists.

QUESTIONS = {
    "self": "Is this note about you — your own work, habits or decisions?",
    "team": "Is this note about the team as a whole, rather than one person?",
}


def why(reason: str) -> str:
    """Why a note is being shown, in a sentence."""
    if reason == NO_BIN:
        return "This note is in no bin, so it appears in no report."
    if reason == UNSURE:
        return "The model was not sure how to sort this note."
    return (f"Picked at random: one note in {AUDIT_ONE_IN} is checked whatever the "
            "model said. That is the only way to find out how often it is "
            "confidently wrong.")


def suggestion(question: Question) -> str:
    """What the model said, as a sentence. Shown, never pre-selected."""
    if question.model_said_yes is None:
        return "The model's answer was not kept for this note."
    said = "yes" if question.model_said_yes else "no"
    if question.confidence is None:
        return f"The model said {said}, without saying how sure it was."
    return f"The model said {said}, {round(question.confidence * 100)}% sure."
