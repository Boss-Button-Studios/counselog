"""What the model said about each note — every answer, not just the yeses.

`note_tags` holds what a note is filed under now, and a no files nothing. That
is the right shape for reading the record and the wrong one for checking it: a
bin the model missed leaves no trace, and when a person settles a guess the
guess is cleared so it can never pass for a decision. This keeps the model's
answers beside the record instead, so that

  - a note the model said no to can still be found and checked, and
  - the model's answer and the person's can later be compared — which is the
    only honest way to say how far the sorting can be trusted, or to calibrate
    it.

Append-only (the schema refuses edits and deletes). Sorting a note again adds a
second set of rows rather than replacing the first: two runs that disagree are
a fact about the model worth keeping, not a mess to tidy up.

Nothing here decides anything. Recording an answer never changes a tag.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:
    import sqlcipher3

JUDGED_BINS = ("self", "team")


@dataclass(frozen=True)
class Judgement:
    """One answer about one bin.

    `confidence` is None when the model gave no usable number. It is not filled
    in with a fallback here — that substitution is the tagger's, for deciding
    what goes to review, and storing it would record a number the model never
    gave.
    """

    bin_key: str
    said_yes: bool
    confidence: float | None


@dataclass(frozen=True)
class RecordedJudgement:
    note_id: int
    bin_key: str
    said_yes: bool
    confidence: float | None
    model: str
    method: str
    judged_at: str


def record(conn: "sqlcipher3.Connection", note_id: int, answers: Iterable[Judgement], *,
           model: str, method: str, judged_at: str | None = None) -> int:
    """Keep one sorting run's answers for a note. Returns how many were kept.

    All of a run's answers go in together or not at all, so a note is never left
    with a `self` answer and no `team` one from the same run.
    """
    answers = list(answers)
    for answer in answers:
        if answer.bin_key not in JUDGED_BINS:
            raise ValueError(f"The model is not asked about {answer.bin_key!r}.")
    when = judged_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
    with conn:
        conn.executemany(
            "INSERT INTO model_judgements (note_id, bin_key, said_yes, confidence, "
            "model, method, judged_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(note_id, a.bin_key, int(a.said_yes), a.confidence, model, method, when)
             for a in answers],
        )
    return len(answers)


def for_note(conn: "sqlcipher3.Connection", note_id: int) -> list[RecordedJudgement]:
    """Every answer kept for a note, oldest run first."""
    return [
        RecordedJudgement(
            note_id=int(row["note_id"]), bin_key=row["bin_key"],
            said_yes=bool(row["said_yes"]), confidence=row["confidence"],
            model=row["model"], method=row["method"], judged_at=row["judged_at"],
        )
        for row in conn.execute(
            "SELECT * FROM model_judgements WHERE note_id = ? ORDER BY id", (note_id,))
    ]


def latest_everywhere(conn: "sqlcipher3.Connection") -> dict[tuple[int, str], Judgement]:
    """The most recent answer for every note and bin, in one read.

    For working over the whole record, where asking note by note would be one
    query per note.
    """
    current: dict[tuple[int, str], Judgement] = {}
    for row in conn.execute("SELECT note_id, bin_key, said_yes, confidence "
                            "FROM model_judgements ORDER BY id"):
        current[(int(row["note_id"]), row["bin_key"])] = Judgement(
            row["bin_key"], bool(row["said_yes"]), row["confidence"])  # later rows overwrite
    return current


def latest(conn: "sqlcipher3.Connection", note_id: int) -> dict[str, RecordedJudgement]:
    """The most recent answer for each bin — what the model thinks *now*."""
    current: dict[str, RecordedJudgement] = {}
    for answer in for_note(conn, note_id):
        current[answer.bin_key] = answer  # later rows overwrite earlier ones
    return current
