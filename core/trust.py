"""How far the `self` and `team` bins can be trusted, measured rather than hoped.

The figure comes from the audit sample alone (`core.checking`): a fixed one in N
of the notes, drawn by a hash before anyone knows what the model said. The other
checked answers cannot be used. Notes in no bin and unsure answers were put to a
person *because* the model had probably gone wrong, so counting them would
overstate its mistakes. Only a sample drawn blind to the answer says how often
a confident answer, the kind nobody looks at, is wrong.

Only notes where both answers are on record count: the model's (schema 8, so
notes sorted before then have none) and a person's. A drawn note nobody has
answered yet is simply not counted.

Below `MIN_SAMPLE` checked notes there is no figure, only progress towards one.
"2 of 3 wrong" would read as a measurement and is mostly noise.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from core import checking, judgements
from core.judgements import JUDGED_BINS
from core.tags import BY_PERSON, INCLUDED, bin_key_for_id

if TYPE_CHECKING:
    import sqlcipher3

# Fewer than this and the figure is not shown. Ten is low for a precise rate,
# but at one note in ten it already takes about a hundred notes to reach, and a
# rough figure that says how rough it is helps more than none.
MIN_SAMPLE = 10

# The figure covers only this many of the most recent checked notes, so it
# follows the model actually sorting now rather than one replaced months ago.
WINDOW = 40


@dataclass(frozen=True)
class Trust:
    """What the audit sample shows about one bin.

    `missed`: the model said no, a person said yes — notes missing from the
    bin. `added`: the model said yes, a person said no — notes in it that do
    not belong.
    """

    bin_key: str
    checked: int
    missed: int
    added: int

    @property
    def enough(self) -> bool:
        return self.checked >= MIN_SAMPLE

    @property
    def wrong(self) -> int:
        return self.missed + self.added


def trust(conn: "sqlcipher3.Connection") -> list[Trust]:
    """One figure per bin the model judges, from the most recent checked
    notes in the audit sample."""
    drawn = checking.audit_sample(conn)
    live = {note.id for note in checking.live_notes(conn)}
    answers = judgements.latest_everywhere(conn)
    person = _persons_answers(conn)

    figures = []
    for key in JUDGED_BINS:
        pairs = [(answers[(note_id, key)].said_yes, said_yes)
                 for (note_id, bin_key), said_yes in sorted(person.items(), reverse=True)
                 if bin_key == key and note_id in drawn and note_id in live
                 and (note_id, key) in answers][:WINDOW]
        figures.append(Trust(
            bin_key=key, checked=len(pairs),
            missed=sum(1 for model, truth in pairs if truth and not model),
            added=sum(1 for model, truth in pairs if model and not truth)))
    return figures


def describe(figure: Trust) -> str:
    """The figure as a sentence, the same in every place it is shown."""
    name = {"self": "about you", "team": "about the team"}[figure.bin_key]
    if not figure.enough:
        return (f"Notes {name}: {figure.checked} of the {MIN_SAMPLE} random checks "
                "needed before there is a figure.")
    count = f"Of the last {figure.checked} notes checked at random, "
    if not figure.wrong:
        return count + f"the sorting got every one right on whether it was {name}."
    parts = []
    if figure.missed:
        parts.append(f"missed {figure.missed} that {'was' if figure.missed == 1 else 'were'} {name}")
    if figure.added:
        parts.append(f"filed {figure.added} as {name} that {'was' if figure.added == 1 else 'were'} not")
    return count + "the sorting " + " and ".join(parts) + "."


def _persons_answers(conn) -> dict[tuple[int, str], bool]:
    """What a person said, yes or no, for every note and judged bin."""
    answered = {}
    for row in conn.execute("SELECT note_id, bin_id, decision FROM note_tags "
                            "WHERE decided_by = ?", (BY_PERSON,)):
        key = bin_key_for_id(conn, int(row["bin_id"]))
        if key in JUDGED_BINS:
            answered[(int(row["note_id"]), key)] = row["decision"] == INCLUDED
    return answered
