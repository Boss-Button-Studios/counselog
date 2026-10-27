"""Saving what one sorting run found about one note.

Two things sort notes: `counselog tag`, which gets its answers from the desktop
service, and the browser's Sort button, which asks the model itself. A note must
be filed the same way whichever one did it, so both come through here.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Iterable, Sequence

from core import judgements, tags

if TYPE_CHECKING:
    import sqlcipher3


def file_sorting(conn: "sqlcipher3.Connection", note_id: int,
                 found: "Sequence[tuple[str, float | None]]",
                 answers: Iterable[judgements.Judgement], *,
                 model: str, method: str) -> None:
    """File the note under the bins found, then keep every answer the model
    gave about it, the noes included.

    Tags first. They are what the record is filed under and matter more, so if
    keeping the answers fails the note is still sorted. Losing a run's answers
    costs a little evidence about the model; losing its tags would cost the
    note its place in every report.
    """
    tags.set_tags(conn, note_id, found)
    judgements.record(conn, note_id, answers, model=model, method=method)
