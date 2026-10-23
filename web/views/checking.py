"""Check the sorting: putting the model's answers to the person who knows.

The queue is `core.checking`'s. This shows it one note at a time — the text, and
for each open bin a plain question with two buttons — because the person
answering is reading a note, not working through a table.

The model's answer is shown beside each question as what it is, a suggestion,
and neither button is selected or styled as the default. A pre-chosen answer
would be confirmed by habit, and then the checked answers would only measure
how often the model agrees with itself.

Named "Check the sorting" because "Held for review" already means the spool's
quarantine, and the two have nothing to do with each other.
"""

from __future__ import annotations

from flask import g, redirect, render_template, request, url_for

from core import checking, models, tags
from core.judgements import JUDGED_BINS
from web.access import open_database, requires_unlock

ANSWERS = ("yes", "no")


def register(app) -> None:

    @app.get("/check")
    @requires_unlock
    def check_sorting():
        """The first note in the queue, or the first after one passed over.

        `after` is how "Not now" works without storing anything: the queue is
        recomputed on every visit, so passing over a note means asking for the
        one behind it.
        """
        after = request.args.get("after", type=int)
        conn = open_database()
        try:
            queue = checking.to_check(conn)
            item, passed_over = _next(queue, after)
            return render_template(
                "check.html", caller=g.caller, item=item, remaining=len(queue),
                passed_over=passed_over, after=after,
                audit_one_in=checking.AUDIT_ONE_IN,
                questions=[_shown(q) for q in item.questions] if item else [],
            )
        finally:
            conn.close()

    @app.post("/check/<int:note_id>/<bin_key>")
    @requires_unlock
    def answer_sorting(note_id: int, bin_key: str):
        """Record a person's answer about one bin. A yes files the note there;
        a no is remembered so the model is not allowed to put it back."""
        answer = request.form.get("answer")
        after = request.form.get("after", type=int)
        if bin_key not in JUDGED_BINS or answer not in ANSWERS:
            # Only a hand-made request gets here; the page sends neither.
            return _refused("That answer could not be read.")
        conn = open_database()
        try:
            if not _answerable(conn, note_id):
                return _refused("That note can no longer be checked. It may have "
                                "been corrected or cleared since the page loaded.")
            if answer == "yes":
                tags.confirm_tag(conn, note_id, bin_key)
            else:
                tags.reject_tag(conn, note_id, bin_key)
        finally:
            conn.close()
        return redirect(url_for("check_sorting", after=after) if after
                        else url_for("check_sorting"))


def _next(queue: list[checking.ToCheck], after: int | None):
    """The note to show, and whether any were passed over to reach it."""
    if after is None:
        return (queue[0] if queue else None), False
    position = next((i for i, item in enumerate(queue) if item.note.id == after), None)
    if position is None:
        # The note passed over has since been answered or corrected; its place
        # is gone, so start from the top rather than guess where it was.
        return (queue[0] if queue else None), False
    rest = queue[position + 1:]
    return (rest[0] if rest else None), True


def _answerable(conn, note_id: int) -> bool:
    """Only the text the record says now can be checked.

    A replaced note's answer would be about words the record no longer stands
    on, and a cleared one has no words left to judge.
    """
    try:
        note = models.get_note(conn, note_id)
    except models.ModelError:
        return False
    current = {n.id for n in models.list_notes(conn)}
    return note.id in current and not note.tombstoned


# The questions, in the words a person would use. Fixed text, so a screen
# reader announces the same question every time.
QUESTIONS = {
    "self": "Is this note about you — your own work, habits or decisions?",
    "team": "Is this note about the team as a whole, rather than one person?",
}


def _shown(question: checking.Question) -> dict:
    return {"bin_key": question.bin_key, "text": QUESTIONS[question.bin_key],
            "reason": question.reason, "suggestion": _suggestion(question)}


def _suggestion(question: checking.Question) -> str:
    """What the model said, as a sentence. Never a pre-selected answer."""
    if question.model_said_yes is None:
        return "The model's answer was not kept for this note."
    said = "yes" if question.model_said_yes else "no"
    if question.confidence is None:
        return f"The model said {said}, without saying how sure it was."
    return f"The model said {said}, {round(question.confidence * 100)}% sure."


def _refused(message: str):
    return render_template("error.html", title="That did not work",
                           message=message), 400


__all__ = ["register"]
