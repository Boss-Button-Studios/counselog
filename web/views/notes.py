"""Reading notes back, and clearing one.

Until now Counselog could capture a note, protect it and prove it had not been
altered, but not show it to anyone. This is the other half of the point.

Clearing a note goes through the same tombstone the CLI's `forget` uses: the
text goes, the chain entry stays, and the surrounding history stays verifiable.
It is deliberately two steps, because it is the one irreversible thing this
interface can do and a phone is an easy place to hit the wrong control.
"""

from __future__ import annotations

from flask import g, redirect, render_template, url_for

from core import models
from web.access import open_database, requires_unlock


def register(app) -> None:

    @app.get("/notes")
    @requires_unlock
    def note_list():
        """Newest first: the note you want is nearly always the recent one."""
        conn = open_database()
        try:
            notes = list(reversed(models.list_notes(conn)))
            return render_template("notes.html", caller=g.caller, notes=notes,
                                   cleared=sum(1 for note in notes if note.tombstoned))
        finally:
            conn.close()

    @app.get("/notes/<int:note_id>")
    @requires_unlock
    def note_detail(note_id: int):
        conn = open_database()
        try:
            note = _find(conn, note_id)
            if note is None:
                return _no_such_note()
            return render_template("note.html", caller=g.caller, note=note,
                                   tags=_labelled_tags(conn, note_id), confirming=False)
        finally:
            conn.close()

    @app.get("/notes/<int:note_id>/clear")
    @requires_unlock
    def confirm_clear(note_id: int):
        """A separate page rather than a dialog.

        The thing being destroyed is shown in full on the page that asks, so the
        answer is given while looking at what the answer applies to.
        """
        conn = open_database()
        try:
            note = _find(conn, note_id)
            if note is None:
                return _no_such_note()
            if note.tombstoned:
                return redirect(url_for("note_detail", note_id=note_id))
            return render_template("note.html", caller=g.caller, note=note,
                                   tags=_labelled_tags(conn, note_id), confirming=True)
        finally:
            conn.close()

    @app.post("/notes/<int:note_id>/clear")
    @requires_unlock
    def clear_note(note_id: int):
        conn = open_database()
        try:
            try:
                models.tombstone_note(conn, note_id)
            except models.ModelError:
                # Already cleared, or never existed. Neither is worth an error
                # page: the note page below says which.
                pass
        finally:
            conn.close()
        return redirect(url_for("note_detail", note_id=note_id))


def _find(conn, note_id: int) -> models.Note | None:
    try:
        return models.get_note(conn, note_id)
    except models.ModelError:
        return None


def _no_such_note():
    return render_template("error.html", title="No such note",
                           message="That note is not in your record."), 404


def _labelled_tags(conn, note_id: int) -> list[tuple[str, float | None]]:
    """Bin keys as names a person recognises.

    Tags travel by stable key — 'self', 'team', 'person:<id>' — because bin ids
    can differ between machines. That is right for the wire and useless on a
    page, so it is resolved here.
    """
    labelled = []
    for key, confidence in models.tags_for_note(conn, note_id):
        if key.startswith("person:"):
            try:
                label = models.get_person(conn, int(key.split(":", 1)[1])).display_name
            except (ValueError, models.ModelError):
                label = key  # a bin whose person is gone: show the raw key
        else:
            label = key
        labelled.append((label, confidence))
    return labelled


__all__ = ["register"]
