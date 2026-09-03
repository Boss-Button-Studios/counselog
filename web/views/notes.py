"""Reading notes back, and clearing one.

Until now Counselog could capture a note, protect it and prove it had not been
altered, but not show it to anyone. This is the other half of the point.

Clearing a note goes through the same tombstone the CLI's `forget` uses: the
text goes, the chain entry stays, and the surrounding history stays verifiable.
It is deliberately two steps, because it is the one irreversible thing this
interface can do and a phone is an easy place to hit the wrong control.

Editing appends rather than rewrites — see `core/revisions.py`. The page has to
say so plainly, because "edit" normally means the old version is gone, and here
it is not.
"""

from __future__ import annotations

from flask import g, redirect, render_template, request, url_for

from core import models, revisions, tags
from web.access import open_database, requires_unlock


def register(app) -> None:

    @app.get("/notes")
    @requires_unlock
    def note_list():
        """Newest first: the note you want is nearly always the recent one."""
        conn = open_database()
        try:
            threads = list(reversed(revisions.threads(conn)))
            return render_template(
                "notes.html", caller=g.caller, threads=threads,
                cleared=sum(1 for t in threads if t.current.tombstoned))
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
            return _note_page(conn, note)
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
            return _note_page(conn, note, confirming=True)
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

    @app.get("/notes/<int:note_id>/edit")
    @requires_unlock
    def edit_note(note_id: int):
        conn = open_database()
        try:
            note = _find(conn, note_id)
            if note is None:
                return _no_such_note()
            if note.tombstoned:
                return redirect(url_for("note_detail", note_id=note_id))
            return _note_page(conn, note, editing=True, draft=note.raw_text)
        finally:
            conn.close()

    @app.post("/notes/<int:note_id>/edit")
    @requires_unlock
    def save_edit(note_id: int):
        """Append a correction. Never rewrite what is already in the record."""
        draft = request.form.get("text") or ""
        conn = open_database()
        try:
            note = _find(conn, note_id)
            if note is None:
                return _no_such_note()
            try:
                revision = revisions.revise(conn, note_id, draft)
            except (revisions.RevisionError, models.ModelError) as exc:
                return _note_page(conn, note, editing=True, draft=draft,
                                  error=str(exc)), 400
        finally:
            conn.close()
        return redirect(url_for("note_detail", note_id=revision.id))


def _note_page(conn, note: models.Note, *, confirming: bool = False,
               editing: bool = False, draft: str | None = None,
               error: str | None = None):
    """One place that renders a note, in whichever of its three states."""
    thread = revisions.thread_for(conn, note.id)
    return render_template(
        "note.html", caller=g.caller, note=note, thread=thread,
        tags=_labelled_tags(conn, note.id), confirming=confirming,
        editing=editing, draft=draft if draft is not None else note.raw_text,
        error=error,
    )


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
    for key, confidence in tags.tags_for_note(conn, note_id):
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
