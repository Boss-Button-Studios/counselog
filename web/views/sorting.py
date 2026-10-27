"""Sort new notes: the browser's way of doing what `counselog tag` does.

The run itself is `web/sorting.py`. This page starts it, stops it, and says how
far it got. It does not refresh itself: a page that reloaded every few seconds
would keep the notes unlocked for as long as it was left open, which is the
thing the idle timeout is there to prevent.
"""

from __future__ import annotations

from flask import current_app, g, redirect, render_template, session as cookie, url_for

from core import checking, models
from web.access import open_database, requires_unlock, sessions_of
from web.sessions import NotSignedIn
from web.sorting import AlreadySorting, Sorter


def sorter_of(app=None) -> Sorter:
    return (app or current_app).config["SORTER"]


def register(app) -> None:

    @app.get("/sort")
    @requires_unlock
    def sort_notes():
        conn = open_database()
        try:
            waiting = len(models.unprocessed_notes(conn))
            to_check = len(checking.to_check(conn))
        finally:
            conn.close()
        return render_template("sort.html", caller=g.caller, waiting=waiting,
                               to_check=to_check, progress=sorter_of().progress())

    @app.post("/sort")
    @requires_unlock
    def start_sorting():
        conn = open_database()
        try:
            note_ids = [note.id for note in models.unprocessed_notes(conn)]
        finally:
            conn.close()
        if note_ids:
            try:
                key = sessions_of().lend(cookie.get("sid"))
            except NotSignedIn:
                return redirect(url_for("sign_in", next=url_for("sort_notes")))
            try:
                sorter_of().start(key, note_ids)
            except AlreadySorting:
                pass  # a second press, or a second browser: the page shows the run
        return redirect(url_for("sort_notes"))

    @app.post("/sort/stop")
    @requires_unlock
    def stop_sorting():
        sorter_of().stop()
        return redirect(url_for("sort_notes"))


__all__ = ["register", "sorter_of"]
