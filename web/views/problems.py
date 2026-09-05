"""What has gone wrong lately, in terms that are safe to show.

The error page tells someone a reference; this is where the references live.
Deliberately not a log viewer — see `core/problems.py` for why the message and
the traceback stay out of the browser. What is here is when, which page, and the
kind of fault, which is enough to tell "the same thing keeps breaking" from "it
happened once and never again".
"""

from __future__ import annotations

from flask import g, render_template

from core import problems
from web.access import open_database, requires_unlock


def register(app) -> None:

    @app.get("/problems")
    @requires_unlock
    def problem_list():
        conn = open_database()
        try:
            return render_template("problems.html", caller=g.caller,
                                   problems=problems.recent(conn),
                                   kept=problems.KEEP)
        finally:
            conn.close()


__all__ = ["register"]
