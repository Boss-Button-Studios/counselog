"""The per-person digest, and the dashboard that says who has gone quiet.

Both are pure reads of the record — no model, no synthesis (spec §9). The work
of assembling them is in `core/reports.py`; what lives here is the boundary: how
a date typed into a form becomes a range, and how a page says what it is
standing on.

Two rules shape the pages.

**A digest never quietly leaves anything out.** Notes nobody has checked are in
it, marked. Notes whose text has been cleared are in it, marked. A page that
dropped them would read as the complete story of what was written about someone,
which is exactly the reading it cannot support.

**A refused range shows nothing rather than something else.** A digest headed
one date range and filled with another is a document that misleads a reader who
did nothing wrong — worse than an error message, because it looks fine.
"""

from __future__ import annotations

import re
from datetime import date

from flask import g, render_template, request

from core import models, reports
from web.access import open_database, requires_unlock

# The one shape accepted from the form. `date.fromisoformat` also takes '20260301'
# and week dates, and a person who typed one of those and got a different range
# than they meant would have no way to tell (Law 5).
PLAIN_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class BadDate(Exception):
    """What was typed is not a date this page will guess at."""


def register(app) -> None:

    @app.get("/reports")
    @requires_unlock
    def reports_dashboard():
        """How often, and how recently — a count, never a judgment (spec §9)."""
        conn = open_database()
        try:
            rows = reports.activity(conn)
            return render_template(
                "reports.html", caller=g.caller,
                here=[row for row in rows if row.person.active],
                gone=[row for row in rows if not row.person.active],
                recency=_recency, unsorted=reports.unsorted_count(conn),
            )
        finally:
            conn.close()

    @app.get("/reports/<int:person_id>")
    @requires_unlock
    def person_digest(person_id: int):
        conn = open_database()
        try:
            try:
                person = models.get_person(conn, person_id)
            except models.ModelError:
                return render_template(
                    "error.html", title="No such person",
                    message="Nobody by that id is on your list."), 404

            typed = {"since": request.args.get("since", ""),
                     "until": request.args.get("until", "")}
            try:
                digest = reports.digest(
                    conn, person_id,
                    since=_as_date(typed["since"]), until=_as_date(typed["until"]))
            except BadDate:
                return _page(person, typed,
                             "Dates go in as year-month-day, like 2026-03-01."), 400
            except reports.ReportError as exc:
                return _page(person, typed, str(exc)), 400
            return render_template("digest.html", caller=g.caller, digest=digest,
                                   person=person, typed=typed, error=None)
        finally:
            conn.close()


def _as_date(typed: str) -> date | None:
    """A date from the form, or nothing. Never a guess."""
    typed = (typed or "").strip()
    if not typed:
        return None
    if not PLAIN_DATE.match(typed):
        raise BadDate(typed)
    try:
        return date.fromisoformat(typed)
    except ValueError as exc:  # the right shape, but not a real day
        raise BadDate(typed) from exc


def _page(person: models.Person, typed: dict, message: str):
    """The page with its form and its complaint, and no notes under it.

    The heading and the dates that were typed stay, because a page that clears
    both leaves nowhere to correct the mistake from.
    """
    return render_template("digest.html", caller=g.caller, digest=None,
                           person=person, typed=typed, error=message)


def _recency(days: int) -> str:
    """How long since the last note, in words rather than a bare number.

    "42" needs the reader to work out what it is counting. This does not. The
    two ways a gap can be unknown — nothing written, or a timestamp that will
    not parse — are different things to tell someone, so the page says them
    rather than folding both into this.
    """
    if days == 0:
        return "today"
    if days == 1:
        return "yesterday"
    return f"{days} days ago"


__all__ = ["register"]
