"""Notes the drain would not accept.

An entry lands here when it fails one of the two checks the spool exists for: it
broke the chain, or it was not stamped by a browser this database knows. Either
way it is not put into the record, and it is not thrown away either.

What is shown is deliberately thin — a position, a device, a reason, two times.
The text is not kept: an entry that failed its checks has not earned a place in
the record, and storing it would create a second, unverified pile of notes next
to the real one.
"""

from __future__ import annotations

from flask import g, redirect, render_template, url_for

from core import intake
from web.access import open_database, requires_unlock


def register(app) -> None:

    @app.get("/held")
    @requires_unlock
    def held_list():
        conn = open_database()
        try:
            return render_template(
                "held.html", caller=g.caller,
                waiting=intake.held(conn),
                seen=[row for row in intake.held(conn, include_acknowledged=True)
                      if row["acknowledged_at"]],
            )
        finally:
            conn.close()

    @app.post("/held/<int:seq>/acknowledge")
    @requires_unlock
    def acknowledge_held(seq: int):
        """Mark one as seen. The row stays — it is the evidence."""
        conn = open_database()
        try:
            intake.acknowledge(conn, seq)
        finally:
            conn.close()
        return redirect(url_for("held_list"))


__all__ = ["register"]
