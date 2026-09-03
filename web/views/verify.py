"""Checking that no note has been altered since it was written.

`models.verify` recomputes every note's hash and walks the chain. This page is
the same check the CLI runs, said the same way — including the part that limits
it. A green tick here proves the record has not changed. It does not prove a
note is true, and it does not prove when the events in it happened. A tool that
let a reassuring result imply more than it checked would be worse than one that
did not check at all, because it would be trusted.

The chain head is shown because it is the value worth writing down somewhere
else. Comparing it later catches a rewrite that a fresh verification on its own
cannot: an attacker who rebuilds the whole chain produces something internally
consistent, and only a copy of the old head from outside the database contradicts
it. Phase 7 signs that value; until then, noting it down is the poor version of
the same idea.
"""

from __future__ import annotations

from flask import g, render_template

from core import models
from web.access import open_database, requires_unlock


def register(app) -> None:

    @app.get("/verify")
    @requires_unlock
    def verify_record():
        conn = open_database()
        try:
            result = models.verify(conn)
            head = models.chain_head(conn)
            return render_template(
                "verify.html", caller=g.caller, result=result,
                problems=[_describe(problem) for problem in result.breaks],
                head=head.entry_hash if head else None,
                covered=head.seq if head else 0,
            )
        finally:
            conn.close()


def _describe(problem) -> dict:
    """One break, in terms that say where to look.

    A `seq` of 0 means the note sits outside the chain entirely — there is no
    position to report, because nothing ever recorded one for it. That is its own
    kind of finding: the note was never written through this program.
    """
    return {
        "note_id": problem.note_id,
        "where": (f"note {problem.note_id}" if problem.seq == 0
                  else f"position {problem.seq}, note {problem.note_id}"),
        "reason": problem.reason,
        "outside_the_chain": problem.seq == 0,
    }


__all__ = ["register"]
