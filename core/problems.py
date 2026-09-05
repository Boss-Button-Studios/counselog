"""Recording that something went wrong, in terms safe to show a person.

The browser's error page cannot show what actually failed. A traceback or an
exception message can carry a filesystem path or a fragment of a note, and the
whole point of the encrypted database is that note text does not appear in
places the key does not protect — a log file being the obvious one.

But "something went wrong, the details are in the service log" is a dead end for
the person this is built for. They do not know where the log is, and if they
found it they should not have to read a traceback to learn that a page was
broken.

So the two halves are split. The **reference** is a short code shown on the
error page and written next to the traceback in the log: quotable by someone who
cannot read the log, findable by someone who can. The **record** kept here is
deliberately thin — when, which route, and the exception's class name. Never the
message, never the traceback, never the path with its query string.

Same shape as `spool_quarantine`, and the same reasoning: evidence a person
should see, recorded on purpose, with the sensitive half left out.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from core.models import utc_now

# Enough that two problems will not collide in a record that keeps a few
# hundred; short enough to read down the phone to someone, or type into a
# search. Not a secret — it identifies a log line, it does not grant anything.
REFERENCE_BYTES = 4

# A crash loop should not be able to grow the database without bound. Old
# problems are worth less than new ones and are not evidence about any note, so
# unlike everything else here they can be dropped.
KEEP = 200


@dataclass(frozen=True)
class Problem:
    """One thing that went wrong, as much as is safe to say about it."""

    reference: str
    occurred_at: str
    endpoint: str | None
    kind: str

    @property
    def where(self) -> str:
        """The page it happened on, in words rather than a route name."""
        return PAGES.get(self.endpoint or "", "somewhere in the interface")


# Endpoint names are ours, but they are not English. A person reading this page
# is trying to work out what they were doing at the time.
PAGES = {
    "capture": "the writing page",
    "write": "saving a note",
    "note_list": "your notes",
    "note_detail": "a note",
    "clear_note": "clearing a note",
    "save_edit": "correcting a note",
    "people_list": "the people list",
    "person_detail": "a person",
    "save_person": "saving a person",
    "reports_dashboard": "the reports list",
    "person_digest": "a digest",
    "verify_record": "checking the record",
    "device_list": "the browsers page",
    "held_list": "the held notes page",
    "problem_list": "the problems page",
    "sign_in": "signing in",
}


def new_reference() -> str:
    """A short code for one problem, tying the page to the log."""
    return secrets.token_hex(REFERENCE_BYTES)


def record(conn, reference: str, *, endpoint: str | None, kind: str) -> Problem:
    """Write down that something failed. Never what it said."""
    with conn:
        conn.execute(
            "INSERT INTO problems (reference, occurred_at, endpoint, kind) "
            "VALUES (?, ?, ?, ?)",
            (reference, utc_now(), endpoint, kind),
        )
        conn.execute(
            "DELETE FROM problems WHERE reference NOT IN ("
            "  SELECT reference FROM problems ORDER BY occurred_at DESC, rowid DESC "
            "  LIMIT ?)", (KEEP,))
    return Problem(reference=reference, occurred_at=utc_now(),
                   endpoint=endpoint, kind=kind)


def recent(conn, limit: int = 50) -> list[Problem]:
    """The newest problems first, because that is the one being asked about."""
    return [
        Problem(reference=row["reference"], occurred_at=row["occurred_at"],
                endpoint=row["endpoint"], kind=row["kind"])
        for row in conn.execute(
            "SELECT * FROM problems ORDER BY occurred_at DESC, rowid DESC LIMIT ?",
            (limit,))
    ]


def count(conn) -> int:
    return int(conn.execute("SELECT COUNT(*) AS n FROM problems").fetchone()["n"])
