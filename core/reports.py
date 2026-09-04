"""The one report and the one dashboard metric (spec §9).

A per-person digest — every note sorted into someone's bin, in the order things
happened — and a count of how recently each person has been written about.
Neither involves the language model, and that is deliberate rather than a
staging decision. §9 asks for a digest with no synthesis, and Law 7 wants the
same notes to produce the same page every time. A model in this path would give
up both, in the one part of Counselog most likely to be read out loud in a room
where it matters.

So the only thing done to a note here is `tidy`: spacing and bullet markers,
nothing that changes a word. The digest is a *view* of the record. It never
writes, and what it shows can always be checked against the note itself.

**A digest says what it stands on.** Some notes are in a bin because a person
confirmed it, some because a name matched literally, and some because the model
judged it. Those are not the same kind of fact, so the page separates them and
counts each. A note nobody has checked is shown, marked — never quietly left
out. Leaving it out would make the digest look better checked than it is, and
this is a document people make decisions from.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timezone

from core import models, revisions, tags

# A digest orders by when things *happened*, which for a corrected note is when
# the original was written, not when the correction was. Both the notes list and
# this agree on that: correcting last month's note must not move it to today.


class ReportError(Exception):
    """The report could not be built as asked."""


# ── deterministic cleanup ────────────────────────────────────────────────────


def tidy(text: str) -> str:
    """Straighten a note's spacing for reading. Never change its words.

    Four rules, all reversible in the sense that matters: none of them can turn
    one statement into a different one.

      * trailing spaces at the end of a line go
      * a run of blank lines becomes one blank line
      * blank lines at the very start and end go
      * `*` and `+` bullets become `-`, so a digest of notes written on three
        different days does not look like three different documents

    A bullet is only recognised with a space after the marker, which is what
    keeps `*emphasis*` and `2 + 2` out of it.

    Idempotent by construction and tested as such: `tidy(tidy(x)) == tidy(x)`.
    A cleanup that kept changing its own output would mean two readers of the
    same note could see different text (Law 7).
    """
    if not text:
        return ""

    lines = [line.rstrip() for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n")]

    kept: list[str] = []
    for line in lines:
        if not line and kept and not kept[-1]:
            continue  # a second blank line in a row adds nothing
        kept.append(_bullet(line))

    while kept and not kept[0]:
        kept.pop(0)
    while kept and not kept[-1]:
        kept.pop()
    return "\n".join(kept)


def _bullet(line: str) -> str:
    """One spelling of "list item", or the line untouched."""
    stripped = line.lstrip(" ")
    indent = line[: len(line) - len(stripped)]
    if stripped[:2] in ("* ", "+ "):
        return f"{indent}-{stripped[1:]}"
    return line


# ── the per-person digest ────────────────────────────────────────────────────


@dataclass(frozen=True)
class Excerpt:
    """One note as a digest shows it, with where its place in the bin came from."""

    note: models.Note          # the revision the record currently stands behind
    occurred_at: str           # when it happened: the *original's* time
    backdated: bool
    edited: bool
    text: str                  # tidied for reading; the note itself is untouched
    decided_by: str            # tags.BY_PERSON / BY_ALIAS / BY_MODEL
    confidence: float | None

    @property
    def cleared(self) -> bool:
        return self.note.tombstoned

    @property
    def checked(self) -> bool:
        """Did a person look at this one and say it belongs here?

        An exact name match is reliable, but nobody read it. A digest that
        counted the two together would claim more checking than happened.
        """
        return self.decided_by == tags.BY_PERSON


@dataclass(frozen=True)
class Digest:
    """Everything written about one person, and what the collection rests on."""

    person: models.Person
    excerpts: tuple[Excerpt, ...]
    since: date | None
    until: date | None

    @property
    def total(self) -> int:
        return len(self.excerpts)

    @property
    def checked(self) -> int:
        return sum(1 for e in self.excerpts if e.checked)

    @property
    def matched(self) -> int:
        return sum(1 for e in self.excerpts if e.decided_by == tags.BY_ALIAS)

    @property
    def guessed(self) -> int:
        """Notes resting on nothing but the model's judgment."""
        return sum(1 for e in self.excerpts if e.decided_by == tags.BY_MODEL)

    @property
    def cleared(self) -> int:
        return sum(1 for e in self.excerpts if e.cleared)


def digest(conn, person_id: int, *, since: date | None = None,
           until: date | None = None) -> Digest:
    """Every note sorted to one person, oldest first.

    Raises `ReportError` if the range is backwards, because a digest headed
    "August to June" showing nothing looks exactly like a person nobody has
    written about, and the two want very different reactions.
    """
    if since and until and since > until:
        raise ReportError("The end of the range is before the start of it.")

    try:
        person = models.get_person(conn, person_id)
    except models.ModelError as exc:
        raise ReportError(str(exc)) from exc

    key = f"{tags.PERSON_PREFIX}{person_id}"
    excerpts = [e for e in _excerpts_in_bin(conn, key, _thread_index(conn))
                if _within(e.occurred_at, since, until)]
    return Digest(person=person, excerpts=tuple(excerpts), since=since, until=until)


def _thread_index(conn) -> dict[int, revisions.Thread]:
    """Every note's correction history, found by the revision that now stands.

    Built once and handed around rather than rebuilt per bin: the dashboard asks
    about every person in turn, and each rebuild walks every note in the record.
    """
    return {thread.current.id: thread for thread in revisions.threads(conn)}


def _excerpts_in_bin(conn, key: str,
                     threads: dict[int, revisions.Thread]) -> list[Excerpt]:
    """The bin's current notes, in the order the events happened.

    `notes_for_bin` already leaves out replaced notes and bins a person has
    excluded. What it cannot do in SQL is find the time the *thread* started, so
    the ordering is settled here.
    """
    built = []
    for note in tags.notes_for_bin(conn, key):
        thread = threads.get(note.id)
        root = thread.root if thread else note
        decision = tags.decision_for(conn, note.id, key)
        built.append(Excerpt(
            note=note,
            occurred_at=root.occurred_at,
            backdated=root.backdated_at is not None,
            edited=bool(thread and thread.edited),
            text=tidy(note.raw_text),
            # A tag row always exists — the bin listing is a join on it — but a
            # missing one must not take the page down. Unattributed reads as the
            # model's, which is the cautious way round: it never overstates how
            # much of the digest a person has checked.
            decided_by=decision.decided_by if decision else tags.BY_MODEL,
            confidence=decision.confidence if decision else None,
        ))

    built.sort(key=lambda e: (e.occurred_at, e.note.id))
    return built


def _within(occurred_at: str, since: date | None, until: date | None) -> bool:
    """Is this timestamp inside the range, treating both ends as whole days?

    Compared as text, the way every other date filter in the record works: ISO
    timestamps sort correctly as strings, so there is no parsing to get wrong on
    the way in. The end of a day is spelled `T23:59:59.999999` because '.' sorts
    above the '+' that opens a timezone offset — so a note at 23:59:59+00:00 on
    the last day of the range is inside it, and one at 00:00:00 the next morning
    is not.
    """
    if since and occurred_at < f"{since.isoformat()}T00:00:00":
        return False
    if until and occurred_at > f"{until.isoformat()}T23:59:59.999999":
        return False
    return True


# ── the dashboard: how recently, and how often ───────────────────────────────


@dataclass(frozen=True)
class Activity:
    """One person's line on the dashboard. A count, never a judgment."""

    person: models.Person
    note_count: int
    last_at: str | None        # when the most recent note about them happened
    days_since: int | None     # None when there is nothing to measure from

    @property
    def never(self) -> bool:
        return self.note_count == 0


def activity(conn, *, now: datetime | None = None) -> list[Activity]:
    """Every person, longest silence first.

    The order is the point of the metric. A dashboard sorted by name tells you
    who is on the list, which you already know; sorted this way, the person you
    have not written about since March is at the top where the gap is visible.

    `now` is injectable so the same record gives the same answer in a test
    (Law 7). It defaults to this machine's clock in UTC, matching `captured_at`.
    """
    today = (now or datetime.now(timezone.utc)).date()
    threads = _thread_index(conn)

    rows = []
    for person in models.list_people(conn, include_inactive=True):
        excerpts = _excerpts_in_bin(conn, f"{tags.PERSON_PREFIX}{person.id}", threads)
        last = excerpts[-1].occurred_at if excerpts else None
        rows.append(Activity(person=person, note_count=len(excerpts), last_at=last,
                             days_since=_days_since(last, today)))

    # Never-written people first, then the longest gap. A person with no notes
    # at all is the strongest version of the thing this list exists to show.
    rows.sort(key=lambda row: (row.days_since is not None, -(row.days_since or 0),
                               row.person.display_name.casefold()))
    return rows


def _days_since(last_at: str | None, today: date) -> int | None:
    """Whole days between a note and today, or None if there is no note.

    Never negative. A note backdated into the future is a typo rather than a
    fact about the future, and "written in -3 days" helps nobody read the page.
    An unparseable timestamp gives None for the same reason `friendly_time`
    shows the raw value: the count is not worth guessing at.
    """
    if not last_at:
        return None
    try:
        when = datetime.fromisoformat(last_at).date()
    except ValueError:
        return None
    return max((today - when).days, 0)


def unsorted_count(conn) -> int:
    """Notes no digest can show yet, because nothing has put them in a bin.

    Shown on the dashboard rather than left implicit. Without it the honest
    reading of an empty digest — "nothing has been sorted yet" — is
    indistinguishable from the alarming one, "nothing has been written".
    """
    return len(models.unprocessed_notes(conn))
