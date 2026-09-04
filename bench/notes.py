"""Hand-labelled notes, and the fictitious record the reading pages are shown on.

Kept apart from the scripts that use them so a note can be added or a label
argued with, without touching the measuring.

These are inventions. They are written the way a supervisor actually writes —
half a sentence, a name, a bullet list, a typo left in — because a model that
scores well on tidy prose and badly on real notes has not been measured on
anything useful.
"""

from __future__ import annotations

# ── labelled for the self/team question ──────────────────────────────────────
#
# The label is the set of bins the model should return. An empty set means the
# note is about one other person and neither bin applies — the answer that is
# easiest for a model to get wrong, because saying yes to everything scores well
# on a set with no negatives in it. Half of these are negatives on purpose.

LABELLED: list[tuple[set[str], str]] = [
    ({"self"},
     "I lost my temper in the planning meeting today and cut someone off twice. "
     "I need to apologise tomorrow and I need to stop doing it."),
    ({"self"},
     "I keep putting off the budget review. Three weeks now. That one is on me "
     "and nobody else."),
    ({"team"},
     "Nobody is talking to anyone about machine bookings. Three people booked "
     "over each other this week and each found out on the day."),
    ({"team"},
     "Standup has drifted to twenty minutes and nobody raises a blocker any "
     "more. The whole group has stopped using it for what it is for."),
    (set(),
     "Sarah reported that her project has fallen a week behind. She needs two "
     "days on the widget machine to proceed."),
    (set(),
     "George has three projects needing the widget machine for the next three "
     "weeks. He booked it two months ago."),
]


# ── the fictitious record ────────────────────────────────────────────────────

PEOPLE = [
    ("Sarah Kurtzman", "Sarah"),
    ("George Johnson", "George"),
    ("Linda Albertson", "Linda"),
    ("Andy Henderson", "Andy"),
    ("Ralph Wrecker", "Ralph"),
]

# Every state a digest can show, which is the point of seeding rather than
# writing three notes by hand: a run of ordinary notes never produces a cleared
# one, a backdated one and a correction, and those are exactly the rows worth
# looking at. Person 1 is Sarah, 2 George, 3 Linda.
#
# (text, captured_at, person index, confidence, backdated_at, then what to do
#  with it afterwards)
SEEDED = [
    ("Sarah flagged that the widget line is bottlenecked behind George's booking.\n"
     "She needs two days on the machine and has none.",
     "2026-06-02T09:15:00+00:00", 1, None, None, None),
    ("The bottleneck came up again in standup. Nobody has moved on it.",
     "2026-06-14T16:40:00+00:00", 1, 0.41, None, None),
    ("Long conversation about the quarter. She is carrying more than\n"
     "her share of the integration work and knows it.",
     "2026-07-01T11:00:00+00:00", 1, 0.58, None, "confirm"),
    ("* asked for Friday off\n* wants the machine time before the freeze\n"
     "+ will hand the report to Ralph",
     "2026-07-20T08:05:00+00:00", 1, None, "2026-07-13T17:00:00+00:00", None),
    ("Sarah said the deadline was the 3rd.",
     "2026-08-03T09:00:00+00:00", 1, None, None, "revise"),
    ("A personal matter Sarah asked me not to keep.",
     "2026-08-19T14:20:00+00:00", 1, 0.77, None, "clear"),
    ("Follow-ups from the review:   \n\n\n"
     "* machine time confirmed\n+ report drafted\n- handover still open\n\n\n",
     "2026-09-01T10:30:00+00:00", 1, 0.83, None, None),
    ("George is holding his booking. He booked two months ago and is not wrong to.",
     "2026-08-28T09:00:00+00:00", 2, None, None, None),
    ("Linda ran the safety briefing. Went well.",
     "2026-04-11T13:00:00+00:00", 3, None, None, None),
]

# What the correction says, for the note marked "revise".
REVISION = ("Sarah said the deadline was the 13th, not the 3rd.\n"
            "Checked the email; she is right.")
