"""Turning stored values into something a person reads.

Small on purpose, and shared: the CLI and the browser must describe the same
note the same way. A note that reads as "2026-09-02 03:09" in the terminal and
something else on a phone invites the reader to think they are looking at two
different things.

Nothing here changes what is stored. These are for display only.
"""

from __future__ import annotations

from datetime import datetime

PREVIEW_CHARS = 200
CLEARED = "(cleared)"


def friendly_time(iso: str | None) -> str:
    """An ISO timestamp as a person reads it, or the original if it will not parse.

    Falling back to the raw value rather than raising: a timestamp that cannot be
    parsed is worth showing as-is, because seeing the odd value is what lets
    anyone work out why it is odd.
    """
    if not iso:
        return ""
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso


def preview(text: str, limit: int = PREVIEW_CHARS) -> str:
    """One line standing in for a note, for a list.

    Whitespace is collapsed so a note that opens with a blank line or a bullet
    list does not turn into a ragged row. A tombstoned note has no text at all,
    and says so rather than appearing as an empty row someone might read as a
    rendering fault.
    """
    if not text:
        return CLEARED
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit] + "…"
