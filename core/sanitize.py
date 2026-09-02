"""Clean note text before it is stored, hashed, or shown to a model.

Spec §7 scopes this precisely. v0 notes are self-authored, so the realistic
problem is not a hostile document — it is pasting an email or a Slack message
and dragging in invisible characters that confuse the tagging prompt. That is an
accident, not an attack, and the fix is proportionate: strip the invisible
things, normalise, move on. No document parsing, no OCR.

This runs at ingestion, *before* the text is hashed into the chain, so what gets
hashed is exactly what gets stored. It runs again before any model call, because
the second pass is nearly free and the alternative is trusting that nothing
touched the text in between.
"""

from __future__ import annotations

import unicodedata

# Control characters worth keeping. Everything else in category Cc is noise in a
# plain-text note and can only confuse downstream consumers.
KEPT_CONTROLS = frozenset("\n\t")


def sanitize(text: str) -> str:
    """Return `text` with invisible characters removed and normalised to NFC.

    Three steps, in this order:

    1. Normalise line endings. Done first because CR is a control character; if
       it were simply stripped, a CRLF document would keep its LF and survive,
       but a classic-Mac CR-only document would have every line welded into one.
    2. Drop invisible characters — Unicode category Cf (zero-width joiners and
       non-joiners, the BOM, directional overrides) and Cc (control characters)
       except the ones worth keeping.
    3. Normalise to NFC, so text that looks identical compares and hashes
       identically.

    A known trade-off, following the spec: stripping Cf removes zero-width
    joiners, which carry meaning in emoji sequences and some Indic scripts. A
    family emoji would decompose into separate people. For English-language
    supervisory notes that is a fair price for predictable input; revisit it if
    notes ever need those scripts.
    """
    if not text:
        return ""

    text = normalize_newlines(text)

    cleaned = []
    for char in text:
        if char in KEPT_CONTROLS:
            cleaned.append(char)
            continue
        category = unicodedata.category(char)
        if category in ("Cf", "Cc"):
            continue  # invisible or control: drop it
        cleaned.append(char)

    return unicodedata.normalize("NFC", "".join(cleaned))


def normalize_newlines(text: str) -> str:
    """One spelling of "new line", everywhere.

    Split out of `sanitize` because it is also the *only* transformation a
    browser is asked to reproduce. A form submission rewrites every newline in a
    textarea as CRLF on its way to the server, so a browser stamping the text it
    holds and a server checking the text it received would disagree about every
    multi-line note. Both sides normalise first, and this is the definition they
    share — see `web/static/capture.js`.

    Classic-Mac CR-only line endings are handled too, and the order matters: CRLF
    must be collapsed before a bare CR is replaced, or every CRLF would become
    two newlines.
    """
    return text.replace("\r\n", "\n").replace("\r", "\n")


def describe_changes(original: str, cleaned: str) -> str | None:
    """A short, plain description of what sanitizing removed, or None.

    Used to tell the user their pasted text was altered. Silence would be worse:
    the note they read back would differ from the one they pasted, with no clue
    why (Law 6).
    """
    if original == cleaned:
        return None
    removed = len(original) - len(cleaned)
    if removed > 0:
        noun = "character" if removed == 1 else "characters"
        return f"removed {removed} invisible or control {noun}"
    return "normalised accented characters"
