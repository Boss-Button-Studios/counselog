"""Deciding which bins a note belongs to.

Two stages, and the split matters more than it looks.

**Aliases first, deterministically.** If a note names someone you have listed,
that is not a judgement call — it is a string match, and a model should never be
asked to second-guess it. These tags are exact, instant, free, and identical
every time (Law 7). Spec §5 anticipates this: `confidence` is explicitly for
when tagging was "LLM-assisted rather than exact name match", so an exact match
records no confidence at all.

**Then the model, for one narrow question.** Measured on the reference desktop,
asking a model to pick from all bins took 47-294 seconds per note and produced
confident nonsense — an 8B model tagged a note with a person who was never
mentioned. Asking only "is this about you, or about the team as a whole?" is a
question aliases genuinely cannot answer, and is small enough to be reliable.

Self and team are honestly fuzzy categories, so model-assigned tags carry a
confidence and low-confidence ones are held for review rather than trusted.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Iterable, Sequence

import httpx

from core import config
from core.sanitize import sanitize

# Chosen by benchmark, not by reputation. On the reference desktop, across five
# hand-labelled notes: deepseek-r1:14b 4/5 at 88s, deepseek-r1:7b 3/5 at 54s,
# and llama3.1:8b, mistral:7b and phi3:mini all 2/5 at 2-4s. The small models
# were fast and wrong — biased toward answering yes to everything.
DEFAULT_MODEL = "deepseek-r1:14b"
DEFAULT_THRESHOLD = 0.75

# What a model-assigned tag is worth when the model gives no usable number.
# Deliberately below the threshold: an unquantified guess should be reviewed.
FALLBACK_CONFIDENCE = 0.5

SELF_TEAM_SCHEMA = {
    "type": "object",
    "properties": {
        "self": {"type": "boolean"},
        "self_confidence": {"type": "number"},
        "team": {"type": "boolean"},
        "team_confidence": {"type": "number"},
    },
    "required": ["self", "self_confidence", "team", "team_confidence"],
}

PROMPT = """A supervisor wrote this note. Answer two questions about it.

self: Is the note about the supervisor's OWN work, habits, or decisions?
team: Is the note about the team AS A WHOLE, rather than one individual?

Both are false if the note is only about one other person.
Give a confidence from 0 to 1 for each answer.

Note:
{note}"""


class TaggingUnavailable(Exception):
    """The model could not be reached or did not answer usably."""


@dataclass(frozen=True)
class Tag:
    """One bin a note belongs to.

    `confidence` is None for an exact alias match — there is nothing uncertain
    to quantify. A number means a model judged it.
    """

    bin_key: str
    confidence: float | None
    matched_by: str  # "alias" or "model"

    @property
    def needs_review(self) -> bool:
        if self.confidence is None:
            return False
        return self.confidence < DEFAULT_THRESHOLD


@dataclass(frozen=True)
class KnownPerson:
    person_id: int
    display_name: str
    aliases: tuple[str, ...]

    @property
    def bin_key(self) -> str:
        return f"person:{self.person_id}"


def _alias_pattern(alias: str) -> re.Pattern[str]:
    """Match an alias as a whole word, case-insensitively.

    Word boundaries stop 'Sam' matching inside 'Samantha'. `re.escape` matters
    because aliases are user text and may contain regex metacharacters — an
    alias of 'J.R.' should not become a wildcard.
    """
    escaped = re.escape(alias.strip())
    return re.compile(rf"(?<!\w){escaped}(?!\w)", re.IGNORECASE)


def match_aliases(text: str, people: Sequence[KnownPerson]) -> list[Tag]:
    """Find every listed person named in the note. Exact, and never guessed."""
    cleaned = sanitize(text)
    found: list[Tag] = []
    for person in people:
        if any(_alias_pattern(alias).search(cleaned) for alias in person.aliases if alias.strip()):
            found.append(Tag(bin_key=person.bin_key, confidence=None, matched_by="alias"))
    return found


def judge_self_team(
    text: str,
    *,
    model: str = DEFAULT_MODEL,
    url: str | None = None,
    timeout: float = 300.0,
    client: "httpx.Client | None" = None,
) -> list[Tag]:
    """Ask the model the one question aliases cannot answer.

    Temperature zero and a fixed seed, so the same note gives the same answer:
    a probabilistic step in an otherwise deterministic pipeline should at least
    be repeatable (Law 7).
    """
    endpoint = (url or config.ollama_url()).rstrip("/") + "/api/chat"
    body = {
        "model": model,
        "messages": [{"role": "user", "content": PROMPT.format(note=sanitize(text))}],
        "format": SELF_TEAM_SCHEMA,
        "stream": False,
        "options": {"temperature": 0, "seed": 42},
    }

    try:
        if client is not None:
            response = client.post(endpoint, json=body, timeout=timeout)
        else:
            response = httpx.post(endpoint, json=body, timeout=timeout)
    except httpx.HTTPError as exc:
        raise TaggingUnavailable(
            f"Could not reach the language model at {endpoint}: {exc}"
        ) from exc

    if response.status_code >= 400:
        raise TaggingUnavailable(f"The language model returned HTTP {response.status_code}.")

    try:
        content = response.json()["message"]["content"]
        answer = json.loads(content)
    except (KeyError, ValueError, TypeError) as exc:
        raise TaggingUnavailable("The language model's answer could not be read.") from exc

    tags: list[Tag] = []
    for bin_key in ("self", "team"):
        if not answer.get(bin_key):
            continue
        tags.append(Tag(bin_key=bin_key,
                        confidence=_confidence(answer.get(f"{bin_key}_confidence")),
                        matched_by="model"))
    return tags


def _confidence(raw: object) -> float:
    """Read a confidence, refusing to trust a number that makes no sense.

    A model that returns 7 or -1 has misunderstood the question, and treating
    that as certainty would auto-accept a tag nobody checked.
    """
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return FALLBACK_CONFIDENCE
    value = float(raw)
    if not 0.0 <= value <= 1.0:
        return FALLBACK_CONFIDENCE
    return value


def tag_note(
    text: str,
    people: Sequence[KnownPerson],
    *,
    model: str = DEFAULT_MODEL,
    use_model: bool = True,
    **kwargs,
) -> list[Tag]:
    """Tag one note: aliases always, the model for self and team.

    The model runs even when aliases matched. A note can name someone *and* be
    about the team, and skipping the second question whenever a name appeared
    would silently lose that.

    If the model is unavailable the alias tags still stand. Half a result beats
    refusing to record what was certain (Law 6).
    """
    tags = match_aliases(text, people)
    if not use_model:
        return tags
    try:
        tags.extend(judge_self_team(text, model=model, **kwargs))
    except TaggingUnavailable:
        raise
    return tags


def people_from_rows(rows: Iterable) -> list[KnownPerson]:
    """Build the matcher's view of people from database rows."""
    import json as _json
    return [
        KnownPerson(
            person_id=int(row["id"]),
            display_name=row["display_name"],
            aliases=tuple(_json.loads(row["aliases"])),
        )
        for row in rows
    ]
