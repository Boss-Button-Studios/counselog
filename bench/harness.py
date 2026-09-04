"""The one place a bench script asks the model something.

Deliberately not `tagger.judge_self_team`: these scripts have to be able to ask
with a *different* prompt shape than the one shipping, which is how the shipping
one was chosen. Everything else — the model, the schema, the options — comes
from `desktop.tagger`, so a bench run measures the real request and not an
approximation of it.
"""

from __future__ import annotations

import json
import time

import httpx

from core import config
from desktop.tagger import DEFAULT_MODEL, PROMPT, SELF_TEAM_SCHEMA

# The ordering used before 2026-09-04, kept so the comparison that chose the
# current one can be repeated rather than taken on trust. Every request in a run
# shares its long opening, which is what made an answer depend on its position.
INSTRUCTIONS_FIRST = """A supervisor wrote this note. Answer two questions about it.

self: Is the note about the supervisor's OWN work, habits, or decisions?
team: Is the note about the team AS A WHOLE, rather than one individual?

Both are false if the note is only about one other person.
Give a confidence from 0 to 1 for each answer.

Note:
{note}"""

SHAPES = {"note first (shipping)": PROMPT,
          "instructions first (before 2026-09-04)": INSTRUCTIONS_FIRST}


class ModelUnavailable(Exception):
    """Ollama is not answering. Worth its own message: it is the usual reason a
    bench run does nothing, and 'connection refused' does not say what to start."""


def ask(text: str, template: str, *, model: str = DEFAULT_MODEL,
        keep_alive: object = None, timeout: float = 600.0):
    """Ask the model about one note. Returns (bins, confidences, seconds)."""
    body = {
        "model": model,
        "messages": [{"role": "user", "content": template.format(note=text)}],
        "format": SELF_TEAM_SCHEMA,
        "stream": False,
        "options": {"temperature": 0, "seed": 42},
    }
    if keep_alive is not None:
        body["keep_alive"] = keep_alive

    started = time.monotonic()
    try:
        response = httpx.post(config.ollama_url().rstrip("/") + "/api/chat",
                              json=body, timeout=timeout)
    except httpx.HTTPError as exc:
        raise ModelUnavailable(
            f"Could not reach Ollama at {config.ollama_url()}: {exc}\n"
            f"Start it, and make sure `ollama pull {model}` has been run."
        ) from exc

    answer = json.loads(response.json()["message"]["content"])
    bins = {key for key in ("self", "team") if answer.get(key)}
    confidences = {key: answer.get(f"{key}_confidence") for key in ("self", "team")}
    return bins, confidences, time.monotonic() - started


def shown(bins: set[str]) -> str:
    """A set of bins as something readable, including when it is empty."""
    return ", ".join(sorted(bins)) if bins else "neither"
