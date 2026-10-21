"""The one place a bench script asks the model something.

Deliberately not `tagger.judge_self_team`: these scripts have to be able to ask
with a *different* prompt shape than the one shipping, which is how the shipping
one was chosen. Everything else — the model, the schema, the options — comes
from `desktop.tagger`, so a bench run measures the real request and not an
approximation of it.
"""

from __future__ import annotations

import argparse
import json
import math
import os
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


# The llama.cpp router on the desktop (`~/llm/serve.sh`). Bench-only for now:
# the shipping tagger still talks to Ollama, and these scripts are how the case
# for moving it is made or not made.
DEFAULT_LLAMACPP = "http://127.0.0.1:8085"
BACKENDS = ("ollama", "llamacpp")


class ModelUnavailable(Exception):
    """The model server is not answering. Worth its own message: it is the usual
    reason a bench run does nothing, and 'connection refused' does not say what
    to start."""


def _ollama_request(prompt: str, model: str, keep_alive: object):
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "format": SELF_TEAM_SCHEMA,
        "stream": False,
        "options": {"temperature": 0, "seed": 42},
    }
    if keep_alive is not None:
        body["keep_alive"] = keep_alive
    return config.ollama_url().rstrip("/") + "/api/chat", body


def _llamacpp_request(prompt: str, model: str, keep_alive: object):
    """The same question through llama.cpp's OpenAI-compatible endpoint.

    `response_format` is how llama.cpp takes a schema; it turns it into a
    grammar, the same mechanism as Ollama's `format`. Reasoning models think
    first, unconstrained, and only the answer is held to the schema — the
    reasoning arrives separately in `reasoning_content` and is ignored here.
    `keep_alive` has no equivalent: the router unloads on its own idle timer.
    """
    url = os.environ.get("COUNSELOG_LLAMACPP_URL", DEFAULT_LLAMACPP)
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "response_format": {"type": "json_schema",
                            "json_schema": {"name": "bins", "schema": SELF_TEAM_SCHEMA,
                                            "strict": True}},
        "temperature": 0,
        "seed": 42,
    }
    return url.rstrip("/") + "/v1/chat/completions", body


def _content(backend: str, payload: dict) -> str:
    if backend == "llamacpp":
        return payload["choices"][0]["message"]["content"]
    return payload["message"]["content"]


def ask(text: str, template: str, *, model: str = DEFAULT_MODEL,
        backend: str = "ollama", keep_alive: object = None, timeout: float = 600.0):
    """Ask the model about one note. Returns (bins, confidences, seconds)."""
    build = _llamacpp_request if backend == "llamacpp" else _ollama_request
    endpoint, body = build(template.format(note=text), model, keep_alive)

    started = time.monotonic()
    try:
        response = httpx.post(endpoint, json=body, timeout=timeout)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise ModelUnavailable(
            f"Could not get an answer from {endpoint} for model {model}: {exc}\n"
            f"Check the server is running and knows that model name."
        ) from exc

    answer = json.loads(_content(backend, response.json()))
    bins = {key for key in ("self", "team") if answer.get(key)}
    confidences = {key: answer.get(f"{key}_confidence") for key in ("self", "team")}
    return bins, confidences, time.monotonic() - started


def shown(bins: set[str]) -> str:
    """A set of bins as something readable, including when it is empty."""
    return ", ".join(sorted(bins)) if bins else "neither"


def arguments(description: str, extra=None) -> argparse.Namespace:
    """The options every bench script takes, so a run names what it measured.

    `extra` lets one script add its own without the others growing a flag they
    would ignore.
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--backend", choices=BACKENDS, default="ollama")
    parser.add_argument("--model", default=DEFAULT_MODEL,
                        help="an Ollama tag, or a llama.cpp router preset name")
    parser.add_argument("--shipping-only", action="store_true",
                        help="measure only the prompt shape that ships")
    if extra is not None:
        extra(parser)
    return parser.parse_args()


def shapes(options: argparse.Namespace) -> dict[str, str]:
    if options.shipping_only:
        first = next(iter(SHAPES))
        return {first: SHAPES[first]}
    return SHAPES


# ── asking one yes/no question and reading the answer's probability ──────────
#
# The alternative to having the model write JSON with a confidence in it. Here
# the model is allowed one token, and the confidence is not something it says
# but something read off it: how much probability it put on "yes" against "no".
# One short pass, no sampling to vary, no reasoning to run away.

YES_NO_QUESTIONS = {
    "self": "Is the note about the supervisor's OWN work, habits, or decisions?",
    "team": "Is the note about the team AS A WHOLE, rather than one individual?",
}

# Note first, for the reason `desktop.tagger.PROMPT` gives.
YES_NO_PROMPT = """Note:
{note}

A supervisor wrote the note above.
Question: {question}
Answer no if the note is only about one other person.
Answer with exactly one word: yes or no."""


def ask_yes_no(text: str, question: str, *, model: str, timeout: float = 300.0):
    """Returns (probability of yes, probability mass on yes or no, seconds).

    Probabilities come from llama.cpp's `logprobs`, over the top candidates for
    the single answer token. "yes", "Yes" and " yes" are one answer spelled
    three ways, so their probabilities are summed. The second value says how
    much of the model's probability landed on any spelling of yes or no at all;
    a low one means it wanted to say something else, and the first value is
    then not worth much.
    """
    url = os.environ.get("COUNSELOG_LLAMACPP_URL", DEFAULT_LLAMACPP)
    body = {
        "model": model,
        "messages": [{"role": "user",
                      "content": YES_NO_PROMPT.format(note=text, question=question)}],
        "max_tokens": 1,
        "temperature": 0,
        "seed": 42,
        "logprobs": True,
        "top_logprobs": 20,
    }
    started = time.monotonic()
    try:
        response = httpx.post(url.rstrip("/") + "/v1/chat/completions",
                              json=body, timeout=timeout)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise ModelUnavailable(f"Could not get an answer from {url} for {model}: {exc}") from exc

    candidates = response.json()["choices"][0]["logprobs"]["content"][0]["top_logprobs"]
    mass = {"yes": 0.0, "no": 0.0}
    for candidate in candidates:
        word = candidate["token"].strip().lower()
        if word in mass:
            mass[word] += math.exp(candidate["logprob"])
    covered = mass["yes"] + mass["no"]
    p_yes = mass["yes"] / covered if covered else 0.5
    return p_yes, covered, time.monotonic() - started
