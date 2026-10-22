"""Is a confidence the model states worth less than one read off it?

Two ways of asking the same self/team question, on the same notes:

  - **json**, what ships: the model writes `{"self": true, "self_confidence":
    0.9, ...}`. The confidence is a number it chose to write down.
  - **logprob**: one yes/no question per bin, one token allowed, and the
    confidence is the probability the model put on its answer — measured, not
    claimed. This is the shape of the "decision models" (Jev and its imitators)
    done with an ordinary model and no new dependency.

The score is taken the way the product uses it. Only a yes becomes a tag, and a
tag below `DEFAULT_THRESHOLD` is held for review. So what matters is:

  - **wrong yes, caught**: a bad tag that review would show someone. Good.
  - **wrong yes, trusted**: a bad tag accepted silently. The costly one.
  - **right yes, held**: a good tag someone has to click through. Friction.
  - **wrong no**: a bin missed. No tag, so review never sees it.

Arguable labels (`bench/pmo.py`) are left out of the score and listed apart.

    PYTHONPATH=. .venv/bin/python bench/compare_confidence.py --backend llamacpp \\
        --model gemma4-coach:12b

The logprob method needs llama.cpp; `--backend` sets only where the json
method asks.
"""

from __future__ import annotations

import sys

from bench.harness import (PROMPT, YES_NO_QUESTIONS, ModelUnavailable, arguments,
                           ask, ask_yes_no)
from bench.notes import cases
from bench.scoring import Decision, score
from desktop.tagger import DEFAULT_THRESHOLD, _confidence


def by_json(case, how) -> tuple[list[Decision], float]:
    bins, confidences, seconds = ask(case.text, PROMPT, **how)
    return [Decision(case.name, key, key in case.expected, case.arguable, key in bins,
                     _confidence(confidences.get(key)))
            for key in YES_NO_QUESTIONS], seconds


def by_logprob(case, model) -> tuple[list[Decision], float]:
    decisions, total = [], 0.0
    for key, question in YES_NO_QUESTIONS.items():
        p_yes, covered, seconds = ask_yes_no(case.text, question, model=model)
        total += seconds
        if covered < 0.5:
            print(f"     {case.name} {key}: only {covered:.0%} of the answer was yes/no",
                  flush=True)
        said = p_yes >= 0.5
        decisions.append(Decision(case.name, key, key in case.expected, case.arguable, said,
                                  p_yes if said else 1 - p_yes))
    return decisions, total


def main() -> int:
    options = arguments(__doc__.splitlines()[0],
                        extra=lambda p: p.add_argument("--set", default="all",
                                                       choices=("all", "labelled", "pmo")))
    notes = cases(options.set)
    how = {"model": options.model, "backend": options.backend}
    print(f"{len(notes)} notes; json via {options.backend}, logprob via llamacpp; "
          f"model {options.model}; review below {DEFAULT_THRESHOLD}")

    results = {"json": ([], 0.0), "logprob": ([], 0.0)}
    try:
        for index, case in enumerate(notes, start=1):
            for method in results:
                if method == "json":
                    found, seconds = by_json(case, how)
                else:
                    found, seconds = by_logprob(case, options.model)
                decisions, total = results[method]
                results[method] = (decisions + found, total + seconds)
            print(f"  {index}/{len(notes)}", end="\r", flush=True)
    except ModelUnavailable as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 2

    for method, (decisions, seconds) in results.items():
        score(method, decisions, seconds, len(notes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
