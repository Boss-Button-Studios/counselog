"""Does the model get hand-labelled notes right?

Six notes, half of them negatives — about one other person, so neither bin
applies. The negatives are the point: a model biased toward saying yes scores
well on a set without them, and phase 4 measured exactly that failure in the
smaller models.

The notes run in one sequence rather than one at a time, so whatever a run does
to the answers is included in the score, and the first note is asked again at
the end to see whether it held.

    PYTHONPATH=. .venv/bin/python bench/model_accuracy.py
    PYTHONPATH=. .venv/bin/python bench/model_accuracy.py --set pmo --shipping-only \
        --backend llamacpp --model gpt-oss-20b

`--set pmo` uses the eighty-two PMO notes in `bench/pmo.py` instead. Those are
mostly negatives, so the number to watch there is how often the model says
yes to a note about one person. Arguable labels are scored apart, because a
model disagreeing with an arguable label has not necessarily got it wrong.

Timings vary by an order of magnitude between models and machines; the script
prints them per note rather than promising one here.
"""

from __future__ import annotations

import sys

from bench.harness import ModelUnavailable, arguments, ask, shapes, shown
from bench.notes import cases


def run(label: str, template: str, notes, **how) -> str:
    print(f"\n=== {label} ===", flush=True)
    firm = [n for n in notes if not n.arguable]
    right = agreed = false_yes = 0
    total_seconds = 0.0
    for index, (name, expected, text, arguable) in enumerate(notes, start=1):
        bins, _, seconds = ask(text, template, **how)
        total_seconds += seconds
        correct = bins == expected
        if arguable:
            agreed += correct
            verdict = "agrees" if correct else "differs (arguable)"
        else:
            right += correct
            verdict = "ok" if correct else "MISS"
            # The failure phase 4 found: a yes on a note that is about one
            # person. Counted on its own because it is the one that costs.
            false_yes += not expected and bool(bins)
        print(f"  {index:2}. want {shown(expected):8} got {shown(bins):8} "
              f"{verdict}  ({seconds:.0f}s)", flush=True)

    repeated, _, seconds = ask(notes[0].text, template, **how)
    held = repeated == notes[0].expected
    print(f"  note 1 asked again at the end: {shown(repeated)} "
          f"{'(same)' if held else '(CHANGED)'}  ({seconds:.0f}s)", flush=True)

    negatives = sum(1 for case in firm if not case.expected)
    arguable_count = len(notes) - len(firm)
    summary = (f"{right}/{len(firm)} correct, yes on {false_yes}/{negatives} "
               f"one-person notes"
               + (f", agreed on {agreed}/{arguable_count} arguable" if arguable_count else "")
               + f", {total_seconds / len(notes):.0f}s/note, "
               + ("held its answer" if held else "DID NOT HOLD"))
    print(f"  {summary}", flush=True)
    return summary


def main() -> int:
    options = arguments(__doc__.splitlines()[0],
                        extra=lambda p: p.add_argument("--set", choices=("labelled", "pmo"),
                                                       default="labelled"))
    how = {"model": options.model, "backend": options.backend}
    notes = cases(options.set)
    print(f"{options.backend}: {options.model}, {len(notes)} notes from '{options.set}'")
    try:
        results = {label: run(label, template, notes, **how)
                   for label, template in shapes(options).items()}
    except ModelUnavailable as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 2

    print("\n=== summary ===")
    for label, summary in results.items():
        print(f"  {label}: {summary}")

    print("\nA score is a measurement, not a pass mark. What it is for is "
          "comparing two shapes,\nor two models, on the same notes — a number "
          "on its own says very little.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
