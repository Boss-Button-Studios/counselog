"""Does the model get hand-labelled notes right?

Six notes, half of them negatives — about one other person, so neither bin
applies. The negatives are the point: a model biased toward saying yes scores
well on a set without them, and phase 4 measured exactly that failure in the
smaller models.

The notes run in one sequence rather than one at a time, so whatever a run does
to the answers is included in the score, and the first note is asked again at
the end to see whether it held.

    PYTHONPATH=. .venv/bin/python bench/model_accuracy.py

About twenty minutes per shape on the reference desktop.
"""

from __future__ import annotations

import sys

from bench.harness import SHAPES, ModelUnavailable, ask, shown
from bench.notes import LABELLED


def run(label: str, template: str) -> tuple[int, bool]:
    print(f"\n=== {label} ===", flush=True)
    right = 0
    for index, (expected, text) in enumerate(LABELLED, start=1):
        bins, _, seconds = ask(text, template)
        correct = bins == expected
        right += correct
        print(f"  {index}. want {shown(expected):8} got {shown(bins):8} "
              f"{'ok' if correct else 'MISS'}  ({seconds:.0f}s)", flush=True)

    repeated, _, seconds = ask(LABELLED[0][1], template)
    held = repeated == LABELLED[0][0]
    print(f"  note 1 asked again at the end: {shown(repeated)} "
          f"{'(same)' if held else '(CHANGED)'}  ({seconds:.0f}s)", flush=True)
    print(f"  {right}/{len(LABELLED)} correct, "
          f"{'held its answer' if held else 'DID NOT HOLD'}", flush=True)
    return right, held


def main() -> int:
    try:
        results = {label: run(label, template) for label, template in SHAPES.items()}
    except ModelUnavailable as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 2

    print("\n=== summary ===")
    for label, (right, held) in results.items():
        print(f"  {right}/{len(LABELLED)} correct, "
              f"{'held' if held else 'CHANGED'}   {label}")

    print("\nA score is a measurement, not a pass mark. What it is for is "
          "comparing two shapes,\nor two models, on the same notes — a number "
          "on its own says very little.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
