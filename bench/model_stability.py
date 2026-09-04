"""Does a note get the same answer wherever it sits in a run?

The question that mattered: sorting asks the model once per note, and the same
note is asked again every time it is corrected. An answer that depends on what
was asked before it means a note can fall out of a bin for no reason anyone
could see.

Ask note A, then note B, then note A again. A's two answers must match. Run it
for each prompt shape, so the comparison that chose the shipping one can be
repeated instead of believed.

    PYTHONPATH=. .venv/bin/python bench/model_stability.py

About five minutes per shape on the reference desktop.
"""

from __future__ import annotations

import sys

from bench.harness import SHAPES, ModelUnavailable, ask, shown
from bench.notes import LABELLED

# One clearly about the writer, one clearly about the team: two answers that
# should never be confused, so a flip between them is unambiguous.
A = LABELLED[0][1]
B = LABELLED[2][1]


def run(label: str, template: str) -> bool:
    print(f"\n=== {label} ===", flush=True)
    answers = []
    for position, (name, text) in enumerate((("A", A), ("B", B), ("A again", A)), start=1):
        bins, confidences, seconds = ask(text, template)
        answers.append(bins)
        print(f"  {position}. {name:8} -> {shown(bins):8} {confidences}  ({seconds:.0f}s)",
              flush=True)

    stable = answers[0] == answers[2]
    print(f"  {'STABLE' if stable else 'UNSTABLE'}: A answered "
          f"{shown(answers[0])}, then {shown(answers[2])}", flush=True)
    return stable


def main() -> int:
    print("Note A, note B, note A again. A must answer the same both times.")
    try:
        results = {label: run(label, template) for label, template in SHAPES.items()}
    except ModelUnavailable as exc:
        print(f"\n{exc}", file=sys.stderr)
        return 2

    print("\n=== summary ===")
    for label, stable in results.items():
        print(f"  {'stable  ' if stable else 'UNSTABLE'} {label}")

    # The shipping shape going unstable is the finding worth a non-zero exit:
    # it is the one someone would want to notice from a script.
    shipping = next(iter(SHAPES))
    return 0 if results[shipping] else 1


if __name__ == "__main__":
    raise SystemExit(main())
