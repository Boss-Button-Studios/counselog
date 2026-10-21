"""Scoring a set of self/team decisions the way the product would use them.

Shared by every script that compares ways of deciding, so a difference between
two of them is a difference in the deciding and not in the counting. Standard
library only: the Laya script runs in a venv of its own that has no `httpx`, and
this must import there too.

Only a yes becomes a tag, and a tag below the review threshold is held for a
person to look at. So the counts that matter are which wrong answers review
would catch, which it would let through, and which right ones it would hold.
"""

from __future__ import annotations

from dataclasses import dataclass

# Mirrors `desktop.tagger.DEFAULT_THRESHOLD`, which cannot be imported here
# without pulling in httpx. `tests/test_bench_data.py` keeps the two equal.
REVIEW_THRESHOLD = 0.75


@dataclass(frozen=True)
class Decision:
    note: int
    bin: str
    wanted: bool
    arguable: bool
    said: bool
    confidence: float  # in the answer given, yes or no


def score(name: str, decisions: list[Decision], seconds: float, notes: int) -> None:
    firm = [d for d in decisions if not d.arguable]
    right = [d for d in firm if d.said == d.wanted]
    wrong_yes = [d for d in firm if d.said and not d.wanted]
    caught = [d for d in wrong_yes if d.confidence < REVIEW_THRESHOLD]
    held = [d for d in firm if d.said and d.wanted and d.confidence < REVIEW_THRESHOLD]
    right_yes = [d for d in firm if d.said and d.wanted]
    wrong_no = [d for d in firm if not d.said and d.wanted]

    print(f"\n=== {name} ===")
    print(f"  {len(right)}/{len(firm)} decisions right, {seconds / notes:.1f}s/note")
    print(f"  wrong yes: {len(wrong_yes)}, of which review catches {len(caught)} "
          f"and trusts {len(wrong_yes) - len(caught)}")
    print(f"  right yes: {len(right_yes)}, of which review holds {len(held)}")
    print(f"  wrong no:  {len(wrong_no)} (never reviewed)")
    for d in wrong_yes + wrong_no:
        print(f"    note {d.note:2} {d.bin}: said {'yes' if d.said else 'no'} "
              f"at {d.confidence:.2f}")
    arguable = [d for d in decisions if d.arguable and (d.said or d.wanted)]
    for d in arguable:
        print(f"    arguable note {d.note:2} {d.bin}: label {'yes' if d.wanted else 'no'}, "
              f"said {'yes' if d.said else 'no'} at {d.confidence:.2f}")
