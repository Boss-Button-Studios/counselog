"""Can a small decision model answer the self/team question, on a CPU?

Laya (Convai Innovations, Apache 2.0) is a 421M-parameter ModernBERT encoder
with a decision head. It never writes text: it reads the note once and scores
each possible answer. If it were good enough, tagging could run on the laptop
itself — the note would never need to travel to the desktop to be sorted, and
the desktop would never need the key for it.

Run with a venv of its own, because Laya needs PyTorch and Counselog does not
(Law 9). Nothing here ships; `bench/` is never installed.

    python3 -m venv ~/.cache/counselog-bench/laya-venv
    ~/.cache/counselog-bench/laya-venv/bin/pip install \\
        --index-url https://download.pytorch.org/whl/cpu torch
    ~/.cache/counselog-bench/laya-venv/bin/pip install "transformers>=5" safetensors numpy

    ~/.cache/counselog-bench/laya-venv/bin/python -I bench/laya_classifier.py ~/models/laya

The model directory holds the files from huggingface.co/convaiinnovations/laya:
`model.safetensors`, `rl_agent_config.json`, `encoder/config.json`, `tokenizer/`,
and the two Python files `rl_agent_api.py` and `rl_common.py`. **Those two are
executed.** They were read in full before the first run on 2026-10-21 — no
network, no subprocess, weights loaded with safetensors rather than pickle — and
the weights matched the checksum the Hub publishes. Read them again before
running a newer copy. `-I` keeps the current directory and PYTHONPATH off the
import path, so only the directory named on the command line is added.

Two ways of asking, because the model card says the first can misbehave:

  - **noul**: Laya's yes/no type. The card warns it "can follow its option
    labels instead of the state", answering a confident no to clear yeses.
  - **choice**: the workaround the card gives — two options with neutral keys,
    the yes and no spelled out as their descriptions.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

from bench.notes import cases  # noqa: E402
from bench.scoring import Decision, score  # noqa: E402

QUESTIONS = {
    "self": ("Is this note, written by a supervisor, about the supervisor's own work, "
             "habits, or decisions?",
             "about the supervisor's own work, habits, or decisions",
             "about someone else, or about the team"),
    "team": ("Is this note, written by a supervisor, about the team as a whole rather "
             "than one individual?",
             "about the team as a whole",
             "about one individual, or about the supervisor"),
}


def as_noul() -> dict:
    return {key: {"type": "noul", "instructions": question}
            for key, (question, _, _) in QUESTIONS.items()}


def as_choice() -> dict:
    # Keys "a" and "b" carry no meaning of their own, which is the point of the
    # card's workaround: the model has to read the descriptions.
    return {key: {"type": "choice", "instructions": question,
                  "criteria": {"a": yes, "b": no}}
            for key, (question, yes, no) in QUESTIONS.items()}


def p_yes(answer: dict) -> float:
    if answer["type"] == "noul":
        return float(answer["noul"])
    return float(answer["probabilities"]["a"])


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__.split("\n\n")[0], file=sys.stderr)
        print("usage: laya_classifier.py MODEL_DIR", file=sys.stderr)
        return 2
    model_dir = Path(sys.argv[1]).expanduser().resolve()
    if not (model_dir / "rl_agent_api.py").is_file():
        print(f"{model_dir} does not look like a Laya checkpoint "
              f"(no rl_agent_api.py).", file=sys.stderr)
        return 2
    sys.path.insert(0, str(model_dir))
    from rl_agent_api import RLAgent  # the reviewed file; see the docstring

    started = time.monotonic()
    agent = RLAgent(str(model_dir), device="cpu")
    print(f"loaded in {time.monotonic() - started:.1f}s on CPU")

    notes = cases("all")
    for name, questions in (("laya noul", as_noul()), ("laya choice", as_choice())):
        decisions, total = [], 0.0
        for index, (expected, text, arguable) in enumerate(notes, start=1):
            started = time.monotonic()
            answers = agent.system_one(text, questions)["answers"]
            total += time.monotonic() - started
            for key in QUESTIONS:
                p = p_yes(answers[key])
                said = p >= 0.5
                decisions.append(Decision(index, key, key in expected, arguable, said,
                                          p if said else 1 - p))
        score(name, decisions, total, len(notes))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
