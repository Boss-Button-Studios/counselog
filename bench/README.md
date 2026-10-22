# bench

Things that measure Counselog against a real model or a real screen. They are
**not tests** and are never run by `pytest`.

The difference is not effort, it is what they check. A test asserts something
that must always be true, runs in milliseconds, and fails the build when it
breaks. These take minutes, need Ollama running with the model pulled, and
answer questions about a probabilistic system where the honest output is a
measurement rather than a pass or a fail.

They live here because the alternative turned out to be worse. The prompt
ordering in `desktop/tagger.py` was chosen on evidence gathered by scripts in a
temporary directory; the numbers went into a docstring and the scripts were
lost. That is a measurement nobody can check and nobody can repeat, which Law 7
asks for explicitly.

| script | question it answers |
|---|---|
| `model_stability.py` | Does a note get the same answer wherever it sits in a run? |
| `model_accuracy.py` | Does the model get hand-labelled notes right? |
| `compare_confidence.py` | Is a confidence read off the model (one-token yes/no, llama.cpp `logprobs`) worth more than one it writes in JSON? |
| `laya_classifier.py` | Can Laya, a small decision model, answer the same question on a CPU? Needs a venv of its own; see its docstring. |
| `seed_record.py` | Give me a record full of fictitious notes to look at. |

| data | what it is |
|---|---|
| `notes.py` | `cases()`, the one loader every scorer uses. Six hand-labelled notes, and the fictitious record `seed_record.py` writes. |
| `data/pmo_notes*.md`, read by `pmo.py` | Eighty-two fictitious PMO notes in two files, generated outside this project and kept as they arrived. Headings give the first self/team label (Team-wide, Self-note, or a person); the overrides in `pmo.py` are proposed and not yet reviewed. |

## Running them

By default they ask `deepseek-r1:14b` through Ollama, the model and runtime that
ship. `--backend llamacpp` asks the llama.cpp router instead
(`COUNSELOG_LLAMACPP_URL`, default `http://127.0.0.1:8085`), and `--model` names
an Ollama tag or a router preset. `--shipping-only` skips the old prompt shape,
which halves the run.

    PYTHONPATH=. .venv/bin/python bench/model_stability.py
    PYTHONPATH=. .venv/bin/python bench/model_accuracy.py
    PYTHONPATH=. .venv/bin/python bench/model_accuracy.py --set pmo --shipping-only \
        --backend llamacpp --model gpt-oss-20b

Run one at a time. Ollama and the router each load models onto the same GPU and
neither knows about the other, so two runs at once measure contention rather
than the model. Each script prints seconds per note; they range from a few
seconds to a few minutes depending on model and runtime.

None of them touches a database, a key, or a note. They only ask the model.

`scoring.py` counts decisions the way the product would use them — only a yes
becomes a tag, and a tag below the review threshold is held for a person — so
"wrong yes, trusted" is the number that costs. It and `pmo.py` are plain logic
and are tested in `tests/test_bench_data.py`; the scripts that call models are
not.

## Results, 2026-10-22

Radeon VII (16 GB, Vulkan), 88 notes (six labelled + eighty-two PMO): 160 firm
decisions, of which 14 are a yes. Arguable labels are listed by each script but
not scored.

| method | right | right yes, of 14 | wrong yes (trusted) | wrong no | s/note |
|---|---|---|---|---|---|
| gemma4 12b, json, llama.cpp | 148/160 | 7 | 5 (5) | 7 | 1.9 |
| gemma4 12b, logprob, llama.cpp | 143/160 | 9 | 12 (12) | 5 | 1.0 |
| Laya, noul, **CPU** | 142/160 | 7 | 11 (3) | 7 | 0.7 |
| Laya, two-option choice, CPU | 80/160 | 9 | 75 (40) | 5 | 0.7 |

**Every method finds about half the notes that belong in self or team.** The
headline accuracy is carried by the negatives; the yeses are where they fail.
gemma's json answer missed `self` on all four Self-note entries, including
"That's on me as much as anyone". And a missed bin makes no tag, so review —
the product's only safety net — never sees it.

- gemma is confident whatever it says: 0.90 or 1.00 on every mistake, written or
  read off the logits. Review would catch none of them.
- Laya's confidences spread, so review catches most of its wrong yeses (8 of
  11) — but it would also hold 6 of its 7 right ones. At 0.75 nearly every Laya
  yes goes to review, which is honest and not much use.
- The card's `choice` workaround is no good on these notes at any size.

Before 2026-10-22 the set had 38 notes and only 4 yeses; on that set every
method looked nearly perfect (gemma 68/70), which is the reason not to trust a
set without positives. deepseek-r1:14b (6/6 on the six labelled notes, 100–215
s/note on Ollama) and gpt-oss-20b (looped for ten minutes at temperature 0) were
measured then and not re-run.
