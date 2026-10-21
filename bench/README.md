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
| `data/pmo_notes.md`, read by `pmo.py` | Thirty-two fictitious PMO notes, generated outside this project and kept as they arrived. Nearly all are about one person, so they measure how often a model says yes when it should not. Self/team labels are in `pmo.py`, proposed and not yet reviewed. |

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

## Results, 2026-10-21

Radeon VII (16 GB, Vulkan), 38 notes (six labelled + thirty-two PMO), 70 firm
decisions of which only 4 are a yes. **That last number is the weakness of every
row below**: a set this short on positives can tell a model that says yes too
often from one that does not, and very little else.

| method | right | wrong yes (trusted) | wrong no | s/note |
|---|---|---|---|---|
| deepseek-r1:14b, json, Ollama | 6/6 labelled only | — | — | 100–215 |
| gpt-oss-20b, json, llama.cpp | stuck on note 5: 13k tokens of reasoning at temperature 0 | | | |
| gemma4 12b, json, llama.cpp | 68/70 | 2 (2) | 0 | 1.8 |
| gemma4 12b, logprob, llama.cpp | 68/70 | 2 (2) | 0 | 0.9 |
| Laya, noul, **CPU** | 65/70 | 4 (1) | 1 | 0.5 |
| Laya, two-option choice, CPU | 35/70 | 34 (21) | 1 | 0.5 |

- Ollama is slower than CPU-only was (88 s/note) for the same model on this card.
- gemma's confidence is 0.89–1.00 on its mistakes either way it is asked, so
  review never sees them. Reading it off the logits did not make it honest.
- Laya's confidences spread out, so review catches more of its errors — but it
  missed "I lost my temper in the planning meeting", the plainest `self` in the
  set. The card's suggested `choice` workaround made it far worse, not better.

## Seeding a record to look at

`seed_record.py` writes fictitious notes and tags into a Counselog database, so
the reading pages can be looked at without anyone testing against their own
notes.

    COUNSELOG_HOME=/tmp/counselog-demo .venv/bin/python bench/seed_record.py

**It refuses to run against your real record**, and that refusal is the point of
the script existing here rather than being retyped each time. A tool that
fabricates notes must never be able to fabricate them in the record that is
supposed to be evidence — so it insists on a `COUNSELOG_HOME` you set yourself,
one that is not the default, and it will not add to a database it did not seed.

## Why they are not in `tests/`

`pyproject.toml` sets `testpaths = ["tests"]`, so `pytest` never collects this
directory, and `packages` lists the modules that ship — `bench` is not one of
them, so it is not installed. Both of those are deliberate: a suite that takes
twenty minutes and needs a language model would stop being run, and the day a
test suite stops being run is the day it stops being true.
