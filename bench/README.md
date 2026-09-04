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
| `seed_record.py` | Give me a record full of fictitious notes to look at. |

## Running them

Ollama must be running with `deepseek-r1:14b` pulled. Each model call takes
about 90 seconds on the reference desktop, so expect a stability run to take
five minutes and an accuracy run twenty.

    PYTHONPATH=. .venv/bin/python bench/model_stability.py
    PYTHONPATH=. .venv/bin/python bench/model_accuracy.py

Neither touches a database, a key, or a note. They only ask the model.

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
