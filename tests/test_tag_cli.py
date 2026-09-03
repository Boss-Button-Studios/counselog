"""Phase 4: the tag and review commands.

The model is stubbed throughout — what matters here is the workflow around it:
progress that survives interruption, results saved as they arrive, and a review
list short enough to actually work through.
"""

import threading

import pytest
from click.testing import CliRunner
from werkzeug.serving import make_server

from core import db, models, tags
from core.certs import CertPaths, server_context
from core.crypto import Keyring, PasswordFactor
from core.paths import keyring_path, notes_db_path
from desktop import tagger
from desktop.__main__ import MutualTLSRequestHandler
from desktop.service import create_app
from desktop.sessions import SessionStore
from desktop.tagger import Tag
from laptop.cli import cli

PASSWORD = "swordfish"


@pytest.fixture
def run(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELOG_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("COUNSELOG_CERTS", str(tmp_path / "certs"))
    monkeypatch.setenv("COUNSELOG_DESKTOP_HOST", "localhost")
    runner = CliRunner()

    def _run(args, stdin=""):
        return runner.invoke(cli, args, input=stdin, catch_exceptions=False)

    return _run


@pytest.fixture
def ready(run, tmp_path, monkeypatch):
    run(["keys", "init", "--factor", "password", "--label", "t"],
        stdin=f"{PASSWORD}\n{PASSWORD}\n")
    run(["init", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    run(["people", "add", "Sarah K.", "--alias", "Sarah", "--unlock-with", "password"],
        stdin=f"{PASSWORD}\n")
    run(["certs", "init"])

    srv = make_server("127.0.0.1", 0, create_app(SessionStore()), threaded=True,
                      ssl_context=server_context(CertPaths(tmp_path / "certs")),
                      request_handler=MutualTLSRequestHandler)
    monkeypatch.setenv("COUNSELOG_PORT", str(srv.server_port))
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield run
    srv.shutdown()
    thread.join(timeout=5)


def _note(run, text):
    return run(["note", "-m", text, "--unlock-with", "password"], stdin=f"{PASSWORD}\n")


def _open():
    dek = Keyring.load(keyring_path()).unlock(PasswordFactor(PASSWORD))
    return db.connect(notes_db_path(), dek)


def _tag(run):
    return run(["tag", "--loopback", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")


# ── tagging ──────────────────────────────────────────────────────────────────


def test_a_named_person_is_tagged(ready, monkeypatch):
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    _note(ready, "Sarah pushed back on the timeline.")
    result = _tag(ready)
    assert result.exit_code == 0, result.output
    assert "Sarah K. (name matched)" in result.output

    conn = _open()
    try:
        assert dict(tags.tags_for_note(conn, 1)) == {"person:1": None}
    finally:
        conn.close()


def test_a_model_guess_shows_its_confidence(ready, monkeypatch):
    monkeypatch.setattr(tagger, "judge_self_team",
                        lambda text, **kw: [Tag("team", 0.85, "model")])
    _note(ready, "The group is finally talking to each other.")
    assert "85% sure" in _tag(ready).output


def test_nothing_to_do_is_said_plainly(ready, monkeypatch):
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    _note(ready, "a note")
    _tag(ready)
    assert "already sorted" in _tag(ready).output


def test_results_are_saved_as_they_arrive(ready, monkeypatch):
    """The whole reason tagging is one note per request: a failure part way
    through must not discard what already succeeded."""
    calls = {"n": 0}

    def flaky(text, **kwargs):
        calls["n"] += 1
        if calls["n"] > 1:
            raise tagger.TaggingUnavailable("the model went away")
        return [Tag("self", 0.9, "model")]

    monkeypatch.setattr(tagger, "judge_self_team", flaky)
    _note(ready, "first note")
    _note(ready, "second note")
    result = _tag(ready)

    assert "Sorted 1 of 2" in result.output
    assert "run `counselog tag` again" in result.output
    conn = _open()
    try:
        assert models.get_note(conn, 1).processed        # kept
        assert not models.get_note(conn, 2).processed    # still waiting
    finally:
        conn.close()


def test_tagging_resumes_where_it_stopped(ready, monkeypatch):
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    _note(ready, "first")
    _note(ready, "second")
    monkeypatch.setattr(tagger, "judge_self_team",
                        lambda text, **kw: (_ for _ in ()).throw(
                            tagger.TaggingUnavailable("down")))
    _tag(ready)
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    result = _tag(ready)
    assert result.exit_code == 0


def test_tagging_warns_when_nobody_is_listed(run, tmp_path, monkeypatch):
    """Without people, only self and team can ever match."""
    run(["keys", "init", "--factor", "password", "--label", "t"],
        stdin=f"{PASSWORD}\n{PASSWORD}\n")
    run(["init", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    run(["certs", "init"])
    run(["note", "-m", "a note", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    result = run(["tag", "--loopback", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert "No people added yet" in result.output


def test_tagging_discloses_what_leaves_the_machine(ready, monkeypatch):
    """Law 2, same as sync: note text is going to another machine."""
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    _note(ready, "a note")
    output = _tag(ready).output
    assert "to be sorted" in output
    assert "mutually authenticated" in output


def test_an_unreachable_desktop_is_reported(ready, monkeypatch):
    monkeypatch.setenv("COUNSELOG_PORT", "1")   # nothing listens there
    _note(ready, "a note")
    result = _tag(ready)
    assert result.exit_code != 0


# ── review ───────────────────────────────────────────────────────────────────


def test_review_shows_only_uncertain_guesses(ready, monkeypatch):
    monkeypatch.setattr(tagger, "judge_self_team",
                        lambda text, **kw: [Tag("team", 0.4, "model")])
    _note(ready, "Sarah was in the retro.")
    _tag(ready)

    result = ready(["review", "--unlock-with", "password"], stdin=f"{PASSWORD}\ny\n")
    assert "1 guess" in result.output
    assert "Sarah K." not in result.output.split("Suggested bin")[1]  # the name match is not queried


def test_keeping_a_guess_settles_it(ready, monkeypatch):
    monkeypatch.setattr(tagger, "judge_self_team",
                        lambda text, **kw: [Tag("team", 0.4, "model")])
    _note(ready, "a note")
    _tag(ready)
    ready(["review", "--unlock-with", "password"], stdin=f"{PASSWORD}\ny\n")

    conn = _open()
    try:
        assert dict(tags.tags_for_note(conn, 1))["team"] == 1.0
        assert tags.tags_needing_review(conn, 0.75) == []
    finally:
        conn.close()


def test_rejecting_a_guess_removes_it(ready, monkeypatch):
    monkeypatch.setattr(tagger, "judge_self_team",
                        lambda text, **kw: [Tag("team", 0.4, "model")])
    _note(ready, "a note")
    _tag(ready)
    ready(["review", "--unlock-with", "password"], stdin=f"{PASSWORD}\nn\n")

    conn = _open()
    try:
        assert tags.tags_for_note(conn, 1) == []
    finally:
        conn.close()


def test_review_can_be_stopped_part_way(ready, monkeypatch):
    """Quitting must keep the answers already given and leave the rest."""
    monkeypatch.setattr(tagger, "judge_self_team",
                        lambda text, **kw: [Tag("team", 0.4, "model")])
    _note(ready, "first")
    _note(ready, "second")
    _tag(ready)

    result = ready(["review", "--unlock-with", "password"], stdin=f"{PASSWORD}\ny\nq\n")
    assert "still waiting" in result.output
    conn = _open()
    try:
        assert len(tags.tags_needing_review(conn, 0.75)) == 1
    finally:
        conn.close()


def test_review_says_when_there_is_nothing_to_check(ready):
    result = ready(["review", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert "Nothing to check" in result.output


# ── progress display ─────────────────────────────────────────────────────────


def test_no_escape_codes_leak_into_redirected_output(ready, monkeypatch):
    """Progress overwrites its own line in a terminal, using an ANSI erase.

    Redirected to a file or a pipe, that escape would be written literally and
    the carriage return would jumble the line, so the in-place update must be
    suppressed. Click's test runner is not a tty, which is the case tested here.
    """
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    _note(ready, "Sarah pushed back on the Q3 timeline in standup this morning.")
    output = _tag(ready).output
    assert "\033" not in output
    assert "[K" not in output
    assert "\r" not in output


def test_the_result_is_shown_on_its_own_line_when_redirected(ready, monkeypatch):
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    _note(ready, "Sarah was there.")
    lines = [l for l in _tag(ready).output.splitlines() if "note 1" in l]
    # One line announcing the note, one reporting what it was tagged with. Both
    # name the note, so a log covering several notes stays readable.
    assert len(lines) == 2
    assert lines[1].strip().startswith("->")


def test_a_note_that_matched_nothing_is_flagged(ready, monkeypatch):
    """A note in no bin shows up in no report. Letting it pass silently would
    lose it more thoroughly than a wrong guess would."""
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    _note(ready, "Something with no name and no obvious subject.")
    output = _tag(ready).output
    assert "no bin at all" in output
    assert "will not show up in any report" in output


def test_notes_that_matched_are_not_flagged(ready, monkeypatch):
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    _note(ready, "Sarah was there.")
    assert "no bin at all" not in _tag(ready).output
