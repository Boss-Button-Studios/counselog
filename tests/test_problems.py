"""Telling someone what broke, without telling them anything unsafe.

"Something went wrong, the details are in the service log" is a dead end for the
person this is built for: they do not know where the log is, and should not have
to read a traceback to learn a page was broken. But the traceback cannot come to
them either — an exception message can carry a file path or a piece of a note,
and note text does not belong anywhere the encryption does not reach.

So the two halves are split, and these tests are mostly about the split holding:
a reference that ties the page to the log, a record thin enough to be safe, and
an error handler that cannot itself take the page down.
"""

import re

import pytest
from click.testing import CliRunner

from core import db, models, problems
from core.crypto import Keyring, PasswordFactor
from core.paths import keyring_path, notes_db_path
from laptop.cli import cli
from web.app import create_app

PASSPHRASE = "correct horse battery staple"
TAILSCALE = {"REMOTE_ADDR": "127.0.0.1", "HTTP_TAILSCALE_USER_LOGIN": "you@example.com"}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELOG_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "data"))
    CliRunner().invoke(cli, ["keys", "init", "--factor", "password", "--label", "w"],
                       input=f"{PASSPHRASE}\n{PASSPHRASE}\n", catch_exceptions=False)
    CliRunner().invoke(cli, ["init", "--unlock-with", "password"],
                       input=f"{PASSPHRASE}\n", catch_exceptions=False)
    return tmp_path


@pytest.fixture
def dek(home):
    return Keyring.load(keyring_path()).unlock(PasswordFactor(PASSPHRASE))


@pytest.fixture
def conn(dek):
    connection = db.connect(notes_db_path(), dek)
    yield connection
    connection.close()


@pytest.fixture
def client(home):
    """An app that renders its own error pages, the way a real one does.

    `app.testing = True` re-raises instead, which would test pytest rather than
    the handler being written here.
    """
    app = create_app()
    app.config["PROPAGATE_EXCEPTIONS"] = False
    return app.test_client()


def sign_in(client):
    page = client.get("/signin", environ_overrides=TAILSCALE)
    token = re.search(r'name="_csrf" value="([^"]+)"',
                      page.get_data(as_text=True)).group(1)
    return client.post("/signin", data={"passphrase": PASSPHRASE, "_csrf": token},
                       environ_overrides=TAILSCALE)


def get(client, path):
    return client.get(path, environ_overrides=TAILSCALE)


def text_of(response) -> str:
    return " ".join(response.get_data(as_text=True).split())


def break_verify(monkeypatch, message="note text that must not escape"):
    """Make a page fail with an exception carrying something private."""
    def explode(conn):
        raise RuntimeError(message)
    monkeypatch.setattr("web.views.verify.models.verify", explode)


# ── what is recorded ─────────────────────────────────────────────────────────


def test_a_problem_records_when_where_and_what_kind(conn):
    problems.record(conn, "abc123", endpoint="verify_record", kind="RuntimeError")

    kept = problems.recent(conn)
    assert len(kept) == 1
    assert kept[0].reference == "abc123"
    assert kept[0].kind == "RuntimeError"
    assert kept[0].where == "checking the record"


def test_a_route_name_becomes_words_a_person_recognises(conn):
    problems.record(conn, "a", endpoint="person_digest", kind="ValueError")
    assert problems.recent(conn)[0].where == "a digest"


def test_an_unknown_route_still_says_something(conn):
    """A route added later must not render an empty gap on the page."""
    problems.record(conn, "a", endpoint="something_new", kind="ValueError")
    assert problems.recent(conn)[0].where == "somewhere in the interface"


def test_the_newest_problem_is_first(conn):
    for reference in ("one", "two", "three"):
        problems.record(conn, reference, endpoint="capture", kind="ValueError")
    assert [p.reference for p in problems.recent(conn)][0] == "three"


def test_old_problems_are_dropped_so_a_crash_loop_cannot_fill_the_database(conn,
                                                                          monkeypatch):
    monkeypatch.setattr(problems, "KEEP", 5)
    for index in range(12):
        problems.record(conn, f"ref{index}", endpoint="capture", kind="ValueError")

    assert problems.count(conn) == 5
    assert problems.recent(conn)[0].reference == "ref11"


def test_references_do_not_repeat():
    assert len({problems.new_reference() for _ in range(500)}) == 500


# ── what reaches the browser ─────────────────────────────────────────────────


def test_a_failure_shows_a_reference_and_not_the_message(client, monkeypatch):
    break_verify(monkeypatch)
    sign_in(client)

    response = get(client, "/verify")
    page = text_of(response)

    assert response.status_code == 500
    assert "note text that must not escape" not in page
    assert "RuntimeError" not in page  # not even the class, on the error page
    assert re.search(r"[0-9a-f]{8}", page), "no reference to quote"


def test_the_reference_on_the_page_is_the_one_that_was_recorded(client, monkeypatch, dek):
    break_verify(monkeypatch)
    sign_in(client)
    page = text_of(get(client, "/verify"))

    shown = re.search(r"\b([0-9a-f]{8})\b", page).group(1)
    conn = db.connect(notes_db_path(), dek)
    try:
        assert [p.reference for p in problems.recent(conn)] == [shown]
        assert problems.recent(conn)[0].kind == "RuntimeError"
    finally:
        conn.close()


def test_the_recorded_kind_is_the_real_fault_not_flasks_wrapper(client, monkeypatch, dek):
    """Flask hands the handler an InternalServerError wrapping what failed.
    Recording the wrapper would say nothing at all."""
    break_verify(monkeypatch)
    sign_in(client)
    get(client, "/verify")

    conn = db.connect(notes_db_path(), dek)
    try:
        assert problems.recent(conn)[0].kind == "RuntimeError"
    finally:
        conn.close()


def test_the_reference_names_a_log_line_that_holds_the_traceback(client, monkeypatch,
                                                                 caplog):
    """The whole value of a reference is the join. Logging Flask's wrapper
    instead of the original put the reference on a line whose traceback stops
    inside Flask's dispatch and says nothing about what actually failed."""
    import logging

    break_verify(monkeypatch)
    sign_in(client)
    with caplog.at_level(logging.ERROR):
        page = text_of(get(client, "/verify"))

    shown = re.search(r"\b([0-9a-f]{8})\b", page).group(1)
    tagged = [record for record in caplog.records if shown in record.getMessage()]
    assert tagged, "nothing in the log carries the reference the page showed"

    logged = "\n".join(record.exc_text or
                        logging.Formatter().formatException(record.exc_info)
                        for record in tagged if record.exc_info)
    assert "RuntimeError" in logged
    assert "note text that must not escape" in logged, (
        "the log line must hold what the page could not show")


def test_the_problems_page_lists_it_without_the_details(client, monkeypatch):
    break_verify(monkeypatch)
    sign_in(client)
    get(client, "/verify")

    page = text_of(get(client, "/problems"))
    assert "Something failed on checking the record" in page
    assert "note text that must not escape" not in page


def test_the_problems_page_is_behind_the_passphrase(client):
    response = get(client, "/problems")
    assert response.status_code == 302
    assert "/signin" in response.headers["Location"]


def test_an_empty_problems_page_does_not_look_broken(client):
    sign_in(client)
    assert "Nothing has gone wrong" in text_of(get(client, "/problems"))


def test_a_failure_while_locked_still_gives_a_reference(client, monkeypatch):
    """The record cannot be written to when it is sealed, and the page must
    still be useful — the log has it either way.

    The capture page is the one that works while locked, which makes it the one
    place this branch can be reached at all.
    """
    def explode(*args, **kwargs):
        raise RuntimeError("boom")
    monkeypatch.setattr("web.views.capture.render_template", explode)

    response = client.get("/", environ_overrides=TAILSCALE)
    page = text_of(response)

    assert response.status_code == 500
    assert re.search(r"[0-9a-f]{8}", page), "no reference to quote"
    assert "could not be written down" in page
    assert "boom" not in page


def test_recording_a_problem_never_replaces_the_error_page(client, monkeypatch):
    """An error handler that raises leaves the browser with no page at all —
    the one outcome worse than the error it was reporting."""
    break_verify(monkeypatch)
    monkeypatch.setattr(problems, "record",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("also broken")))
    sign_in(client)

    response = get(client, "/verify")
    assert response.status_code == 500
    assert "Something went wrong" in text_of(response)
