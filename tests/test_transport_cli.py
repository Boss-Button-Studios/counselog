"""Phase 3: the certs, doctor, and sync commands.

Covers the setup path a person actually walks: make certificates, check the
link, send notes.
"""

import threading

import pytest
from click.testing import CliRunner
from werkzeug.serving import make_server

from core import db, models
from core.certs import CertPaths, server_context
from core.paths import mirror_db_path
from desktop.__main__ import MutualTLSRequestHandler
from desktop import mirror
from desktop.service import create_app
from desktop.sessions import SessionStore
from laptop.cli import cli

PASSWORD = "swordfish"


@pytest.fixture
def env(tmp_path, monkeypatch):
    # Point at a settings file that does not exist, so a real .env on this
    # machine cannot change what these tests see.
    monkeypatch.setenv("COUNSELOG_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "data"))
    monkeypatch.setenv("COUNSELOG_CERTS", str(tmp_path / "certs"))
    monkeypatch.setenv("COUNSELOG_DESKTOP_HOST", "localhost")
    monkeypatch.delenv("COUNSELOG_DESKTOP_IPS", raising=False)
    return tmp_path


@pytest.fixture
def run(env):
    runner = CliRunner()

    def _run(args, stdin=""):
        return runner.invoke(cli, args, input=stdin, catch_exceptions=False)

    return _run


@pytest.fixture
def with_notes(run):
    run(["keys", "init", "--factor", "password", "--label", "t"],
        stdin=f"{PASSWORD}\n{PASSWORD}\n")
    run(["init", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    for text in ("first note", "second note"):
        run(["note", "-m", text, "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    return run


# ── certs ────────────────────────────────────────────────────────────────────


def test_certs_init_creates_the_authority(run, env):
    result = run(["certs", "init"])
    assert result.exit_code == 0
    paths = CertPaths(env / "certs")
    for path in (paths.ca_cert, paths.ca_key, paths.cert("server"),
                 paths.key("server"), paths.cert("laptop"), paths.key("laptop")):
        assert path.exists(), path


def test_certs_init_warns_about_the_private_keys(run):
    """ca.key and server.key must never leave the desktop."""
    output = run(["certs", "init"]).output
    assert "Do not copy ca.key or server.key" in output


def test_certs_init_refuses_to_silently_replace(run):
    """Re-running would lock out every device already enrolled."""
    run(["certs", "init"])
    result = run(["certs", "init"])
    assert result.exit_code != 0
    assert "lock out" in result.output


def test_certs_init_warns_when_no_desktop_is_configured(run, monkeypatch):
    monkeypatch.setenv("COUNSELOG_DESKTOP_HOST", "localhost")
    assert "loopback only" in run(["certs", "init"]).output


def test_enrolling_a_second_device(run, env):
    run(["certs", "init"])
    result = run(["certs", "enroll", "phone"])
    assert result.exit_code == 0
    assert CertPaths(env / "certs").cert("phone").exists()


def test_enrolling_twice_is_refused(run):
    run(["certs", "init"])
    run(["certs", "enroll", "phone"])
    assert run(["certs", "enroll", "phone"]).exit_code != 0


# ── doctor ───────────────────────────────────────────────────────────────────


def test_doctor_says_to_make_certificates_first(run):
    result = run(["doctor"])
    assert result.exit_code != 0
    assert "certs init" in result.output


def test_doctor_reports_an_unreachable_desktop(run, monkeypatch):
    """Point at a port nothing is bound to, so the result does not depend on
    whatever else happens to be listening on this machine."""
    import socket
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        free_port = probe.getsockname()[1]
    monkeypatch.setenv("COUNSELOG_PORT", str(free_port))

    run(["certs", "init"])
    result = run(["doctor", "--loopback"])
    assert result.exit_code != 0
    assert "counselogd running" in result.output


# ── sync, against a real service ─────────────────────────────────────────────


@pytest.fixture
def live_desktop(run, env, monkeypatch):
    """A real TLS service, on the port the CLI will dial."""
    run(["certs", "init"])
    server = make_server("127.0.0.1", 0, create_app(SessionStore()), threaded=True,
                         ssl_context=server_context(CertPaths(env / "certs")),
                         request_handler=MutualTLSRequestHandler)
    monkeypatch.setenv("COUNSELOG_PORT", str(server.server_port))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=5)


def test_doctor_passes_against_a_live_desktop(with_notes, live_desktop):
    result = with_notes(["doctor", "--loopback"])
    assert result.exit_code == 0
    assert "it sees us as 'laptop'" in result.output


def test_sync_sends_notes_to_the_mirror(with_notes, live_desktop):
    result = with_notes(["sync", "--loopback", "--unlock-with", "password"],
                        stdin=f"{PASSWORD}\n")
    assert result.exit_code == 0, result.output
    assert "Sent 2 note(s)" in result.output


def test_sync_discloses_what_leaves_the_machine(with_notes, live_desktop):
    """Law 2: say what is going where, every time, in one line."""
    output = with_notes(["sync", "--loopback", "--unlock-with", "password"],
                        stdin=f"{PASSWORD}\n").output
    assert "Sending note text to" in output
    assert "mutually authenticated" in output


def test_sync_says_the_key_was_handed_back(with_notes, live_desktop):
    output = with_notes(["sync", "--loopback", "--unlock-with", "password"],
                        stdin=f"{PASSWORD}\n").output
    assert "handed back" in output


def test_syncing_twice_sends_nothing_the_second_time(with_notes, live_desktop):
    with_notes(["sync", "--loopback", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    again = with_notes(["sync", "--loopback", "--unlock-with", "password"],
                       stdin=f"{PASSWORD}\n")
    assert "Nothing new to send" in again.output


def test_only_new_notes_are_sent(with_notes, live_desktop):
    with_notes(["sync", "--loopback", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    with_notes(["note", "-m", "a third note", "--unlock-with", "password"],
               stdin=f"{PASSWORD}\n")
    result = with_notes(["sync", "--loopback", "--unlock-with", "password"],
                        stdin=f"{PASSWORD}\n")
    assert "Sent 1 note(s)" in result.output


def test_the_mirror_holds_a_verifiable_copy(with_notes, live_desktop):
    """Both machines end up with the same history, independently checkable."""
    with_notes(["sync", "--loopback", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")

    from core.crypto import Keyring, PasswordFactor
    from core.paths import keyring_path, notes_db_path
    dek = Keyring.load(keyring_path()).unlock(PasswordFactor(PASSWORD))

    copy = db.connect(mirror_db_path(), dek)
    laptop = db.connect(notes_db_path(), dek)
    try:
        assert mirror.verify(copy).ok
        assert [e.entry_hash for e in models.chain_entries(copy)] == \
               [e.entry_hash for e in models.chain_entries(laptop)]
    finally:
        copy.close()
        laptop.close()


def test_sync_needs_a_database(run, live_desktop):
    run(["keys", "init", "--factor", "password", "--label", "t"],
        stdin=f"{PASSWORD}\n{PASSWORD}\n")
    result = run(["sync", "--loopback", "--unlock-with", "password"], stdin=f"{PASSWORD}\n")
    assert result.exit_code != 0
    assert "counselog init" in result.output
