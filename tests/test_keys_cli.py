"""Phase 1: the `counselog keys` commands.

These drive the CLI the way a person does, because the dangerous mistakes here
are interaction mistakes — revoking the wrong thing, or being allowed to lock
yourself out — not cryptographic ones.
"""

import pytest
from click.testing import CliRunner

from laptop.cli import cli


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "data"))
    return tmp_path / "data"


@pytest.fixture
def run(home):
    runner = CliRunner()

    def _run(args, stdin=""):
        return runner.invoke(cli, args, input=stdin, catch_exceptions=False)

    return _run


def _init(run, password="swordfish"):
    return run(["keys", "init", "--factor", "password", "--label", "first"],
               stdin=f"{password}\n{password}\n")


def test_init_creates_a_keyring(run, home):
    result = _init(run)
    assert result.exit_code == 0
    assert (home / "keyring.json").exists()
    assert "Keyring created" in result.output


def test_init_urges_a_second_key(run):
    """One key is a single point of total failure. Say so at the moment it matters."""
    assert "losing it means losing every note" in _init(run).output


def test_init_refuses_to_clobber_an_existing_keyring(run):
    """Overwriting a keyring would orphan every note in the database."""
    _init(run)
    result = _init(run)
    assert result.exit_code != 0
    assert "already exists" in result.output


def test_add_then_unlock_with_either(run):
    _init(run, "first-pw")
    added = run(["keys", "add", "--factor", "password", "--label", "backup",
                 "--unlock-with", "password"],
                stdin="first-pw\nsecond-pw\nsecond-pw\n")
    assert added.exit_code == 0
    assert "2 ways" in added.output

    for password in ("first-pw", "second-pw"):
        result = run(["keys", "test", "--factor", "password"], stdin=f"{password}\n")
        assert result.exit_code == 0, password
        assert "Unlocked" in result.output


def test_add_requires_unlocking_first(run):
    """You cannot register a new key without proving you hold an existing one."""
    _init(run, "right")
    result = run(["keys", "add", "--factor", "password", "--label", "sneaky",
                  "--unlock-with", "password"],
                 stdin="wrong\nnew\nnew\n")
    assert result.exit_code != 0
    assert "did not unlock" in result.output


def test_test_command_reports_a_wrong_password(run):
    _init(run, "right")
    result = run(["keys", "test", "--factor", "password"], stdin="wrong\n")
    assert result.exit_code != 0
    assert "did not unlock" in result.output


def test_list_warns_when_there_is_only_one_way_in(run):
    _init(run)
    assert "Only one way in" in run(["keys", "list"]).output


def test_revoke_refuses_to_remove_the_last_key(run):
    """The lockout guard, reached through the CLI rather than the library."""
    _init(run)
    wrapper_id = _first_id(run)
    result = run(["keys", "revoke", wrapper_id], stdin="y\n")
    assert result.exit_code != 0
    assert "only way into your notes" in result.output
    assert run(["keys", "list"]).output.count("password") == 1


def test_revoke_is_honest_about_what_it_does_not_do(run):
    """Removing a wrapper is not retroactive protection. Do not imply it is."""
    _init(run, "first-pw")
    run(["keys", "add", "--factor", "password", "--label", "backup",
         "--unlock-with", "password"], stdin="first-pw\nsecond-pw\nsecond-pw\n")
    result = run(["keys", "revoke", _first_id(run)], stdin="y\n")
    assert result.exit_code == 0
    assert "does" in result.output and "not protect data" in result.output


def test_revoke_can_be_declined(run):
    _init(run, "pw")
    run(["keys", "add", "--factor", "password", "--label", "b",
         "--unlock-with", "password"], stdin="pw\nb\nb\n")
    before = run(["keys", "list"]).output
    run(["keys", "revoke", _first_id(run)], stdin="n\n")
    assert run(["keys", "list"]).output == before


def test_revoke_unknown_id_is_rejected(run):
    _init(run)
    result = run(["keys", "revoke", "notarealid"], stdin="y\n")
    assert result.exit_code != 0
    assert "No registered key" in result.output


def test_commands_explain_a_missing_keyring(run):
    """A new user running the wrong command first should be told what to run."""
    for args in (["keys", "list"], ["keys", "test"]):
        result = run(args)
        assert result.exit_code != 0
        assert "keys init" in result.output


def test_status_works_before_anything_is_set_up(run):
    result = run(["status"])
    assert result.exit_code == 0
    assert "not set up" in result.output


def test_counts_are_pluralised(run):
    _init(run, "pw")
    assert "1 ways" not in run(["keys", "list"]).output
    added = run(["keys", "add", "--factor", "password", "--label", "b",
                 "--unlock-with", "password"], stdin="pw\nb\nb\n")
    assert "2 ways" in added.output


def _first_id(run) -> str:
    """The id in the first data row of `keys list`."""
    return run(["keys", "list"]).output.splitlines()[1].split()[0]
