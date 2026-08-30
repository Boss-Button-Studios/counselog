"""Shared fixtures."""

import contextlib
import os

import pytest


@pytest.fixture
def hushed_stderr():
    """Silence fd 2 for the duration of a block.

    SQLCipher reports decrypt failures from C directly to fd 2, so Python-level
    redirection does not catch them. Trial decryption during unlock is a normal
    path, so this guard is used in production code too — see core/db.py.
    """

    @contextlib.contextmanager
    def _hush():
        saved = os.dup(2)
        with open(os.devnull, "wb") as null:
            os.dup2(null.fileno(), 2)
        try:
            yield
        finally:
            os.dup2(saved, 2)
            os.close(saved)

    return _hush


@pytest.fixture(autouse=True)
def isolate_from_local_settings(tmp_path_factory, monkeypatch):
    """Keep a developer's real .env out of every test.

    Without this, whether a test passes depends on whether the machine running
    it happens to have a configured desktop — which is exactly the kind of
    result that cannot be trusted (Law 7).
    """
    absent = tmp_path_factory.mktemp("settings") / "absent.env"
    monkeypatch.setenv("COUNSELOG_ENV_FILE", str(absent))
