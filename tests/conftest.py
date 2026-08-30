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
