"""The ./counselog and ./counselogd shell wrappers.

A wrapper that silently falls back to an interpreter without the dependencies
produces a ModuleNotFoundError from deep inside an import chain, which tells the
user nothing about what went wrong or what to do. That happened on a real
machine, so it is pinned here.
"""

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
WRAPPERS = ("counselog", "counselogd")


@pytest.mark.parametrize("wrapper", WRAPPERS)
def test_the_wrapper_is_executable(wrapper):
    assert os.access(REPO / wrapper, os.X_OK)


@pytest.mark.parametrize("wrapper", WRAPPERS)
def test_an_unprepared_machine_gets_instructions_not_a_traceback(wrapper, tmp_path):
    """Simulate a fresh clone: no venv, and a python without the dependencies."""
    shutil.copy2(REPO / wrapper, tmp_path / wrapper)

    # A stub interpreter that fails the dependency probe but can still report a
    # version, standing in for a system python that has never had pip run on it.
    bindir = tmp_path / "bin"
    bindir.mkdir()
    stub = bindir / "python3"
    stub.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        '  *"import sqlcipher3"*) exit 1 ;;\n'
        '  *version_info*) echo "3.11" ;;\n'
        '  *) exit 1 ;;\n'
        "esac\n"
    )
    stub.chmod(stub.stat().st_mode | stat.S_IEXEC)

    result = subprocess.run(
        [str(tmp_path / wrapper), "doctor"],
        capture_output=True, text=True,
        env={**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}"},
    )

    assert result.returncode == 1
    assert "Traceback" not in result.stderr
    assert "ModuleNotFoundError" not in result.stderr
    # It must say what to run, and mention the version requirement.
    assert "python3 -m venv .venv" in result.stderr
    assert "pip install -e ." in result.stderr
    assert "3.12" in result.stderr


@pytest.mark.parametrize("wrapper", WRAPPERS)
def test_yubikey_setup_is_described_as_a_separate_step(wrapper, tmp_path):
    """Its build dependencies are the most likely thing to block a new machine,
    and only a machine with a key needs it at all."""
    text = (REPO / wrapper).read_text()
    assert "libpcsclite-dev" in text
    assert '".[yubikey]"' in text
