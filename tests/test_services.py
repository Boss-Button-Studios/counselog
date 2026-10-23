"""deploy/install-user-services: the two systemd user units it writes.

Run with --no-start into a temporary folder, so nothing is installed or
started on the machine running the tests.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "deploy" / "install-user-services"
UNITS = ("counselog-web.service", "counselog-desktop.service")


@pytest.fixture
def installed(tmp_path):
    units, data = tmp_path / "units", tmp_path / "data"
    result = subprocess.run(
        [str(SCRIPT), "--no-start"], capture_output=True, text=True,
        env={**os.environ, "COUNSELOG_UNIT_DIR": str(units), "COUNSELOG_HOME": str(data)})
    assert result.returncode == 0, result.stderr
    return units, data


@pytest.mark.parametrize("unit", UNITS)
def test_a_unit_runs_this_checkouts_wrapper(installed, unit):
    units, _ = installed
    text = (units / unit).read_text()
    assert "@" not in text.replace("%h", ""), "a placeholder was left unfilled"
    exec_start = next(line for line in text.splitlines() if line.startswith("ExecStart="))
    wrapper = Path(exec_start.removeprefix("ExecStart="))
    assert wrapper.parent == REPO and os.access(wrapper, os.X_OK)


@pytest.mark.parametrize("unit", UNITS)
def test_a_unit_may_write_only_to_the_data_folder(installed, unit):
    units, data = installed
    text = (units / unit).read_text()
    for setting in ("NoNewPrivileges=yes", "ProtectSystem=strict",
                    "ProtectHome=read-only", f"ReadWritePaths={data}"):
        assert setting in text.splitlines()


def test_the_data_folder_is_created_owner_only(installed):
    _, data = installed
    assert data.stat().st_mode & 0o777 == 0o700


@pytest.mark.skipif(not shutil.which("systemd-analyze"), reason="no systemd-analyze")
@pytest.mark.parametrize("unit", UNITS)
def test_systemd_accepts_the_unit(installed, unit):
    units, _ = installed
    result = subprocess.run(["systemd-analyze", "--user", "verify", str(units / unit)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_an_unknown_argument_is_refused(tmp_path):
    result = subprocess.run([str(SCRIPT), "--start-everything"], capture_output=True,
                            text=True, env={**os.environ,
                                            "COUNSELOG_UNIT_DIR": str(tmp_path)})
    assert result.returncode == 2 and not list(tmp_path.iterdir())
