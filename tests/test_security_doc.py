"""SECURITY.md has to stay true, and the numbers in it are the part that rots.

Every contributor is told to read that file before touching `core/crypto/`, so a
stale figure in it is worse than no figure: it is a claim about the system that
someone will rely on while changing the system. These tests fail when the code
moves and the document does not.

Only load-bearing values are checked — the ones a reader would act on. Prose is
not testable and is not tested; what is tested is that the document still says
the things it must never stop saying.
"""

import pathlib
import re

import pytest

from core.crypto.factors import PasswordFactor
from core.crypto.signing import ALGORITHM
from core.devices import SECRET_BYTES
from web.ratelimit import LOCKOUT_SECONDS, MAX_ATTEMPTS, MAX_CONCURRENT, WINDOW_SECONDS
from web.sessions import DEFAULT_ABSOLUTE_SECONDS, DEFAULT_IDLE_SECONDS

DOC = pathlib.Path(__file__).resolve().parent.parent / "SECURITY.md"


@pytest.fixture(scope="module")
def text() -> str:
    assert DOC.exists(), "CLAUDE.md tells everyone to read this file before touching crypto"
    return DOC.read_text(encoding="utf-8")


# ── the numbers ──────────────────────────────────────────────────────────────


def test_the_scrypt_parameters_match_the_code(text):
    assert f"n = 2^{PasswordFactor.SCRYPT_N.bit_length() - 1}" in text
    assert f"r = {PasswordFactor.SCRYPT_R}" in text
    assert f"p = {PasswordFactor.SCRYPT_P}" in text


def test_the_session_timeouts_match_the_code(text):
    assert f"**{int(DEFAULT_IDLE_SECONDS / 60)} minutes idle**" in text
    assert f"**{int(DEFAULT_ABSOLUTE_SECONDS / 60)} minutes absolute**" in text


def test_the_sign_in_limits_match_the_code(text):
    assert f"capped at {MAX_CONCURRENT}" in text
    assert f"{MAX_ATTEMPTS} attempts per {int(WINDOW_SECONDS / 60)} minutes" in text
    assert f"{int(LOCKOUT_SECONDS)}-second lockout" in text


def test_the_device_secret_size_matches_the_code(text):
    assert f"{SECRET_BYTES}-byte secret in `localStorage`" in text


def test_the_signature_algorithm_matches_the_code(text):
    """The document names the curve and hash; the code names the same pair."""
    assert ALGORITHM == "ecdsa-p256-sha256"
    assert "ECDSA P-256 over SHA-256" in text


# ── the claims that must never quietly disappear ─────────────────────────────


@pytest.mark.parametrize("claim", [
    "does not prove",
    "only the order in which they were written down",
    "only when it was signed",
    "Every note written since is vouched for by nobody",
    "record is covered",  # the doc emphasises "whole", so match around it
])
def test_the_limits_of_the_record_are_still_stated(text, claim):
    """Each of these is a thing a reader would otherwise assume. Losing any of
    them turns this document into reassurance."""
    assert claim in text


@pytest.mark.parametrize("claim", [
    "outside the encryption boundary",
    "Erasure cannot be guaranteed",
    "has not been run against",
    "A bin the model missed is caught only if someone checks",
    "sees note text in memory",
])
def test_the_known_gaps_are_still_admitted(text, claim):
    """A threat model listing only what is handled is marketing."""
    assert claim in text


def test_it_does_not_claim_the_loopback_check_stops_a_local_process(text):
    """It cannot, and `web/identity.py` says so in its own comment. An earlier
    draft of this file implied otherwise, which is the kind of overstatement a
    threat model exists to prevent."""
    assert "can also reach loopback and set those headers itself" in text
