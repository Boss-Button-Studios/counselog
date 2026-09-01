"""Keeping sign-in attempts from exhausting the machine.

Deriving a key costs about 260 ms and 128 MB by design — that expense is what
makes a stolen keyring hard to attack offline. It also means a handful of
concurrent sign-in attempts would exhaust this machine's 14 GB of RAM, so the
same property that protects the notes is a way to knock the service over.

This did not matter when unlocking was a local CLI call. It matters now that
anything on the tailnet can post to a form.

Two limits, doing different jobs:

  - a **concurrency cap**, so simultaneous attempts cannot multiply the memory
    cost. This is the one that prevents the machine falling over.
  - an **attempt limit** per caller with a growing delay, so guessing is slow.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

MAX_CONCURRENT = 2
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300.0
LOCKOUT_SECONDS = 60.0


class TooManyAttempts(Exception):
    """Refused before any expensive work was done."""


@dataclass
class _Record:
    attempts: list[float] = field(default_factory=list)
    locked_until: float = 0.0


class SignInLimiter:
    def __init__(self, max_concurrent: int = MAX_CONCURRENT,
                 max_attempts: int = MAX_ATTEMPTS,
                 window: float = WINDOW_SECONDS,
                 lockout: float = LOCKOUT_SECONDS) -> None:
        self._max_attempts = max_attempts
        self._window = window
        self._lockout = lockout
        self._records: dict[str, _Record] = {}
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(max_concurrent)

    def check(self, caller: str) -> None:
        """Refuse an over-limit caller *before* any key derivation happens.

        Order matters: doing this after the derivation would mean the attack
        still costs 128 MB per attempt.
        """
        now = time.monotonic()
        with self._lock:
            record = self._records.setdefault(caller, _Record())
            if now < record.locked_until:
                wait = int(record.locked_until - now) + 1
                raise TooManyAttempts(
                    f"Too many sign-in attempts. Try again in {wait} seconds."
                )
            record.attempts = [t for t in record.attempts if now - t < self._window]
            if len(record.attempts) >= self._max_attempts:
                record.locked_until = now + self._lockout
                record.attempts.clear()
                raise TooManyAttempts(
                    f"Too many sign-in attempts. Try again in "
                    f"{int(self._lockout)} seconds."
                )
            record.attempts.append(now)

    def slot(self) -> "threading.BoundedSemaphore":
        """Context manager capping concurrent derivations.

        Blocking rather than refusing: a legitimate second sign-in should wait
        its turn, not fail.
        """
        return self._slots

    def succeeded(self, caller: str) -> None:
        """Clear the record — a correct passphrase is not an attack."""
        with self._lock:
            self._records.pop(caller, None)
