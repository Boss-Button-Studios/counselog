"""In-memory custody of the database key.

The DEK exists in plaintext only inside a running process, only for as long as
it is needed. This module is that "only for as long as it is needed" part: a
holder with an expiry, so a walked-away-from laptop or an idle desktop service
stops being able to read notes without anyone having to remember to lock it.

The desktop depends on this more than the laptop does. It receives the DEK over
mTLS per session and must forget it — on expiry, on shutdown, on crash. That is
what makes a stolen desktop disk inert (spec §6, and SECURITY.md).
"""

from __future__ import annotations

import time
from types import TracebackType

DEFAULT_TTL_SECONDS = 900  # 15 minutes


class SessionExpired(Exception):
    """The key was held past its expiry and has been discarded."""


class SessionClosed(Exception):
    """The key was explicitly discarded."""


class DekSession:
    """Holds a DEK in memory for a bounded time.

    On the honesty of wiping: `close()` overwrites the buffer, which removes the
    obvious copy. It cannot promise the key is gone from the machine. Python may
    have copied the bytes during earlier operations, and the OS may have paged
    them out. Treat this as reducing exposure, not eliminating it — the real
    defences are the TTL, and never writing the key to disk.
    """

    def __init__(self, dek: bytes, ttl_seconds: float = DEFAULT_TTL_SECONDS) -> None:
        if ttl_seconds <= 0:
            raise ValueError("A session TTL must be positive.")
        # bytearray, not bytes: immutable bytes cannot be overwritten in place.
        self._buffer = bytearray(dek)
        self._ttl = float(ttl_seconds)
        # Monotonic, so a clock change cannot extend a session.
        self._expires_at = time.monotonic() + self._ttl
        self._closed = False

    @property
    def dek(self) -> bytes:
        """The key, if this session is still valid.

        Checks expiry on every access rather than on a timer, so an expired
        session cannot be used even if nothing has swept it up yet.
        """
        if self._closed:
            raise SessionClosed("This session has been closed. Unlock again.")
        if self.expired:
            self.close()
            raise SessionExpired("This session has expired. Unlock again.")
        return bytes(self._buffer)

    @property
    def expired(self) -> bool:
        return time.monotonic() >= self._expires_at

    @property
    def seconds_remaining(self) -> float:
        return max(0.0, self._expires_at - time.monotonic())

    def renew(self) -> None:
        """Extend an active session. Will not resurrect an expired one."""
        if self._closed:
            raise SessionClosed("This session has been closed. Unlock again.")
        if self.expired:
            self.close()
            raise SessionExpired("This session has expired. Unlock again.")
        self._expires_at = time.monotonic() + self._ttl

    def close(self) -> None:
        """Discard the key. Safe to call more than once."""
        if not self._closed:
            for i in range(len(self._buffer)):
                self._buffer[i] = 0
            self._buffer = bytearray()
            self._closed = True

    def __enter__(self) -> "DekSession":
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.close()

    def __repr__(self) -> str:
        # Never let a key reach a log line or a traceback through repr.
        state = "closed" if self._closed else f"{self.seconds_remaining:.0f}s left"
        return f"<DekSession {state}>"
