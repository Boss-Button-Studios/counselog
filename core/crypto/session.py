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

from core.crypto.memory import LockedBuffer

DEFAULT_TTL_SECONDS = 900  # 15 minutes of inactivity

# However much work is in flight, a borrowed key is handed back eventually.
# Without this, renewing on every use would let a busy session live forever,
# which is exactly the property the TTL exists to prevent.
MAX_LIFETIME_SECONDS = 3600  # 1 hour


class SessionExpired(Exception):
    """The key was held past its expiry and has been discarded."""


class SessionClosed(Exception):
    """The key was explicitly discarded."""


class DekSession:
    """Holds a DEK in memory for a bounded time.

    On the honesty of wiping: `close()` overwrites the buffer, which removes the
    obvious copy. It cannot promise the key is gone from the machine — Python
    may have copied the bytes during earlier operations.

    The buffer is `mlock`ed so the kernel may not page it to swap. That matters
    here more than it sounds: this machine's swap is unencrypted, so without it
    a key held in memory can reach a disk that outlives the process. See
    core/crypto/memory.py for what that does and does not fix.
    """

    def __init__(self, dek: bytes, ttl_seconds: float = DEFAULT_TTL_SECONDS,
                 max_lifetime: float = MAX_LIFETIME_SECONDS) -> None:
        if ttl_seconds <= 0:
            raise ValueError("A session TTL must be positive.")
        # Pinned out of swap, and overwritable in place.
        self._buffer = LockedBuffer(dek)
        self._ttl = float(ttl_seconds)
        # Monotonic, so a clock change cannot extend a session.
        started = time.monotonic()
        self._expires_at = started + self._ttl
        self._deadline = started + max(float(max_lifetime), self._ttl)
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
        return self._buffer.bytes()

    @property
    def expired(self) -> bool:
        now = time.monotonic()
        return now >= self._expires_at or now >= self._deadline

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
        # Never past the absolute deadline: renewal extends an active session,
        # it does not make one immortal.
        self._expires_at = min(time.monotonic() + self._ttl, self._deadline)

    @property
    def memory_locked(self) -> bool:
        """Whether the key is genuinely pinned out of swap. Reported by doctor."""
        return self._buffer.locked if not self._closed else False

    @property
    def lock_error(self) -> str | None:
        return self._buffer.lock_error if not self._closed else None

    def close(self) -> None:
        """Discard the key. Safe to call more than once."""
        if not self._closed:
            self._buffer.clear()
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
