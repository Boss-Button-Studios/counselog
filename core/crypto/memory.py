"""Holding a key in memory that cannot be written to disk.

This machine has 119 GB of unencrypted swap. A key sitting in ordinary memory
can be paged out to it in plaintext and survive a power-off — which defeats the
one property the whole design exists to protect: that a stolen disk is inert
ciphertext.

`mlock` pins the pages holding the key so the kernel may not swap them.

**What this does not fix.** The DEK is handed to SQLCipher as a hex string in a
PRAGMA, and Python makes transient copies of strings that no amount of care here
can pin. This narrows the window; it does not close it. The durable fix is
encrypting swap at the system level, which is outside this program. Said plainly
in SECURITY.md rather than left for someone to assume.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os

_PAGE_SIZE = os.sysconf("SC_PAGESIZE")


def _libc() -> "ctypes.CDLL | None":
    name = ctypes.util.find_library("c")
    if not name:
        return None
    try:
        return ctypes.CDLL(name, use_errno=True)
    except OSError:
        return None


class LockedBuffer:
    """A mutable byte buffer that the kernel is asked not to swap out.

    Not a security boundary on its own — anything running as this user can still
    read the process's memory. It closes one specific hole: the key reaching a
    disk that outlives the process.
    """

    def __init__(self, data: bytes) -> None:
        self._size = len(data)
        self._buffer = ctypes.create_string_buffer(bytes(data), self._size)
        self._locked = False
        self._lock_error: str | None = None
        self._lock()

    def _range(self) -> tuple[int, int]:
        """The page-aligned range covering this buffer.

        Linux rounds down for you, but doing it explicitly keeps the behaviour
        obvious and portable to systems that require alignment.
        """
        address = ctypes.addressof(self._buffer)
        start = address & ~(_PAGE_SIZE - 1)
        length = (address - start) + self._size
        return start, length

    def _lock(self) -> None:
        libc = _libc()
        if libc is None:
            self._lock_error = "C library unavailable"
            return
        start, length = self._range()
        if libc.mlock(ctypes.c_void_p(start), ctypes.c_size_t(length)) == 0:
            self._locked = True
            return
        # Usually RLIMIT_MEMLOCK. Carry on rather than refusing to run: an
        # unlocked key is exactly the situation before this existed, and a tool
        # that will not start protects nothing (Law 6).
        self._lock_error = os.strerror(ctypes.get_errno())

    @property
    def locked(self) -> bool:
        """Whether the key is genuinely pinned. Surfaced by `doctor`."""
        return self._locked

    @property
    def lock_error(self) -> str | None:
        return self._lock_error

    def bytes(self) -> bytes:
        """A copy of the contents.

        Returning a copy is unavoidable — Python has no borrowed view of bytes —
        and that copy is not locked. Callers should hold it as briefly as they
        can.
        """
        if self._buffer is None:
            raise ValueError("This buffer has been cleared.")
        return bytes(self._buffer.raw[:self._size])

    def clear(self) -> None:
        """Overwrite and release. Safe to call more than once."""
        if self._buffer is None:
            return
        ctypes.memset(ctypes.addressof(self._buffer), 0, self._size)
        if self._locked:
            libc = _libc()
            if libc is not None:
                start, length = self._range()
                libc.munlock(ctypes.c_void_p(start), ctypes.c_size_t(length))
            self._locked = False
        self._buffer = None

    def __len__(self) -> int:
        return self._size

    def __repr__(self) -> str:
        state = "cleared" if self._buffer is None else \
                ("locked" if self._locked else "NOT locked")
        return f"<LockedBuffer {self._size} bytes, {state}>"
