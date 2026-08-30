"""Custody of the database key the laptop lends this machine.

This is the mechanism that lets a headless box hold an encrypted mirror without
holding a way to open it. The key arrives over mutual TLS, lives in memory for a
bounded time, and is never written anywhere. Reboot the desktop, or wait out the
timeout, and the mirror is ciphertext again (spec §6).

Anything that weakens that — persisting a session, extending it indefinitely —
undoes the reason the desktop is allowed to keep a copy at all.
"""

from __future__ import annotations

import secrets
import threading

from core.crypto import DekSession, SessionClosed, SessionExpired


class NoSuchSession(Exception):
    """The session id is unknown, expired, or already closed."""


class SessionStore:
    """In-memory sessions, keyed by an unguessable id.

    Guarded by a lock because the service handles requests on threads; two
    requests arriving together must not corrupt the table.
    """

    def __init__(self) -> None:
        self._sessions: dict[str, tuple[str, DekSession]] = {}
        self._lock = threading.Lock()

    def open(self, device: str, dek: bytes, ttl_seconds: float) -> str:
        session_id = secrets.token_urlsafe(24)
        with self._lock:
            self._prune()
            self._sessions[session_id] = (device, DekSession(dek, ttl_seconds))
        return session_id

    def key_for(self, session_id: str, device: str) -> bytes:
        """The key for this session, if it belongs to this device.

        Checking the device matters: mutual TLS proves who is connecting, and a
        session id leaked to another enrolled device should not let that device
        read notes. The certificate and the session must agree.
        """
        with self._lock:
            entry = self._sessions.get(session_id)
            if entry is None:
                raise NoSuchSession("No such session. Unlock and try again.")
            owner, session = entry
            if owner != device:
                # Do not confirm the session exists to the wrong device.
                raise NoSuchSession("No such session. Unlock and try again.")
            try:
                return session.dek
            except (SessionExpired, SessionClosed) as exc:
                self._sessions.pop(session_id, None)
                raise NoSuchSession(str(exc)) from exc

    def close(self, session_id: str, device: str) -> bool:
        with self._lock:
            entry = self._sessions.get(session_id)
            if entry is None or entry[0] != device:
                return False
            entry[1].close()
            del self._sessions[session_id]
            return True

    def close_all(self) -> None:
        """Drop every key. Called on shutdown."""
        with self._lock:
            for _, session in self._sessions.values():
                session.close()
            self._sessions.clear()

    def _prune(self) -> None:
        """Discard expired sessions rather than waiting to be asked for them."""
        for session_id, (_, session) in list(self._sessions.items()):
            if session.expired:
                session.close()
                del self._sessions[session_id]

    def __len__(self) -> int:
        with self._lock:
            self._prune()
            return len(self._sessions)
