"""Custody of the database key while someone is signed in.

The desktop is now where notes live, so the key is held for as long as a reading
session lasts rather than the seconds a sync took. Three things keep that window
short:

  - idle timeout, refreshed by use
  - an absolute cap that renewal cannot push past
  - the key is dropped entirely once the last session ends

Capture does not need any of this — a note can be written while locked, which is
what makes a five-minute idle timeout livable rather than infuriating.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass

from core.crypto import DekSession, SessionClosed, SessionExpired

DEFAULT_IDLE_SECONDS = 300      # 5 minutes
DEFAULT_ABSOLUTE_SECONDS = 1800  # 30 minutes


class NotSignedIn(Exception):
    """No usable session: absent, expired, or locked."""


@dataclass
class SessionInfo:
    """What the interface may say about a session. Never the key."""

    caller: str
    created_at: float
    idle_remaining: float
    absolute_remaining: float
    memory_locked: bool


class BrowserSessions:
    """Server-side sessions, keyed by an unguessable id kept in a cookie.

    Locked because Flask serves on threads: two requests arriving together must
    not corrupt the table.
    """

    def __init__(self, idle_seconds: float = DEFAULT_IDLE_SECONDS,
                 absolute_seconds: float = DEFAULT_ABSOLUTE_SECONDS) -> None:
        self._idle = idle_seconds
        self._absolute = absolute_seconds
        self._sessions: dict[str, tuple[str, DekSession, float]] = {}
        self._lock = threading.Lock()

    def sign_in(self, caller: str, dek: bytes) -> str:
        session_id = secrets.token_urlsafe(32)
        with self._lock:
            self._prune()
            self._sessions[session_id] = (
                caller,
                DekSession(dek, ttl_seconds=self._idle, max_lifetime=self._absolute),
                time.monotonic(),
            )
        return session_id

    def key(self, session_id: str | None) -> bytes:
        """The database key for a live session, refreshing its idle timer."""
        if not session_id:
            raise NotSignedIn("Sign in to read your notes.")
        with self._lock:
            entry = self._sessions.get(session_id)
            if entry is None:
                raise NotSignedIn("Your session has ended. Sign in again.")
            _, session, _ = entry
            try:
                dek = session.dek
                session.renew()
                return dek
            except (SessionExpired, SessionClosed) as exc:
                self._drop(session_id)
                raise NotSignedIn(str(exc)) from exc

    def info(self, session_id: str | None) -> SessionInfo | None:
        with self._lock:
            entry = self._sessions.get(session_id or "")
            if entry is None:
                return None
            caller, session, created = entry
            if session.expired:
                self._drop(session_id or "")
                return None
            return SessionInfo(
                caller=caller,
                created_at=created,
                idle_remaining=session.seconds_remaining,
                absolute_remaining=max(0.0, self._absolute - (time.monotonic() - created)),
                memory_locked=session.memory_locked,
            )

    def sign_out(self, session_id: str | None) -> bool:
        with self._lock:
            if not session_id or session_id not in self._sessions:
                return False
            self._drop(session_id)
            return True

    def lock_all(self) -> int:
        """Drop every key at once — the Lock button, suspend, and shutdown."""
        with self._lock:
            count = len(self._sessions)
            for session_id in list(self._sessions):
                self._drop(session_id)
            return count

    def any_open(self) -> bool:
        with self._lock:
            self._prune()
            return bool(self._sessions)

    def _drop(self, session_id: str) -> None:
        """Caller must hold the lock."""
        entry = self._sessions.pop(session_id, None)
        if entry is not None:
            entry[1].close()

    def _prune(self) -> None:
        """Caller must hold the lock."""
        for session_id, (_, session, _) in list(self._sessions.items()):
            if session.expired:
                self._drop(session_id)

    def __len__(self) -> int:
        with self._lock:
            self._prune()
            return len(self._sessions)
