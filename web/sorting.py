"""Sorting notes from the browser, in the background.

Sorting takes one to two minutes a note, far longer than a page can wait, so the
Sort button starts this and the page reports on it. It asks the model directly,
the same one `counselog tag` reaches through the desktop service. The browser
interface already runs on the machine with the model, so going through the
service would only mean lending the key to a second process.

**One run at a time.** The model has one GPU, and two runs would sort the same
notes twice.

**Which key it uses.** A copy lent by the session that pressed the button
(`BrowserSessions.lend`), checked before every note. The run ends when that copy
does: Stop, signing out of that session, Lock, or the end of that sign-in's
thirty minutes. A browser going idle does not end it, so you can press Sort and
put the phone down. Every note is saved as it is sorted, so a run cut short
keeps whatever it finished.

**What it remembers.** Counts and plain-words reasons only, never note text.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, replace

from core import db, filing, models
from core.crypto import DekSession, SessionClosed, SessionExpired
from core.paths import notes_db_path
from desktop import tagger

log = logging.getLogger(__name__)

LOCKED = ("Stopped because the notes were locked. Sign in and press Sort again "
          "to carry on.")
ASKED = "Stopped when asked. Press Sort again to carry on."
BROKE = ("Stopped by something unexpected. Every note sorted before it is kept. "
         "Try again, or run `counselog tag` to see more.")


class AlreadySorting(Exception):
    """A run is already going."""


@dataclass(frozen=True)
class Progress:
    """How a run is going, safe to show to anyone signed in."""

    total: int
    done: int = 0
    in_no_bin: int = 0
    running: bool = True
    # Why it ended early, in plain words. None while running and when it
    # finished everything.
    stopped_because: str | None = None
    started_at: float = 0.0


class Sorter:
    """Runs one sorting run at a time on a thread of its own."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._progress: Progress | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self, key: DekSession, note_ids: list[int]) -> None:
        """Sort these notes, in order. Takes charge of `key` and closes it."""
        with self._lock:
            if self._progress is not None and self._progress.running:
                key.close()
                raise AlreadySorting("Notes are already being sorted.")
            self._stop.clear()
            self._progress = Progress(total=len(note_ids), started_at=time.time())
            self._thread = threading.Thread(target=self._run, args=(key, list(note_ids)),
                                            name="counselog-sorting", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stop after the note being sorted now. The model cannot be
        interrupted part way, and its answer for that note is kept."""
        self._stop.set()

    def progress(self) -> Progress | None:
        with self._lock:
            return self._progress

    def join(self, timeout: float | None = None) -> None:
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def _update(self, **changes) -> None:
        with self._lock:
            self._progress = replace(self._progress, **changes)

    def _run(self, key: DekSession, note_ids: list[int]) -> None:
        reason = None
        try:
            reason = self._sort_all(key, note_ids)
        except Exception as exc:  # noqa: BLE001 — a thread has nobody to raise to
            # The type only: the message could quote a note.
            log.error("sorting stopped: %s", type(exc).__name__)
            reason = BROKE
        finally:
            key.close()
            self._update(running=False, stopped_because=reason)

    def _sort_all(self, key: DekSession, note_ids: list[int]) -> str | None:
        """Sort each note in turn. Returns why it stopped early, or None."""
        for note_id in note_ids:
            if self._stop.is_set():
                return ASKED
            try:
                note, people = self._read(key.dek, note_id)
            except (SessionClosed, SessionExpired):
                return LOCKED
            if note is None:
                # Corrected, cleared or sorted by something else since the
                # button was pressed: nothing left to do for it.
                self._update(done=self.progress().done + 1)
                continue
            try:
                sorting = tagger.sort_note(note.raw_text, people)
            except tagger.TaggingUnavailable as exc:
                return f"Stopped: {exc}"
            if not self._save(key, note_id, sorting):
                # Locked while the model was thinking. The answer is dropped
                # rather than written with a key nobody is holding any more.
                return LOCKED
            progress = self.progress()
            self._update(done=progress.done + 1,
                         in_no_bin=progress.in_no_bin + (0 if sorting.tags else 1))
        return None

    def _read(self, dek: bytes, note_id: int):
        """The note, if it still needs sorting, and the people to match."""
        conn = db.connect(notes_db_path(), dek)
        try:
            waiting = {note.id: note for note in models.unprocessed_notes(conn)}
            people = [tagger.KnownPerson(person_id=p.id, display_name=p.display_name,
                                         aliases=tuple(p.aliases))
                      for p in models.list_people(conn)]
            return waiting.get(note_id), people
        finally:
            conn.close()

    def _save(self, key: DekSession, note_id: int, sorting: tagger.Sorting) -> bool:
        try:
            dek = key.dek
        except (SessionClosed, SessionExpired):
            return False
        conn = db.connect(notes_db_path(), dek)
        try:
            filing.file_sorting(conn, note_id,
                                [(tag.bin_key, tag.confidence) for tag in sorting.tags],
                                sorting.judgements,
                                model=tagger.DEFAULT_MODEL, method=tagger.METHOD)
        finally:
            conn.close()
        return True


__all__ = ["AlreadySorting", "Progress", "Sorter"]
