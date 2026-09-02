"""Writing a note. The one thing that must work at any moment, in any state.

Two paths, and the split is exactly the security boundary:

  - **Signed in.** The key is here, so the note goes straight into the record.
    Nothing is gained by routing it through a sealed file first.
  - **Locked.** There is no key, so the note is sealed to the spool's public key
    and set aside. The browser stamps it on the way out, and the next sign-in
    decides whether to believe it.

The page is the same either way, and so is the box you type in. Which path a
note took is shown afterwards, because a note that will be held for review is
something the writer should hear about while they still remember writing it.
"""

from __future__ import annotations

from flask import (
    g,
    redirect,
    render_template,
    request,
    session as cookie,
    url_for,
)

from core import db, devices, intake, models, spool
from core.sanitize import normalize_newlines
from core.paths import notes_db_path, spool_db_path
from web.access import open_database, sessions_of
from web.sessions import NotSignedIn
from web.views.auth import take_intake_summary

WROTE_COOKIE = "wrote"
MAX_NOTE_CHARS = spool.MAX_NOTE_CHARS


def register(app) -> None:

    @app.get("/")
    def home():
        """The capture box, and nothing above it.

        This is the page a phone opens to. Anything that pushes the textarea
        below the fold makes the tool slower than a scrap of paper, which is the
        only competitor that matters.
        """
        return render_template(
            "capture.html",
            caller=g.caller,
            text="",
            error=None,
            wrote=cookie.pop(WROTE_COOKIE, None),
            intake_summary=take_intake_summary(),
            can_seal=_sealing_is_possible(),
            database_present=notes_db_path().exists(),
        )

    @app.post("/write")
    def write():
        # Normalised before anything else touches it. A form submission turns
        # every newline in a textarea into CRLF, and the browser stamped the
        # text as it held it — so without this, every multi-line note written
        # while locked would fail its check and be held for review.
        text = normalize_newlines(request.form.get("text") or "")

        def refuse(message: str, status: int = 400):
            return render_template(
                "capture.html", caller=g.caller, text=text, error=message,
                wrote=None, intake_summary={},
                can_seal=_sealing_is_possible(),
                database_present=notes_db_path().exists(),
            ), status

        if not text.strip():
            return refuse("Write something first.")
        if len(text) > MAX_NOTE_CHARS:
            return refuse("That note is longer than this can take. "
                          "Split it into a few notes.")

        try:
            dek = sessions_of().key(cookie.get("sid"))
        except NotSignedIn:
            dek = None

        if dek is not None:
            g.dek = dek
            try:
                outcome = _file_directly(text)
            except db.DatabaseError:
                # Signed in, but there is nothing to write into. Never echo the
                # underlying message: it carries a path.
                return refuse("There is no notes database on this machine yet. "
                              "Run `counselog init` first.", 503)
        else:
            outcome = _seal_for_later(text, request.form)
        if outcome is None:
            return refuse("This machine cannot hold a note written while locked "
                          "yet. Sign in once to set that up.", 503)

        # Redirect after posting so a refresh does not write the note twice.
        cookie[WROTE_COOKIE] = outcome
        return redirect(url_for("home"))


def _file_directly(text: str) -> dict:
    """Store the note in the record now, because the key is in hand."""
    conn = open_database()
    try:
        models.add_note(conn, text)
    finally:
        conn.close()
    return {"where": "record"}


def _seal_for_later(text: str, form) -> dict | None:
    """Seal the note to the spool. Returns None if this machine cannot yet.

    Everything the browser sends is treated as a claim, not a fact. A device id
    that is not one of ours, a stamp that is not the right shape, a timestamp
    that is not the one form we accept: none of these are refused, because
    refusing would throw away a note someone just wrote. They are normalised to
    something the drain will recognise as unstamped, and the writer is told the
    note will be held for review.
    """
    try:
        public = intake.published_key()
    except intake.IntakeError:
        return None

    device_id = form.get("device") or ""
    mac_hex = form.get("mac") or ""
    stamped = devices.is_device_id(device_id) and devices.is_mac_hex(mac_hex)

    captured_at = form.get("captured_at") or ""
    if not devices.is_captured_at(captured_at):
        # A browser that ran the script always sends the right shape, so this is
        # a browser that did not. Our clock is the honest answer, and the note
        # would be held for review anyway.
        captured_at = spool.utc_now()
        stamped = False

    conn = spool.connect(spool_db_path())
    try:
        spool.append(
            conn, public,
            text=text,
            captured_at=captured_at,
            device_id=device_id if stamped else devices.UNSTAMPED,
            mac=bytes.fromhex(mac_hex) if stamped else b"\x00" * 32,
        )
    finally:
        conn.close()
    return {"where": "spool", "stamped": stamped}


def _sealing_is_possible() -> bool:
    """Can a note be written while locked on this machine yet?

    False on a fresh install until someone signs in once, because the keypair is
    made with the database open. The page says so rather than presenting a box
    that would fail on submit (Guideline 2).
    """
    try:
        intake.published_key()
    except intake.IntakeError:
        return False
    return True


__all__ = ["register", "MAX_NOTE_CHARS"]
