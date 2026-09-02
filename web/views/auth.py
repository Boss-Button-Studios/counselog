"""Signing in, locking, and the drain that runs between them.

Signing in is the only moment this program has both the key and a reason to use
it, so it is also where notes written while locked are taken into the record.
That coupling is deliberate: a spool that is only drained when someone
remembers to ask would quietly grow, and notes would sit outside the chain for
as long as nobody looked.
"""

from __future__ import annotations

import secrets

from flask import (
    current_app,
    g,
    redirect,
    render_template,
    request,
    session as cookie,
    url_for,
)

from core import db, intake, spool
from core.crypto import Keyring, KeyringError, PasswordFactor, UnlockFailed
from core.paths import (
    keyring_path,
    notes_db_path,
    spool_db_path,
    spool_public_key_path,
)
from web.access import sessions_of, signed_in
from web.ratelimit import SignInLimiter, TooManyAttempts

INTAKE_COOKIE = "intake"


def register(app) -> None:

    @app.get("/signin")
    def sign_in():
        if signed_in():
            return redirect(url_for("home"))
        return render_template("signin.html", caller=g.caller, error=None,
                               next=request.args.get("next", "/"))

    @app.post("/signin")
    def do_sign_in():
        limiter: SignInLimiter = current_app.config["LIMITER"]
        caller = g.caller.login or "unknown"
        target = request.form.get("next") or "/"

        def refuse(message: str, status: int = 401):
            return render_template("signin.html", caller=g.caller, error=message,
                                   next=target), status

        # Checked before any derivation: refusing afterwards would still let an
        # attacker spend 128 MB of this machine's memory per attempt.
        try:
            limiter.check(caller)
        except TooManyAttempts as exc:
            return refuse(str(exc), 429)

        passphrase = request.form.get("passphrase") or ""
        if not passphrase:
            return refuse("Enter your passphrase.")

        try:
            ring = Keyring.load(keyring_path())
        except KeyringError as exc:
            return refuse(str(exc), 500)

        with limiter.slot():
            try:
                dek = ring.unlock(PasswordFactor(passphrase))
            except (UnlockFailed, KeyringError):
                # Deliberately not saying which part was wrong.
                return refuse("That passphrase did not unlock your notes.")

        limiter.succeeded(caller)
        summary = take_in_spool(dek)
        # New id on sign-in, so a session id seen before the passphrase was
        # entered cannot become an authenticated one.
        cookie.clear()
        cookie["sid"] = sessions_of().sign_in(caller, dek)
        cookie["csrf"] = secrets.token_urlsafe(32)
        if summary:
            cookie[INTAKE_COOKIE] = summary
        return redirect(target if target.startswith("/") else "/")

    @app.post("/lock")
    def lock():
        """Discard the key now, on every device.

        Locks everything rather than just this session: pressing Lock means
        "close the notes", and leaving another browser holding the key would not
        be that.
        """
        sessions_of().lock_all()
        cookie.clear()
        return redirect(url_for("sign_in"))

    @app.get("/status")
    def status():
        """What is unlocked, for a person and for `doctor`."""
        info = sessions_of().info(cookie.get("sid"))
        return {
            "signed_in": info is not None,
            "caller": g.caller.login,
            "sessions_open": len(sessions_of()),
            "memory_locked": info.memory_locked if info else None,
            "database_present": notes_db_path().exists(),
            "capture_while_locked": spool_public_key_path().exists(),
        }


def take_in_spool(dek: bytes) -> dict:
    """Drain the spool into the record. Returns a summary for the next page.

    Counts and reasons only — never note text. The summary travels in the
    signed cookie so it survives the redirect after sign-in, and anything worth
    keeping is already in the database.

    A failure here does not stop the sign-in. Being unable to take in spooled
    notes is a bad afternoon; being unable to sign in because of it would be a
    worse one, and the user is told either way.
    """
    try:
        conn = db.connect(notes_db_path(), dek)
    except db.DatabaseError:
        # No database yet: `counselog init` has not been run. Nothing to drain
        # into, and the home page already says so.
        return {}

    try:
        intake.ensure_identity(conn)
        spool_conn = spool.connect(spool_db_path())
        try:
            report = intake.take_in(conn, spool_conn)
        finally:
            spool_conn.close()
    except Exception:
        # Broad on purpose: see the docstring. Logged with a traceback so the
        # cause is recoverable, and never shown to the browser.
        current_app.logger.exception("could not take in the spool")
        return {"failed": True}
    finally:
        conn.close()

    if not report.anything_happened and not report.clock_disagreements:
        return {}
    return {
        "stored": len(report.stored),
        "held": len(report.quarantined),
        "clocks": len(report.clock_disagreements),
        "replaced": report.spool_was_replaced,
        "altered": report.spool_was_altered,
    }


def take_intake_summary() -> dict:
    """Read the last drain's summary and clear it: it is shown once."""
    return cookie.pop(INTAKE_COOKIE, None) or {}


__all__ = ["register", "take_in_spool", "take_intake_summary"]
