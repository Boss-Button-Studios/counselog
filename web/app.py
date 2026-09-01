"""The Counselog web application.

Served on the tailnet from the desktop, reachable from whatever device is in
hand. A supervisor's note is worth writing in the ninety seconds after a
conversation ends, and that moment is rarely spent at a terminal.

Two gates, doing different jobs. A tailscale ACL decides which devices can
reach the port at all; the passphrase decides what unlocks the notes. Reaching
the page proves nothing about being allowed to read anything.
"""

from __future__ import annotations

import functools
import secrets
from typing import Callable

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    session as cookie,
    url_for,
)

from core import db
from core.crypto import Keyring, KeyringError, PasswordFactor, UnlockFailed
from core.paths import keyring_path, notes_db_path
from web.identity import identify
from web.ratelimit import SignInLimiter, TooManyAttempts
from web.sessions import BrowserSessions, NotSignedIn

SESSION_COOKIE = "counselog_session"
CSRF_FIELD = "_csrf"


def create_app(*, sessions: BrowserSessions | None = None,
               require_tailscale: bool = True) -> Flask:
    app = Flask(__name__)

    # Signs the cookie that carries the session id. Regenerated per process, so
    # restarting the service invalidates every session — which is the behaviour
    # wanted anyway: a restart should seal the database.
    app.secret_key = secrets.token_bytes(32)
    app.config.update(
        SESSIONS=sessions or BrowserSessions(),
        LIMITER=SignInLimiter(),
        REQUIRE_TAILSCALE=require_tailscale,
        SESSION_COOKIE_NAME=SESSION_COOKIE,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        # tailscale serve terminates TLS, so the browser always speaks https
        # even though this process listens on plain loopback.
        SESSION_COOKIE_SECURE=True,
        PERMANENT_SESSION_LIFETIME=1800,
        MAX_CONTENT_LENGTH=2 * 1024 * 1024,
    )

    @app.before_request
    def establish_caller() -> None:
        g.caller = identify(request.environ,
                            require_tailscale=app.config["REQUIRE_TAILSCALE"])
        if not g.caller.known:
            abort(403, "This service is only reachable through tailscale.")

    @app.after_request
    def security_headers(response):
        """No external anything. The page is served from one machine and needs
        nothing from the internet, so the policy can be absolute rather than a
        negotiation."""
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "style-src 'self'; "
            "script-src 'self'; "
            "img-src 'self' data:; "
            "form-action 'self'; "
            "base-uri 'none'; "
            "frame-ancestors 'none'"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Cache-Control"] = "no-store"
        return response

    _register_csrf(app)
    _register_routes(app)
    return app


# ── CSRF ─────────────────────────────────────────────────────────────────────


def _register_csrf(app: Flask) -> None:
    """A token per browser session, required on every state-changing request.

    SameSite=Strict already blocks the common case, but it is one cookie
    attribute away from being the only defence, and browsers vary. Two
    independent mechanisms is the right number here.
    """

    @app.before_request
    def check_csrf() -> None:
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return
        expected = cookie.get("csrf")
        supplied = request.form.get(CSRF_FIELD) or request.headers.get("X-CSRF-Token")
        if not expected or not supplied or not secrets.compare_digest(expected, supplied):
            abort(400, "This form has expired. Reload the page and try again.")

    @app.context_processor
    def csrf_token() -> dict:
        if "csrf" not in cookie:
            cookie["csrf"] = secrets.token_urlsafe(32)
        return {"csrf_token": cookie["csrf"], "csrf_field": CSRF_FIELD}

    @app.context_processor
    def unlock_state() -> dict:
        """Every page shows whether the notes are readable.

        Injected globally rather than passed per route: the header and footer
        need it on every page including error pages, and a route that forgot to
        pass it would otherwise render as though locked. Deliberately not called
        `session` — Flask already puts the cookie under that name.
        """
        from flask import current_app
        return {"unlocked": sessions_of(current_app).info(cookie.get("sid"))}


# ── access to the database ───────────────────────────────────────────────────


def sessions_of(app: Flask) -> BrowserSessions:
    return app.config["SESSIONS"]


def signed_in() -> bool:
    from flask import current_app
    return sessions_of(current_app).info(cookie.get("sid")) is not None


def requires_unlock(view: Callable) -> Callable:
    """For anything that reads notes. Capture deliberately does not use this."""

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        from flask import current_app
        try:
            g.dek = sessions_of(current_app).key(cookie.get("sid"))
        except NotSignedIn:
            return redirect(url_for("sign_in", next=request.path))
        return view(*args, **kwargs)

    return wrapper


def open_database():
    """Open the notes database with the key from the current session."""
    return db.connect(notes_db_path(), g.dek)


# ── routes ───────────────────────────────────────────────────────────────────


def _register_routes(app: Flask) -> None:

    @app.get("/signin")
    def sign_in():
        if signed_in():
            return redirect(url_for("home"))
        return render_template("signin.html", caller=g.caller, error=None,
                               next=request.args.get("next", "/"))

    @app.post("/signin")
    def do_sign_in():
        from flask import current_app
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
        # New id on sign-in, so a session id seen before the passphrase was
        # entered cannot become an authenticated one.
        cookie.clear()
        cookie["sid"] = sessions_of(current_app).sign_in(caller, dek)
        cookie["csrf"] = secrets.token_urlsafe(32)
        return redirect(target if target.startswith("/") else "/")

    @app.post("/lock")
    def lock():
        """Discard the key now, on every device.

        Locks everything rather than just this session: pressing Lock means
        "close the notes", and leaving another browser holding the key would not
        be that.
        """
        from flask import current_app
        sessions_of(current_app).lock_all()
        cookie.clear()
        return redirect(url_for("sign_in"))

    @app.get("/")
    def home():
        from flask import current_app
        return render_template("home.html", caller=g.caller)

    @app.get("/status")
    def status():
        """What is unlocked, for a person and for `doctor`."""
        from flask import current_app
        info = sessions_of(current_app).info(cookie.get("sid"))
        return {
            "signed_in": info is not None,
            "caller": g.caller.login,
            "sessions_open": len(sessions_of(current_app)),
            "memory_locked": info.memory_locked if info else None,
            "database_present": notes_db_path().exists(),
        }

    @app.errorhandler(403)
    def forbidden(exc):
        return render_template("error.html", title="Not reachable from here",
                               message=getattr(exc, "description", "")), 403

    @app.errorhandler(400)
    def bad_request(exc):
        return render_template("error.html", title="That did not work",
                               message=getattr(exc, "description", "")), 400

    @app.errorhandler(500)
    def server_error(exc):
        app.logger.exception("unhandled error", exc_info=exc)
        # Never echo an internal message: it could carry a path or note text.
        return render_template("error.html", title="Something went wrong",
                               message="The details are in the service log."), 500
