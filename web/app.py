"""The Counselog web application.

Served on the tailnet from the desktop, reachable from whatever device is in
hand. A supervisor's note is worth writing in the ninety seconds after a
conversation ends, and that moment is rarely spent at a terminal.

Two gates, doing different jobs. A tailscale ACL decides which devices can
reach the port at all; the passphrase decides what unlocks the notes. Reaching
the page proves nothing about being allowed to read anything.

This module is the frame: the factory, the policies that apply to every request,
and the error pages. The routes themselves live in `web/views/`.
"""

from __future__ import annotations

import secrets

from flask import Flask, abort, g, render_template, request, session as cookie

from core.display import friendly_time, preview
from web.access import CSRF_FIELD, sessions_of
from web.identity import identify
from web.ratelimit import SignInLimiter
from web.sessions import BrowserSessions
from web.views import register_all

SESSION_COOKIE = "counselog_session"


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
        negotiation.

        `script-src 'self'` and no `'unsafe-inline'`: the one script this
        interface has is a file, and everything it needs to know arrives in
        `data-` attributes rather than in an inline block."""
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

    # Shared with the CLI, so a note reads the same in both (core/display.py).
    app.jinja_env.filters["friendly_time"] = friendly_time
    app.jinja_env.filters["preview"] = preview

    _register_csrf(app)
    _register_errors(app)
    register_all(app)
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
        return {"unlocked": sessions_of().info(cookie.get("sid"))}


# ── error pages ──────────────────────────────────────────────────────────────


def _register_errors(app: Flask) -> None:

    @app.errorhandler(403)
    def forbidden(exc):
        return render_template("error.html", title="Not reachable from here",
                               message=getattr(exc, "description", "")), 403

    @app.errorhandler(400)
    def bad_request(exc):
        return render_template("error.html", title="That did not work",
                               message=getattr(exc, "description", "")), 400

    @app.errorhandler(404)
    def not_found(exc):
        return render_template("error.html", title="No such page",
                               message="That address is not part of Counselog."), 404

    @app.errorhandler(413)
    def too_large(exc):
        return render_template(
            "error.html", title="That was too big",
            message="Notes are text. Split a very long one into a few."), 413

    @app.errorhandler(500)
    def server_error(exc):
        app.logger.exception("unhandled error", exc_info=exc)
        # Never echo an internal message: it could carry a path or note text.
        return render_template("error.html", title="Something went wrong",
                               message="The details are in the service log."), 500
