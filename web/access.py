"""Who may do what, and how a view reaches the database.

Separate from `web/app.py` so the view modules and the application factory can
both use these without importing each other. There is nothing decorative here:
every function is about the boundary between "reaching the page" and "reading
the notes", which are deliberately different things.
"""

from __future__ import annotations

import functools
from typing import Callable

from flask import current_app, g, redirect, request, session as cookie, url_for

from core import db
from core.paths import notes_db_path
from web.sessions import BrowserSessions, NotSignedIn

CSRF_FIELD = "_csrf"


def sessions_of(app=None) -> BrowserSessions:
    return (app or current_app).config["SESSIONS"]


def signed_in() -> bool:
    return sessions_of().info(cookie.get("sid")) is not None


def requires_unlock(view: Callable) -> Callable:
    """For anything that reads or changes notes.

    Capture deliberately does not use this: a note can be written while locked,
    which is what lets the reading window be five minutes.
    """

    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        try:
            g.dek = sessions_of().key(cookie.get("sid"))
        except NotSignedIn:
            return redirect(url_for("sign_in", next=request.path))
        return view(*args, **kwargs)

    return wrapper


def open_database():
    """Open the notes database with the key from the current session.

    Only ever called from a view behind `requires_unlock`, which is what puts
    the key on `g` in the first place.
    """
    return db.connect(notes_db_path(), g.dek)
