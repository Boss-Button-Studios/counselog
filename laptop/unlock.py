"""Getting the database open, once, for whichever command needs it.

Every command that touches notes needs the same three steps: load the keyring,
unlock it, open the database. Doing that in one place means the prompts and the
error messages stay consistent, and means no command invents its own way of
handling a wrong password.
"""

from __future__ import annotations

import click

from core import db
from core.crypto import (
    FactorUnavailable,
    Keyring,
    KeyringError,
    PasswordFactor,
    UnlockFailed,
    YubiKeyFactor,
)
from core.paths import keyring_path, notes_db_path

FACTOR_CHOICES = ("yubikey", "password")


def build_factor(kind: str, *, confirm_password: bool = False):
    """Turn a factor name into a usable factor, prompting the user if needed."""
    if kind == "yubikey":
        return YubiKeyFactor()
    password = click.prompt("Password", hide_input=True,
                            confirmation_prompt=confirm_password)
    return PasswordFactor(password)


def load_keyring() -> Keyring:
    try:
        return Keyring.load(keyring_path())
    except KeyringError as exc:
        raise click.ClickException(str(exc)) from exc


def unlock_dek(ring: Keyring, kind: str | None = None) -> bytes:
    """Recover the DEK, trying the most convenient factor first.

    With a key plugged in this should be touch-and-go; the password only comes
    up if there is no key, or the user asks for it. When the user names a factor
    explicitly we do not quietly fall back to another — being asked for a
    password when you asked to use your YubiKey is confusing, not helpful.
    """
    registered = {w.factor for w in ring.wrappers}
    order = [kind] if kind else [k for k in FACTOR_CHOICES if k in registered]

    last_error: Exception | None = None
    for candidate in order:
        try:
            return ring.unlock(build_factor(candidate))
        except (UnlockFailed, FactorUnavailable) as exc:
            last_error = exc
            if kind:
                break
            click.echo(f"  {candidate}: {exc}", err=True)
    raise click.ClickException(str(last_error) if last_error else "Could not unlock.")


def open_database(kind: str | None = None):
    """Unlock and open the notes database. The common path for most commands."""
    dek = unlock_dek(load_keyring(), kind)
    try:
        return db.connect(notes_db_path(), dek)
    except db.DatabaseError as exc:
        raise click.ClickException(str(exc)) from exc
