"""`counselog keys` — register, list, and revoke ways into your notes.

Kept apart from the rest of the CLI because key management is the one place a
mistake is unrecoverable: lose every registered factor and the notes are gone,
with no reset link and no support line. The commands here lean on the side of
refusing and explaining (Guideline 2).
"""

from __future__ import annotations

import shutil
import time

import click

from datetime import datetime

from core import db
from core.crypto import FactorUnavailable, Keyring, KeyringError, new_dek
from core.paths import keyring_path, notes_db_path
from laptop.unlock import FACTOR_CHOICES, build_factor, load_keyring, unlock_dek

def _ways(count: int) -> str:
    """'1 way' / '2 ways' — small thing, but it reads as broken otherwise."""
    return f"{count} way" if count == 1 else f"{count} ways"


def _friendly_date(iso: str) -> str:
    """Render a stored timestamp for a person, not for a parser."""
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso  # never let an odd timestamp break the listing


@click.group("keys")
def keys() -> None:
    """Manage the keys and passwords that unlock your notes."""


@keys.command("init")
@click.option("--factor", type=click.Choice(FACTOR_CHOICES), default="yubikey",
              show_default=True, help="How you want to unlock your notes.")
@click.option("--label", default=None, help="A name to recognise this key by later.")
def init(factor: str, label: str | None) -> None:
    """Create the keyring and register your first key.

    This generates the database key. It exists only inside this process and is
    written down nowhere — only wrapped copies, which are useless without a
    registered key or the password.
    """
    path = keyring_path()
    if path.exists():
        raise click.ClickException(
            f"A keyring already exists at {path}. Use `counselog keys add` to "
            "register another key."
        )

    ring = Keyring(path)
    try:
        wrapper = ring.add(
            new_dek(),
            build_factor(factor, confirm_password=True),
            label or f"first {factor}",
        )
    except FactorUnavailable as exc:
        raise click.ClickException(str(exc)) from exc
    ring.save()

    click.echo(f"Keyring created at {path}")
    click.echo(f"Registered {wrapper.factor} '{wrapper.label}' (id {wrapper.id})")
    click.echo()
    click.secho("Register a second key or a password now.", bold=True)
    click.echo("With only one way in, losing it means losing every note.")
    click.echo("  counselog keys add --factor password")


@keys.command("add")
@click.option("--factor", type=click.Choice(FACTOR_CHOICES), required=True,
              help="The kind of key to register.")
@click.option("--label", default=None, help="A name to recognise this key by later.")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None,
              help="Which registered factor to unlock with first.")
def add(factor: str, label: str | None, unlock_with: str | None) -> None:
    """Register another key or password against the same notes.

    Adding a key never re-encrypts anything: it wraps the existing database key
    a second time. You must already be able to unlock — you cannot add a key
    without proving you hold one.
    """
    ring = load_keyring()
    click.echo("First, unlock with a key you already have.")
    dek = unlock_dek(ring, unlock_with)

    if factor == "yubikey":
        click.echo("Now plug in the NEW YubiKey (and only that one).")
        click.confirm("Ready?", default=True, abort=True)

    try:
        wrapper = ring.add(dek, build_factor(factor, confirm_password=True),
                           label or f"{factor} added later")
    except FactorUnavailable as exc:
        raise click.ClickException(str(exc)) from exc
    ring.save()
    click.echo(f"Registered {wrapper.factor} '{wrapper.label}' (id {wrapper.id}).")
    click.echo(f"You now have {_ways(len(ring))} to unlock your notes.")


def _ways(count: int) -> str:
    """'1 way' / '2 ways' — small thing, but it reads as broken otherwise."""
    return f"{count} way" if count == 1 else f"{count} ways"


def _friendly_date(iso: str) -> str:
    """Render a stored timestamp for a person, not for a parser."""
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso  # never let an odd timestamp break the listing


@keys.command("list")
def list_keys() -> None:
    """Show every registered way into your notes."""
    ring = load_keyring()
    click.echo(f"{'ID':<18}{'TYPE':<11}{'REGISTERED':<18}LABEL")
    for wrapper in ring.wrappers:
        registered = _friendly_date(wrapper.created_at)
        click.echo(f"{wrapper.id:<18}{wrapper.factor:<11}{registered:<18}{wrapper.label}")
    click.echo()
    if len(ring) == 1:
        click.secho("Only one way in. If you lose it, the notes are gone.", fg="yellow")
    else:
        click.echo(f"{_ways(len(ring))} to unlock.")


@keys.command("revoke")
@click.argument("wrapper_id")
def revoke(wrapper_id: str) -> None:
    """Stop a key or password from opening your notes.

    Be clear about what this does: it stops that key working from now on. It
    cannot reach backwards. If the key was copied, or someone has an old backup
    of the database, removing the wrapper does not protect that data — only
    rotating the database key does.
    """
    ring = load_keyring()
    match = next((w for w in ring.wrappers if w.id == wrapper_id), None)
    if match is None:
        raise click.ClickException(f"No registered key with id {wrapper_id!r}.")

    click.echo(
        f"About to revoke {match.factor} '{match.label}' "
        f"(registered {_friendly_date(match.created_at)})."
    )
    click.confirm("Revoke it?", abort=True)
    try:
        ring.revoke(wrapper_id)
    except KeyringError as exc:
        raise click.ClickException(str(exc)) from exc
    ring.save()

    click.echo(f"Revoked. {_ways(len(ring))} to unlock remain.")
    click.echo()
    click.echo("Note: this stops that key opening the notes from now on. It does")
    click.echo("not protect data from a copy of the key used before now, or from")
    click.echo("an older backup. For that, the database key has to be rotated.")


@keys.command("test")
@click.option("--factor", type=click.Choice(FACTOR_CHOICES), default=None,
              help="Test one specific factor.")
def test_unlock(factor: str | None) -> None:
    """Check that unlocking actually works, without touching any notes.

    Worth running after registering a backup key, while the original is still in
    your hand — that is the moment a mistake is still cheap to fix.
    """
    ring = load_keyring()
    dek = unlock_dek(ring, factor)
    click.secho(f"Unlocked. Recovered a {len(dek)}-byte key.", fg="green")

@keys.command("rotate")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None,
              help="Which registered factor to unlock with.")
def rotate(unlock_with: str | None) -> None:
    """Replace the key your notes are encrypted with.

    Use this when a key might have been copied, rather than merely lost.
    Revoking stops a key working from now on; rotating actually re-encrypts the
    notes, so an old copy of the database becomes unreadable too.

    Every registered key and password must be to hand, because each one has to
    be re-registered against the new key. A YubiKey left in a drawer would
    otherwise be locked out.
    """
    ring = load_keyring()
    path = notes_db_path()

    click.echo("Rotating replaces the key your notes are encrypted with.")
    click.echo(f"You will need every registered key and password: {len(ring)} in total.")
    for wrapper in ring.wrappers:
        click.echo(f"  - {wrapper.factor}: {wrapper.label}")
    click.echo()
    click.secho("The desktop's copy of your notes will stop opening until the next "
                "sync re-sends the new key.", fg="yellow")
    click.confirm("Continue?", abort=True)

    dek = unlock_dek(ring, unlock_with)
    try:
        conn = db.connect(path, dek) if path.exists() else None
    except db.DatabaseError as exc:
        raise click.ClickException(str(exc)) from exc

    # Collect every factor first. Nothing is changed until all of them answer,
    # so a key that is not present aborts while everything still works.
    factors = {}
    for kind in sorted({w.factor for w in ring.wrappers}):
        click.echo(f"\nRe-registering your {kind}.")
        factors[kind] = build_factor(kind, confirm_password=(kind == "password"))

    backup = keyring_path().with_suffix(f".json.before-rotation-{int(time.time())}")
    shutil.copy2(keyring_path(), backup)

    new_key = new_dek()
    try:
        ring.rewrap_all(new_key, factors)          # in memory; fails safely
        if conn is not None:
            db.rekey(conn, new_key)                # database now needs new_key
        ring.save()                                # keyring now matches
    except Exception as exc:
        raise click.ClickException(
            f"Rotation failed: {exc}\n"
            f"Your previous keyring was copied to {backup} before anything changed. "
            "If your notes will not open, restore that file."
        ) from exc
    finally:
        if conn is not None:
            conn.close()

    if conn is not None:
        try:
            db.connect(path, new_key).close()
        except db.DatabaseError as exc:
            raise click.ClickException(
                f"Rotation finished but the database did not reopen: {exc}\n"
                f"Restore {backup} over {keyring_path()} and try again."
            ) from exc

    click.secho("Rotated.", fg="green")
    click.echo(f"All {len(ring)} keys re-registered against the new key.")
    click.echo(f"A copy of the old keyring is at {backup} — delete it once you have")
    click.echo("confirmed everything opens, since it can still unwrap the old key.")
