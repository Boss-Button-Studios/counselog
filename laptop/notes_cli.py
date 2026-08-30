"""Capturing notes, and checking that the record has not been altered.

Capture has to be fast. If writing a note is slower than not writing one, the
notes stop happening and the tool is worthless — so `counselog note -m "..."`
is one line and no ceremony.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import click

from core import db, models
from core.paths import notes_db_path
from core.sanitize import describe_changes, sanitize
from laptop.unlock import FACTOR_CHOICES, load_keyring, open_database, unlock_dek

MAX_IMPORT_BYTES = 1_000_000  # a note is prose, not a data dump


def _as_utc_iso(day: datetime) -> str:
    """A calendar date becomes midnight UTC on that day."""
    return day.replace(tzinfo=timezone.utc).isoformat(timespec="seconds")


@click.command("init")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None,
              help="Which registered factor to unlock with.")
def init(unlock_with: str | None) -> None:
    """Create the notes database.

    Uses the key already in your keyring, so the database and your registered
    YubiKeys and passwords all agree from the start.
    """
    path = notes_db_path()
    if path.exists():
        raise click.ClickException(f"A database already exists at {path}.")

    dek = unlock_dek(load_keyring(), unlock_with)
    try:
        conn = db.create(path, dek)
    except db.DatabaseError as exc:
        raise click.ClickException(str(exc)) from exc
    conn.close()

    click.echo(f"Created {path}")
    click.echo("Add the people you write notes about, then start writing:")
    click.echo('  counselog people add "Sarah K." --alias Sarah --alias SK')
    click.echo('  counselog note -m "..."')


@click.command("note")
@click.option("-m", "--message", default=None, help="The note. Omit to open an editor.")
@click.option("--backdated", type=click.DateTime(formats=["%Y-%m-%d"]), default=None,
              help="When it actually happened, if not today (YYYY-MM-DD).")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def note(message: str | None, backdated: datetime | None, unlock_with: str | None) -> None:
    """Write a note.

    The time you wrote it is recorded automatically and cannot be edited later.
    If you are writing up something from last week, use --backdated: it records
    when it happened without pretending you wrote it then.
    """
    if message is None:
        message = click.edit(text="\n# Write your note above. Lines starting with # are ignored.\n")
        if message is None:
            raise click.ClickException("Nothing written — note discarded.")
        message = "\n".join(l for l in message.splitlines() if not l.startswith("#")).strip()
    if not message.strip():
        raise click.ClickException("Nothing written — note discarded.")

    conn = open_database(unlock_with)
    try:
        _warn_if_changed(message)
        stored = models.add_note(
            conn, message,
            backdated_at=_as_utc_iso(backdated) if backdated else None,
        )
    except models.ModelError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        conn.close()

    when = _friendly(stored.captured_at)
    click.echo(f"Saved note {stored.id} · {when}")
    if stored.backdated_at:
        click.echo(f"  recorded as happening {_friendly(stored.backdated_at)}")


@click.command("import")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--backdated", type=click.DateTime(formats=["%Y-%m-%d"]), default=None,
              help="When it actually happened (YYYY-MM-DD).")
@click.option("--third-party", is_flag=True,
              help="Someone else wrote this, not you.")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def import_file(path: Path, backdated: datetime | None, third_party: bool,
                unlock_with: str | None) -> None:
    """Import a text or markdown file as one note.

    --third-party marks a document you did not write yourself. Today that only
    records where it came from. It matters because the sanitizing this version
    does is sized for your own notes, not for documents written by other people;
    marking them now means the stronger checks can be applied later without
    having to guess which notes were which (spec §10).
    """
    if path.stat().st_size > MAX_IMPORT_BYTES:
        raise click.ClickException(
            f"{path.name} is larger than {MAX_IMPORT_BYTES // 1000} KB. "
            "Notes are meant to be prose — split it up if this is really one note."
        )
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise click.ClickException(
            f"{path.name} is not readable as text. Only plain text and markdown "
            "can be imported."
        ) from exc

    conn = open_database(unlock_with)
    try:
        _warn_if_changed(text)
        stored = models.add_note(
            conn, text,
            source_type=models.SOURCE_FILE,
            source_trust=models.TRUST_THIRD_PARTY if third_party else models.TRUST_SELF,
            backdated_at=_as_utc_iso(backdated) if backdated else None,
        )
    except models.ModelError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        conn.close()

    click.echo(f"Imported {path.name} as note {stored.id} · {_friendly(stored.captured_at)}")
    if third_party:
        click.echo("  marked as written by someone else")


@click.command("verify")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def verify(unlock_with: str | None) -> None:
    """Check that no note has been altered since it was written.

    Every note is linked to the one before it, so a changed, inserted or removed
    note breaks the chain and is reported here with its position.
    """
    conn = open_database(unlock_with)
    try:
        result = models.verify(conn)
    finally:
        conn.close()

    if result.checked == 0:
        click.echo("No notes yet — nothing to check.")
        return

    if result.ok:
        click.secho(f"All {result.checked} notes are unaltered since they were written.",
                    fg="green")
        if result.tombstoned:
            click.echo(f"{result.tombstoned} note(s) had their text cleared. The record "
                       "around them is intact, but their text can no longer be checked.")
        click.echo()
        click.echo("This shows the notes have not been changed. It does not show that")
        click.echo("what they say is true, or exactly when the events happened.")
        return

    click.secho(f"Problems found in {len(result.breaks)} place(s):", fg="red", bold=True)
    for problem in result.breaks:
        where = f"note {problem.note_id}" if problem.seq == 0 else \
                f"position {problem.seq} (note {problem.note_id})"
        click.echo(f"  {where}: {problem.reason}")
    raise SystemExit(1)


@click.command("forget")
@click.argument("note_id", type=int)
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def forget(note_id: int, unlock_with: str | None) -> None:
    """Permanently clear a note's text, keeping its place in the record.

    The text is gone and cannot be recovered. The note's position stays, so the
    rest of the history can still be checked — otherwise removing one note would
    destroy the evidence that nothing else was touched.
    """
    conn = open_database(unlock_with)
    try:
        target = models.get_note(conn, note_id)
        click.echo(f"Note {target.id}, written {_friendly(target.captured_at)}:")
        click.echo(click.style(_preview(target.raw_text), dim=True))
        click.echo()
        click.confirm("Clear this text permanently?", abort=True)
        models.tombstone_note(conn, note_id)
    except models.ModelError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        conn.close()
    click.echo(f"Note {note_id} cleared. Its place in the record remains.")


def _warn_if_changed(text: str) -> None:
    """Tell the user if their text was altered on the way in.

    Silence here would mean reading back a note that differs from what was
    pasted, with no explanation (Law 6).
    """
    change = describe_changes(text, sanitize(text))
    if change:
        click.echo(click.style(f"Note: {change} from the pasted text.", dim=True))


def _preview(text: str, limit: int = 200) -> str:
    if not text:
        return "(already cleared)"
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit] + "…"


def _friendly(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso
