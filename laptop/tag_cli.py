"""Sorting notes into bins, and checking the guesses.

Tagging is deliberately its own command rather than part of `sync`. On a machine
without a GPU the model takes over a minute per note, and capture has to stay
fast — you should be able to write a note and get on with your day without
waiting for anything to think about it.
"""

from __future__ import annotations

import sys
import time

import click

from core import db, models
from core.paths import notes_db_path
from desktop import mirror, tagger
from laptop.client import DesktopClient, TransportError
from laptop.unlock import FACTOR_CHOICES, load_keyring, unlock_dek

# Generous, because the model is slow and giving up early would waste the work.
TAG_TIMEOUT_PER_NOTE = 300.0


@click.command("tag")
@click.option("--loopback", is_flag=True, help="Talk to a service on this machine.")
@click.option("--model", default=None,
              help=f"Which model to use. Default: {tagger.DEFAULT_MODEL}")
@click.option("--limit", type=int, default=20, show_default=True,
              help="How many notes to tag in one run.")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def tag(loopback: bool, model: str | None, limit: int, unlock_with: str | None) -> None:
    """Sort new notes into bins.

    Names you have listed are matched exactly and cost nothing. Whether a note
    is about you or about the team is a judgement, so that part is put to the
    language model on the desktop — which is slow, and why this is a separate
    command you run when it suits you.
    """
    dek = unlock_dek(load_keyring(), unlock_with)
    try:
        conn = db.connect(notes_db_path(), dek)
    except db.DatabaseError as exc:
        raise click.ClickException(str(exc)) from exc

    client = DesktopClient.from_config(loopback=loopback)
    session_id = None
    try:
        pending = models.unprocessed_notes(conn)[:limit]
        if not pending:
            click.echo("Every note is already sorted.")
            return

        people = models.list_people(conn)
        if not people:
            click.secho("No people added yet, so only 'self' and 'team' can be matched.",
                        fg="yellow")
            click.echo('  counselog people add "Sarah K." --alias Sarah')

        click.echo(f"Sending {len(pending)} note(s) to {client.base_url} to be sorted, "
                   "over an encrypted, mutually authenticated connection.")
        click.echo("The model reasons about each note in turn — usually one to two "
                   "minutes, occasionally longer. Results are saved as they arrive, "
                   "so stopping early keeps whatever is done.")
        click.echo()

        session_id = client.open_session(dek)
        client.send_people(session_id, [
            _person_payload(person) for person in models.list_people(conn, include_inactive=True)
        ])
        # Make sure the desktop actually holds the notes before asking about them.
        status = client.mirror_status(session_id)
        outstanding = mirror.to_payloads(conn, after_seq=status["head_seq"])
        if outstanding:
            client.sync(session_id, outstanding)

        # One note per request. The model is slow enough that batching would mean
        # a single interruption discarding everything already computed — which is
        # exactly what happened the first time this was built as one call.
        done = 0
        for index, note in enumerate(pending, start=1):
            # Overwrite the "working on it" line in a terminal; keep both lines
            # when output is redirected, where a carriage return just makes a mess.
            live = sys.stdout.isatty()
            click.echo(f"  [{index}/{len(pending)}] note {note.id}: "
                       f"{_preview(note.raw_text, 56)}", nl=not live)
            started = time.monotonic()
            try:
                answer = client.tag(session_id, [note.id], model=model,
                                    timeout=TAG_TIMEOUT_PER_NOTE)
            except TransportError as exc:
                click.echo()
                click.secho(f"      stopped: {exc}", fg="red")
                break

            failure = (answer.get("failed") or {}).get(str(note.id))
            if failure:
                click.echo()
                click.secho(f"      stopped: {failure}", fg="red")
                break

            note_tags = _parse(answer).get(note.id, [])
            models.set_tags(conn, note.id, note_tags)
            done += 1
            elapsed = time.monotonic() - started
            names = ", ".join(_describe(conn, key, c) for key, c in note_tags)
            prefix = "\r" if live else "      -> "
            suffix = " " * 20 if live else ""
            head = f"[{index}/{len(pending)}] note {note.id}: " if live else ""
            click.echo(f"{prefix}  {head}{names or 'no bin matched'}"
                       f"  ({elapsed:.0f}s){suffix}")

        _summarise(conn, done, len(pending))
    except TransportError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        if session_id:
            client.close_session(session_id)
        conn.close()


def _parse(answer: dict) -> dict[int, list[tuple[str, float | None]]]:
    from core import protocol
    try:
        return protocol.parse_tags(answer.get("tags", {}))
    except protocol.ProtocolError as exc:
        raise click.ClickException(f"The desktop sent something unexpected: {exc}") from exc


def _person_payload(person: models.Person):
    from core.protocol import PersonPayload
    return PersonPayload(
        person_id=person.id, display_name=person.display_name,
        aliases=person.aliases, active=person.active, created_at=person.created_at,
    )


def _summarise(conn, done: int, total: int) -> None:
    click.echo()
    if done == 0:
        click.secho("Nothing was sorted.", fg="yellow")
    elif done < total:
        click.secho(f"Sorted {done} of {total}. The rest are still waiting — "
                    "run `counselog tag` again to continue.", fg="yellow")
    else:
        click.secho(f"Sorted all {done} note(s).", fg="green")

    unsure = models.tags_needing_review(conn, tagger.DEFAULT_THRESHOLD)
    if unsure:
        click.echo(f"{len(unsure)} guess(es) the model was unsure about. "
                   "Check them with `counselog review`.")


def _describe(conn, key: str, confidence: float | None) -> str:
    """Name a bin the way a person thinks of it, not by its key."""
    label = key
    if key.startswith(models.PERSON_PREFIX):
        try:
            label = models.get_person(conn, int(key[len(models.PERSON_PREFIX):])).display_name
        except models.ModelError:
            pass
    if confidence is None:
        return f"{label} (name matched)"
    return f"{label} ({confidence:.0%} sure)"


@click.command("review")
@click.option("--threshold", type=float, default=tagger.DEFAULT_THRESHOLD, show_default=True,
              help="Show guesses below this confidence.")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def review(threshold: float, unlock_with: str | None) -> None:
    """Check the sorting the model was unsure about.

    Only shows guesses. Notes matched by name are exact and are not second
    guessed here, so this list stays short enough to actually work through.
    """
    from laptop.unlock import open_database

    conn = open_database(unlock_with)
    try:
        pending = models.tags_needing_review(conn, threshold)
        if not pending:
            click.secho("Nothing to check.", fg="green")
            return

        click.echo(f"{len(pending)} guess(es) to check.\n")
        for note, key, confidence in pending:
            click.echo(click.style(f"Note {note.id} · {note.captured_at[:10]}", bold=True))
            click.echo(f"  {_preview(note.raw_text)}")
            click.echo(f"  Suggested bin: {_describe(conn, key, confidence)}")
            choice = click.prompt("  Keep it?", type=click.Choice(["y", "n", "q"]),
                                  default="y", show_choices=True)
            if choice == "q":
                click.echo("Stopped. The rest are still waiting.")
                return
            if choice == "y":
                models.confirm_tag(conn, note.id, key)
            else:
                models.reject_tag(conn, note.id, key)
            click.echo()
        click.secho("All checked.", fg="green")
    finally:
        conn.close()


def _preview(text: str, limit: int = 200) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit] + "…"
