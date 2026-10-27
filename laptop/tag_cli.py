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

from core import checking, db, filing, judgements, models, tags
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
@click.option("--device", default="laptop", show_default=True,
              help="Which enrolled identity to present.")
def tag(loopback: bool, model: str | None, limit: int, unlock_with: str | None,
        device: str) -> None:
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

    # Not always 'laptop'. The certificate a machine presents is its own, and
    # `certs prune` deliberately removes every other device's key — so on the
    # machine that holds the record and also runs the service, the only identity
    # available is the one enrolled for it. Without this, sorting could not be
    # run at all there (Guideline 4: the identity you hold, not one you borrow).
    client = DesktopClient.from_config(loopback=loopback, device=device)
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

        client.require_current()
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
        untagged: list[int] = []
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
            _file(conn, note.id, note_tags, answer)
            if not note_tags:
                untagged.append(note.id)
            done += 1
            elapsed = time.monotonic() - started
            names = ", ".join(_describe(conn, key, c) for key, c in note_tags)
            # \033[K erases from the cursor to the end of the line. Padding with
            # a fixed number of spaces cannot work: the line being replaced is as
            # long as the note preview, so any leftover tail shows through.
            prefix = "\r  " if live else "      -> "
            suffix = "\033[K" if live else ""
            # The note id goes on the result line too when redirected: in a log
            # with several notes, "-> no bin matched" alone names nothing.
            head = f"[{index}/{len(pending)}] " if live else ""
            click.echo(f"{prefix}{head}note {note.id}: {names or 'no bin matched'}"
                       f"  ({elapsed:.0f}s){suffix}")

        _summarise(conn, done, len(pending), untagged)
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


def _file(conn, note_id: int, note_tags, answer: dict) -> None:
    """File the note and keep every answer the model gave (`core.filing`)."""
    from core import protocol
    try:
        given = protocol.parse_judgements(answer.get("judgements", {})).get(note_id, [])
        model, method = protocol.parse_sorting_source(answer)
    except protocol.ProtocolError as exc:
        raise click.ClickException(f"The desktop sent something unexpected: {exc}") from exc
    filing.file_sorting(conn, note_id, note_tags,
                        [judgements.Judgement(key, said_yes, confidence)
                         for key, said_yes, confidence in given],
                        model=model, method=method)


def _person_payload(person: models.Person):
    from core.protocol import PersonPayload
    return PersonPayload(
        person_id=person.id, display_name=person.display_name,
        aliases=person.aliases, active=person.active, created_at=person.created_at,
    )


def _summarise(conn, done: int, total: int, untagged: list[int]) -> None:
    click.echo()
    if done == 0:
        click.secho("Nothing was sorted.", fg="yellow")
    elif done < total:
        click.secho(f"Sorted {done} of {total}. The rest are still waiting — "
                    "run `counselog tag` again to continue.", fg="yellow")
    else:
        click.secho(f"Sorted all {done} note(s).", fg="green")

    # Offered once, here, rather than started: a run can end at any hour, and
    # checking is better done when there is time to read.
    waiting = checking.to_check(conn)
    if waiting:
        click.echo(f"{len(waiting)} note(s) worth checking. Run `counselog review`, "
                   "or open Check the sorting in the browser.")

    if untagged:
        # A note in no bin appears in no report. Saying nothing here would let it
        # quietly disappear, which is worse than the model simply being wrong.
        ids = ", ".join(str(i) for i in untagged)
        click.secho(f"{len(untagged)} note(s) ended up in no bin at all: {ids}",
                    fg="yellow")
        click.echo("  They will not show up in any report. If they mention someone,")
        click.echo("  adding an alias for that person and running `counselog tag`")
        click.echo("  again will pick them up.")


def _describe(conn, key: str, confidence: float | None) -> str:
    """Name a bin the way a person thinks of it, not by its key."""
    label = key
    if key.startswith(tags.PERSON_PREFIX):
        try:
            label = models.get_person(conn, int(key[len(tags.PERSON_PREFIX):])).display_name
        except models.ModelError:
            pass
    if confidence is None:
        return f"{label} (name matched)"
    return f"{label} ({confidence:.0%} sure)"


@click.command("review")
@click.option("--threshold", type=float, default=checking.REVIEW_THRESHOLD, show_default=True,
              help="Ask about answers the model gave below this confidence.")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def review(threshold: float, unlock_with: str | None) -> None:
    """Check the sorting: notes in no bin, answers the model was unsure of,
    and a few picked at random to see how often it is confidently wrong.

    The same list as "Check the sorting" in the browser. There is no default
    answer: Enter alone asks again, so nothing is confirmed by habit.
    """
    from laptop.unlock import open_database

    conn = open_database(unlock_with)
    try:
        queue = checking.to_check(conn, threshold)
        if not queue:
            click.secho("Nothing to check.", fg="green")
            return

        click.echo(f"{len(queue)} note(s) to check. Answer y or n; "
                   "s skips a note, q stops.\n")
        for item in queue:
            if _review_one(conn, item) == "q":
                click.echo("Stopped. The rest are still waiting.")
                return
            click.echo()
        click.secho("All checked.", fg="green")
    finally:
        conn.close()


def _review_one(conn, item: checking.ToCheck) -> str:
    """Put one note's questions. Returns 'q' to stop, 's' if skipped, '' if done."""
    note = item.note
    click.echo(click.style(f"Note {note.id} · {note.occurred_at[:10]}", bold=True))
    click.echo(f"  {checking.why(item.reason)}")
    click.echo()
    for line in note.raw_text.splitlines() or [""]:
        click.echo(f"    {line}")
    click.echo()
    for question in item.questions:
        click.echo(f"  {checking.QUESTIONS[question.bin_key]}")
        click.echo(f"  {checking.suggestion(question)}")
        # No default, deliberately: a default is an answer given by habit.
        choice = click.prompt("  Your answer", type=click.Choice(["y", "n", "s", "q"]),
                              show_choices=True)
        if choice in ("s", "q"):
            return choice
        if choice == "y":
            tags.confirm_tag(conn, note.id, question.bin_key)
        else:
            tags.reject_tag(conn, note.id, question.bin_key)
    return ""


def _preview(text: str, limit: int = 200) -> str:
    flat = " ".join(text.split())
    return flat if len(flat) <= limit else flat[:limit] + "…"
