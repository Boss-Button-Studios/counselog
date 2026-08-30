"""Managing the people you write notes about.

Each person gets a bin, and their aliases are how a note mentioning "Sarah" or
"SK" finds its way to the right one without a model being involved.
"""

from __future__ import annotations

import click

from core import models
from laptop.unlock import FACTOR_CHOICES, open_database


@click.group("people")
def people() -> None:
    """Manage the people you write notes about."""


@people.command("add")
@click.argument("display_name")
@click.option("--alias", "aliases", multiple=True,
              help="Another way you refer to them. Repeat for several.")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def add(display_name: str, aliases: tuple[str, ...], unlock_with: str | None) -> None:
    """Add someone, with the names you actually use for them.

    Aliases matter more than they look: an exact name match tags a note with no
    model involved at all, which is faster and completely predictable. The more
    real aliases you give, the less often anything has to be guessed.
    """
    conn = open_database(unlock_with)
    try:
        person = models.add_person(conn, display_name, aliases)
    except models.ModelError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        conn.close()

    click.echo(f"Added {person.display_name}")
    click.echo(f"  matching on: {', '.join(person.aliases)}")


@people.command("list")
@click.option("--all", "include_inactive", is_flag=True,
              help="Include people who have left.")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def list_people(include_inactive: bool, unlock_with: str | None) -> None:
    """Show everyone you write notes about."""
    conn = open_database(unlock_with)
    try:
        found = models.list_people(conn, include_inactive=include_inactive)
    finally:
        conn.close()

    if not found:
        click.echo("Nobody added yet.")
        click.echo('  counselog people add "Sarah K." --alias Sarah')
        return

    click.echo(f"{'ID':<5}{'NAME':<24}{'STATUS':<10}ALSO KNOWN AS")
    for person in found:
        status = "active" if person.active else "left"
        others = [a for a in person.aliases if a != person.display_name]
        click.echo(f"{person.id:<5}{person.display_name:<24}{status:<10}{', '.join(others)}")


@people.command("remove")
@click.argument("person_id", type=int)
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def remove(person_id: int, unlock_with: str | None) -> None:
    """Mark someone as having left the team.

    Their notes are kept. Removing the notes as well would break the record for
    everyone else, and there may be good reasons to keep them for a while — see
    the retention question in the spec. To clear a specific note's text, use
    `counselog forget`.
    """
    conn = open_database(unlock_with)
    try:
        person = models.get_person(conn, person_id)
        click.confirm(f"Mark {person.display_name} as having left?", abort=True)
        models.set_person_active(conn, person_id, False)
    except models.ModelError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        conn.close()
    click.echo(f"{person.display_name} marked as having left. Their notes are kept.")
