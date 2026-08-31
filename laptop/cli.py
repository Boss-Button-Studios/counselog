"""Click command group for the laptop CLI.

Commands arrive by phase (see tasks.md): keys in phase 1; init/note/import/
people/verify in phase 2; certs/doctor in phase 3; sync/review in phase 4;
report/dash in phase 5; ui in phase 6.
"""

import click

from laptop.keys_cli import keys
from laptop.notes_cli import forget, import_file, init, note, verify
from laptop.people_cli import people
from laptop.tag_cli import review, tag
from laptop.transport_cli import certs, doctor, sync


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(package_name="counselog")
def cli() -> None:
    """Counselog — your encrypted note journal."""


cli.add_command(keys)
cli.add_command(people)
cli.add_command(init)
cli.add_command(note)
cli.add_command(import_file)
cli.add_command(verify)
cli.add_command(forget)
cli.add_command(certs)
cli.add_command(doctor)
cli.add_command(sync)
cli.add_command(tag)
cli.add_command(review)


@cli.command()
def status() -> None:
    """Show what is set up so far and what is not."""
    from core.crypto import Keyring, KeyringError
    from core.paths import counselog_home, keyring_path, notes_db_path

    click.echo(f"Counselog data:  {counselog_home()}")
    try:
        ring = Keyring.load(keyring_path())
        click.echo(f"Keyring:         {len(ring)} registered key(s)")
    except KeyringError:
        click.echo("Keyring:         not set up — run `counselog keys init`")
    exists = notes_db_path().exists()
    click.echo(f"Notes database:  {'present' if exists else 'not created yet'}")
    if not exists:
        click.echo("                 run `counselog init`")
