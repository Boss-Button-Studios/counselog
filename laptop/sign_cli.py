"""Vouching for the record, and saying how much of it is vouched for.

Signing needs the YubiKey and there is no software alternative offered, which is
a deliberate refusal rather than a gap. A signing key kept on disk could be used
by anyone who can already open the database, so a signature made with one would
prove nothing beyond what the reader already had — a reassuring row that means
nothing is worse than no row at all.

The signer is built through `build_signer` so tests can substitute one, the same
way phase 1's factors take an injectable responder. That is what lets everything
except the hardware custody be exercised on a machine with no key in it.
"""

from __future__ import annotations

import click

from core import models, signatures
from core.crypto import PivSigner, SignerUnavailable, SigningError
from laptop.unlock import FACTOR_CHOICES, open_database


def build_signer(pin: str) -> PivSigner:
    """The real thing. Replaced in tests, never in normal use."""
    return PivSigner(pin=pin)


@click.command("sign")
@click.option("--label", default=None,
              help="What to call this key in the record, e.g. 'work laptop'.")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def sign(label: str | None, unlock_with: str | None) -> None:
    """Sign the record as it stands, with the key on your YubiKey.

    One signature covers everything written so far, so this is one PIN per
    sitting rather than one per note — writing a note stays as fast as typing.

    What it proves is narrow and worth being clear about: that whoever held the
    key vouched for this record at this moment. Not that the notes are true, and
    not when the events in them happened.
    """
    conn = open_database(unlock_with)
    try:
        head = models.chain_head(conn)
        if head is None:
            click.echo("No notes yet — there is nothing to sign.")
            return

        click.echo(f"Signing the record as it stands: {head.seq} entr"
                   f"{'y' if head.seq == 1 else 'ies'}.")
        pin = click.prompt("YubiKey PIN", hide_input=True)

        try:
            recorded = signatures.sign_head(conn, build_signer(pin), label=label)
        except SignerUnavailable as exc:
            raise click.ClickException(str(exc)) from exc
        except SigningError as exc:
            raise click.ClickException(str(exc)) from exc

        click.secho(f"Signed {recorded.covers_seq} entr"
                    f"{'y' if recorded.covers_seq == 1 else 'ies'} "
                    f"with key {recorded.pubkey_id}.", fg="green")
        click.echo()
        click.echo("This says you vouched for the record at this moment. It does not")
        click.echo("say the notes are true, or when the events in them happened.")
        click.echo("Notes written from now on are not covered until you sign again.")
    finally:
        conn.close()


def report(conn) -> signatures.CoverageResult:
    """Print what the signatures are worth, and hand back what was found.

    Returns the result rather than a count so the caller can say the right
    closing words for the state it is in — the limits of a signature are worth
    stating when there is one, and noise when there is not.

    Shared by `verify` rather than living inside it, so the command that checks
    the record and the command that signs it cannot drift into describing the
    same state two different ways.
    """
    result = signatures.verify_coverage(conn)

    if not result.checks:
        click.echo("Not signed. The record shows it has not been altered, but "
                   "nothing here shows who recorded it.")
        return result

    broken = [check for check in result.checks if not check.valid]
    for check in broken:
        click.secho(f"  signature {check.signature.id} ({check.signature.signed_at}): "
                    f"{check.reason}", fg="red")

    if result.covered_seq:
        click.secho(f"Signed up to entry {result.covered_seq} of {result.head_seq}.",
                    fg="green" if result.ok else "yellow")
    if result.uncovered:
        click.secho(f"{result.uncovered} entr"
                    f"{'y is' if result.uncovered == 1 else 'ies are'} newer than the "
                    "last signature and vouched for by nobody.", fg="yellow")
    return result


__all__ = ["sign", "report", "build_signer"]
