"""Vouching for the record, and saying how much of it is vouched for.

Four commands, because the key and the record do not have to be on the same
machine. `sign` is for when they are. When they are not — a key that will not
fit the port on the machine holding the notes, or a deliberate separation —
`sign-request` writes out what needs signing, `sign-offline` signs it wherever
the key is, and `sign-attach` puts the result back. Only a hash travels.

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

from pathlib import Path

import click

from core import detached, models, signatures
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


__all__ = ["sign", "sign_request", "sign_offline", "sign_attach",
           "report", "build_signer"]


@click.command("sign-request")
@click.argument("path", type=click.Path(dir_okay=False, writable=True, path_type=Path))
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def sign_request(path: Path, unlock_with: str | None) -> None:
    """Write out what needs signing, to sign on the machine with the key.

    Run this where the record is. The file holds a position in the chain and the
    hash at that position — the same value the verify page tells you to keep
    somewhere else — and nothing about any note. It is safe to carry on a USB
    stick, and useless to anyone who takes it.
    """
    conn = open_database(unlock_with)
    try:
        request = signatures.request_for_head(conn)
    except signatures.SignatureError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        conn.close()

    path.write_text(request.to_json(), encoding="utf-8")
    click.echo(f"Wrote {path}, covering {request.seq} "
               f"entr{'y' if request.seq == 1 else 'ies'}.")
    click.echo("Take it to the machine with the key and run:")
    click.echo(f"    counselog sign-offline {path.name} signature.json")


@click.command("sign-offline")
@click.argument("request_path", type=click.Path(exists=True, dir_okay=False,
                                                path_type=Path))
@click.argument("out_path", type=click.Path(dir_okay=False, writable=True,
                                            path_type=Path))
@click.option("--label", default=None, help="What to call this key in the record.")
def sign_offline(request_path: Path, out_path: Path, label: str | None) -> None:
    """Sign a request with your YubiKey, on a machine with no record on it.

    Needs no database, no passphrase and no notes — only the key. That is the
    point: the machine holding your notes never has to hold the key that vouches
    for them.
    """
    try:
        request = detached.read_request(request_path.read_text(encoding="utf-8"))
    except (detached.DetachedError, OSError, UnicodeDecodeError) as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"Signing {request.seq} entr{'y' if request.seq == 1 else 'ies'} "
               f"of a record, at {request.entry_hash[:16]}…")
    pin = click.prompt("YubiKey PIN", hide_input=True)

    try:
        signed = signatures.sign_request(request, build_signer(pin))
    except (SignerUnavailable, SigningError, signatures.SignatureError) as exc:
        raise click.ClickException(str(exc)) from exc

    out_path.write_text(signed.to_json(), encoding="utf-8")
    click.secho(f"Wrote {out_path}.", fg="green")
    click.echo("Take it back and run:")
    click.echo(f"    counselog sign-attach {out_path.name}")


@click.command("sign-attach")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--label", default=None,
              help="What to call this key in the record, e.g. 'work laptop'.")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def sign_attach(path: Path, label: str | None, unlock_with: str | None) -> None:
    """Add a signature made elsewhere to the record.

    Checked before it is stored: that the position is in this chain, that the
    hash there is the one that was signed, and that the signature verifies. A
    file that fails any of those is refused — storing it would report a broken
    signature every time the record is checked from then on.
    """
    try:
        signed = detached.read_signature(path.read_text(encoding="utf-8"))
    except (detached.DetachedError, OSError, UnicodeDecodeError) as exc:
        raise click.ClickException(str(exc)) from exc

    conn = open_database(unlock_with)
    try:
        try:
            recorded = signatures.attach(conn, signed, label=label)
        except signatures.SignatureError as exc:
            raise click.ClickException(str(exc)) from exc

        click.secho(f"Attached. Signed {recorded.covers_seq} "
                    f"entr{'y' if recorded.covers_seq == 1 else 'ies'} "
                    f"with key {recorded.pubkey_id}.", fg="green")
        click.echo()
        report(conn)
    finally:
        conn.close()
