"""Setting up the link to the desktop, and checking it works.

`certs init` runs once on the desktop; `doctor` is what you run when something
is not working and you want to know which part.
"""

from __future__ import annotations

import click
import httpx

from core import config
from core.certs import (
    CertificateError,
    create_ca,
    default_paths,
    issue_client,
    issue_server,
)
from laptop.client import REQUIRED_SERVICE_VERSION, DesktopClient, TransportError
from laptop.unlock import FACTOR_CHOICES, load_keyring, unlock_dek


@click.group("certs")
def certs() -> None:
    """Set up the secure link between your laptop and the desktop."""


@certs.command("init")
@click.option("--device", "devices", multiple=True, default=("laptop",),
              show_default=True, help="Name each capture device. Repeat for several.")
@click.option("--force", is_flag=True, help="Replace the existing authority.")
def certs_init(devices: tuple[str, ...], force: bool) -> None:
    """Create the certificates the two machines use to recognise each other.

    Run this once, on the desktop. Each device gets its own certificate, so a
    lost laptop can be locked out later without disturbing anything else.
    """
    paths = default_paths()
    if paths.ca_cert.exists() and not force:
        raise click.ClickException(
            f"An authority already exists in {paths.root}. Re-running would lock out "
            "every device already enrolled. Use --force only if that is what you want."
        )

    host = config.desktop_host()
    addresses = config.desktop_addresses()
    if host == "localhost" and not addresses:
        click.secho("No desktop address configured — issuing for loopback only.", fg="yellow")
        click.echo("Copy .env.example to .env and set COUNSELOG_DESKTOP_HOST before")
        click.echo("using this across two machines.")

    try:
        create_ca(paths)
        issue_server(paths, [host], addresses)
        for device in devices:
            issue_client(paths, device)
    except CertificateError as exc:
        raise click.ClickException(str(exc)) from exc

    click.echo(f"Created a certificate authority in {paths.root}")
    valid_for = ", ".join(dict.fromkeys([host, *addresses, "localhost"]))
    click.echo(f"  desktop certificate valid for: {valid_for}")
    for device in devices:
        click.echo(f"  device certificate: {device}")
    click.echo()
    click.secho("Copy these to each capture device:", bold=True)
    click.echo(f"  {paths.ca_cert.name}, <device>.crt, <device>.key")
    click.secho("Do not copy ca.key or server.key anywhere. They stay here.", fg="yellow")


@certs.command("enroll")
@click.argument("device")
def certs_enroll(device: str) -> None:
    """Issue a certificate for another capture device."""
    paths = default_paths()
    if paths.cert(device).exists():
        raise click.ClickException(f"{device} is already enrolled.")
    try:
        issue_client(paths, device)
    except CertificateError as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(f"Enrolled {device}.")
    click.echo(f"Copy {paths.ca_cert.name}, {device}.crt and {device}.key to that device.")


@click.command("doctor")
@click.option("--loopback", is_flag=True, help="Check a service on this machine.")
@click.option("--device", default="laptop", show_default=True)
def doctor(loopback: bool, device: str) -> None:
    """Check every part of the link to the desktop, one at a time.

    Reports each step separately so a failure points at the thing that is
    actually broken, rather than at 'connection error'.
    """
    ok = True
    paths = default_paths()

    click.echo("Certificates")
    for label, path in (("authority", paths.ca_cert),
                        ("this device", paths.cert(device)),
                        ("device key", paths.key(device))):
        present = path.exists()
        ok &= present
        _line(label, present, str(path.name) if present else "missing")

    if not ok:
        click.echo()
        raise click.ClickException("Run `counselog certs init` on the desktop first.")

    # A short timeout: doctor is what you run when something is wrong, and a
    # half-open port should report quickly rather than hang.
    client = DesktopClient.from_config(loopback=loopback, device=device)
    client.timeout = 5.0
    click.echo(f"\nDesktop at {client.base_url}")
    try:
        health = client.health()
        running = health.get("service_version", 0)
        current = running >= REQUIRED_SERVICE_VERSION
        _line("reachable", True, f"service v{running}")
        _line("up to date", current,
              "" if current else f"needs v{REQUIRED_SERVICE_VERSION} — restart counselogd there")
        ok &= current
        _line("mutual TLS", True, f"it sees us as '{health['device']}'")
        if health["device"] != device:
            click.secho(f"  note: the desktop reads our certificate as "
                        f"'{health['device']}', not '{device}'.", fg="yellow")
    except TransportError as exc:
        _line("reachable", False, str(exc))
        ok = False

    click.echo("\nLanguage model")
    try:
        response = httpx.get(f"{config.ollama_url()}/api/tags", timeout=5.0)
        models = [m["name"] for m in response.json().get("models", [])]
        _line("ollama", True, f"{len(models)} model(s)")
        for name in models[:5]:
            click.echo(f"      {name}")
    except Exception as exc:  # noqa: BLE001 - any failure here is just "not available"
        _line("ollama", False, f"{type(exc).__name__}")
        click.echo("      Only needed on the desktop, for tagging and reports.")

    click.echo()
    if ok:
        click.secho("Everything needed for syncing is working.", fg="green")
    else:
        raise click.ClickException("Some checks failed — see above.")


@click.command("sync")
@click.option("--loopback", is_flag=True, help="Talk to a service on this machine.")
@click.option("--unlock-with", type=click.Choice(FACTOR_CHOICES), default=None)
def sync(loopback: bool, unlock_with: str | None) -> None:
    """Send new notes to the desktop.

    Tagging arrives in the next phase; for now this copies notes to the
    desktop's encrypted mirror so reports can be generated there later.
    """
    from core import db
    from core.paths import notes_db_path
    from desktop import mirror

    dek = unlock_dek(load_keyring(), unlock_with)
    try:
        conn = db.connect(notes_db_path(), dek)
    except db.DatabaseError as exc:
        raise click.ClickException(str(exc)) from exc

    client = DesktopClient.from_config(loopback=loopback)

    # Law 2: say what is leaving this machine, where it is going, and how it is
    # protected — every time, in one line.
    click.echo(f"Sending note text to {client.base_url} over an encrypted, "
               "mutually authenticated connection.")

    session_id = None
    try:
        client.require_current()
        session_id = client.open_session(dek)
        status = client.mirror_status(session_id)
        pending = mirror.to_payloads(conn, after_seq=status["head_seq"])
        if not pending:
            click.echo("Nothing new to send.")
            return
        result = client.sync(session_id, pending)
        click.echo(f"Sent {result['stored']} note(s). The desktop now holds "
                   f"{result['head_seq']}.")
    except TransportError as exc:
        raise click.ClickException(str(exc)) from exc
    finally:
        if session_id:
            client.close_session(session_id)
        conn.close()
        click.echo("The desktop's copy of the key has been handed back.")


def _line(label: str, ok: bool, detail: str) -> None:
    mark = click.style("ok", fg="green") if ok else click.style("no", fg="red")
    click.echo(f"  [{mark}] {label:<14}{detail}")
