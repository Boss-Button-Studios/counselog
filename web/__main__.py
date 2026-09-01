"""Entry point for `./counselogweb` — the browser interface on the tailnet."""

from __future__ import annotations

import json
import logging
import shutil
import signal
import subprocess
import sys
import threading

import click
from werkzeug.serving import make_server

from core import config
from web.app import create_app
from web.sessions import BrowserSessions

DEFAULT_PORT = 8443
log = logging.getLogger("counselogweb")


def tailscale_serve_status(port: int) -> tuple[bool, str]:
    """Is tailscale already forwarding to us?

    Checked rather than assumed: without the proxy the app refuses every
    request, and "403 from my own machine" is a confusing way to discover that
    a one-line setup step was never run.
    """
    if not shutil.which("tailscale"):
        return False, "the tailscale command is not on PATH"
    try:
        raw = subprocess.run(["tailscale", "serve", "status", "--json"],
                             capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"could not ask tailscale: {exc}"
    if raw.returncode != 0 or not raw.stdout.strip():
        return False, "nothing is being served"
    try:
        config_data = json.loads(raw.stdout)
    except ValueError:
        return False, "tailscale's answer could not be read"
    # An unconfigured tailscale answers `{}`, which is truthy — checking only
    # for empty output reported "serving something, but not this port" when in
    # fact nothing was served at all.
    if not config_data:
        return False, "nothing is being served"
    if f"127.0.0.1:{port}" in json.dumps(config_data):
        return True, "forwarding to this port"
    return False, f"serving something, but not 127.0.0.1:{port}"


@click.command()
@click.option("--port", type=int, default=DEFAULT_PORT, show_default=True)
@click.option("--allow-direct", is_flag=True,
              help="Development only: accept requests that did not come via tailscale.")
@click.option("-v", "--verbose", is_flag=True)
def main(port: int, allow_direct: bool, verbose: bool) -> None:
    """Serve the browser interface on 127.0.0.1, behind tailscale."""
    logging.basicConfig(level=logging.INFO if verbose else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(message)s")

    sessions = BrowserSessions()
    app = create_app(sessions=sessions, require_tailscale=not allow_direct)
    # Loopback only. Tailscale is the only thing that should reach this, and
    # binding wider would put a sign-in form on the local network.
    server = make_server("127.0.0.1", port, app, threaded=True)

    if allow_direct:
        click.secho("Running with --allow-direct: any local process can claim "
                    "any identity. Development only.", fg="yellow")
    else:
        forwarding, detail = tailscale_serve_status(port)
        if not forwarding:
            click.secho(f"tailscale is not forwarding to this port ({detail}).", fg="yellow")
            click.echo("Requests will be refused until it is. Set it up once with:")
            click.echo(f"    tailscale serve --bg --https=443 http://127.0.0.1:{port}")

    def shutdown(signum, _frame) -> None:
        # On its own thread: server.shutdown() blocks until serve_forever
        # returns, and serve_forever is running on this one. Learned the hard
        # way in phase 3, where the same mistake left the service unkillable
        # and holding a key.
        def stop() -> None:
            sealed = sessions.lock_all()
            if sealed:
                log.info("sealed %s session(s) on shutdown", sealed)
            server.shutdown()

        threading.Thread(target=stop, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    click.echo(f"counselog web interface on http://127.0.0.1:{port}")
    click.echo(f"Reach it at https://{config.desktop_host()}/ from any tailnet device.")
    click.echo("Writing a note needs no sign-in; reading needs your passphrase.")
    try:
        server.serve_forever()
    finally:
        sessions.lock_all()
        click.echo("\nStopped. Every key discarded; the database is sealed.")


if __name__ == "__main__":
    # prog_name so help and errors say `counselogweb`, not `python -m web`.
    sys.exit(main(prog_name="counselogweb"))
