"""Entry point for `./counselogd` — the desktop inference and mirror service."""

from __future__ import annotations

import logging
import signal
import sys
import threading

import click
from werkzeug.serving import WSGIRequestHandler, make_server

from core import config
from core.certs import CertificateError, default_paths, server_context
from desktop.service import create_app
from desktop.sessions import SessionStore


class MutualTLSRequestHandler(WSGIRequestHandler):
    """Pass the verified client certificate through to the application.

    Werkzeug does not surface the peer certificate on its own, and without it
    the service could not tell which enrolled device is calling — so a session
    could not be tied to the device that opened it. TLS has already validated
    the certificate against our CA by the time this runs.
    """

    def make_environ(self) -> dict:
        environ = super().make_environ()
        getpeercert = getattr(self.connection, "getpeercert", None)
        environ["SSL_CLIENT_CERT_DICT"] = getpeercert() if getpeercert else None
        return environ


@click.command()
@click.option("--loopback", is_flag=True,
              help="Listen on 127.0.0.1 for development on one machine.")
@click.option("--port", type=int, default=None, help="Override the configured port.")
@click.option("-v", "--verbose", is_flag=True, help="Log each request.")
def main(loopback: bool, port: int | None, verbose: bool) -> None:
    """Serve bin tagging, reports, and the note mirror over mutual TLS."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    host = "127.0.0.1" if loopback else config.bind_address()
    listen_port = port or config.port()

    try:
        context = server_context(default_paths())
    except CertificateError as exc:
        raise SystemExit(f"Cannot start: {exc}")

    sessions = SessionStore()
    app = create_app(sessions)
    server = make_server(host, listen_port, app, threaded=True,
                         ssl_context=context, request_handler=MutualTLSRequestHandler)

    def shutdown(signum, _frame) -> None:
        """Drop every borrowed key on the way out.

        The keys would die with the process anyway; doing it explicitly means
        the mirror is unreadable from the moment shutdown starts, not merely
        once the interpreter finishes exiting.

        Both steps run on a separate thread. `server.shutdown()` blocks until
        `serve_forever()` stops, and `serve_forever()` is running on *this*
        thread — calling it inline from the signal handler deadlocks, leaving a
        process that ignores Ctrl-C and keeps the borrowed key in memory until
        it is killed outright.
        """
        def stop() -> None:
            sessions.close_all()
            server.shutdown()

        threading.Thread(target=stop, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    click.echo(f"counselogd listening on https://{host}:{listen_port}")
    click.echo("Mutual TLS required. This machine holds no key of its own —")
    click.echo("the laptop lends it one per session, in memory only.")
    try:
        server.serve_forever()
    finally:
        sessions.close_all()
        click.echo("\nStopped. Every borrowed key discarded; the mirror is sealed.")


if __name__ == "__main__":
    sys.exit(main())
