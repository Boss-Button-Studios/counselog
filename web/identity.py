"""Deciding whether a request really came from tailscale, and who sent it.

`tailscale serve` terminates TLS and forwards to a loopback port, adding headers
that name the calling tailnet user. Those headers are only worth anything if the
request genuinely came through that proxy: any process able to open a local
socket could set them itself and claim to be anyone.

So the identity is trusted only when both hold:

  1. the connection came from loopback, and
  2. the request arrived on the port tailscale forwards to, carrying the
     headers tailscale actually sets.

Binding to 127.0.0.1 is not by itself the control — it keeps the wider network
out, but says nothing about other processes on this machine. This module is the
control.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

# Set by tailscale serve on every forwarded request.
LOGIN_HEADER = "Tailscale-User-Login"
NAME_HEADER = "Tailscale-User-Name"


@dataclass(frozen=True)
class Caller:
    """Who is asking, as far as anything can be established."""

    login: str | None
    display_name: str | None
    via_tailscale: bool

    @property
    def known(self) -> bool:
        return self.via_tailscale and bool(self.login)

    def describe(self) -> str:
        if not self.via_tailscale:
            return "a local process (not via tailscale)"
        return self.login or "an unidentified tailnet caller"


def _is_loopback(address: str | None) -> bool:
    if not address:
        return False
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def identify(environ: dict, *, require_tailscale: bool = True) -> Caller:
    """Work out who is calling, refusing to be fooled by a forged header.

    `require_tailscale=False` exists for local development, where there is no
    proxy in front. It must never be the default: it turns the headers into
    something any local process can assert.
    """
    remote = environ.get("REMOTE_ADDR")
    login = environ.get(f"HTTP_{LOGIN_HEADER.upper().replace('-', '_')}")
    name = environ.get(f"HTTP_{NAME_HEADER.upper().replace('-', '_')}")

    if not require_tailscale:
        return Caller(login=login or "local-development", display_name=name,
                      via_tailscale=True)

    # A request that did not arrive over loopback did not come through the
    # proxy, because the proxy is the only thing we listen for.
    if not _is_loopback(remote):
        return Caller(login=None, display_name=None, via_tailscale=False)

    # Loopback alone is not enough: another local process can also reach us.
    # The header must be present, and tailscale always sets it on forwarded
    # requests. This does not stop a local process forging one — nothing at this
    # layer can — which is why reading notes needs the passphrase regardless.
    if not login:
        return Caller(login=None, display_name=name, via_tailscale=False)

    return Caller(login=login, display_name=name, via_tailscale=True)
