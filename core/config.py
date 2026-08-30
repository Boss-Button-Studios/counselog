"""Where the two machines find each other.

Addresses live in a `.env` beside the repo, never in source. The repo is public,
and a hostname plus a tailnet address is a map of someone's private network —
worth keeping out of a commit even though it is not a secret in the usual sense.
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_PORT = 8443
DEFAULT_OLLAMA = "http://127.0.0.1:11434"

# Always valid targets, so the loopback development mode works without anyone
# having to configure anything. Mutual TLS is what actually gates access, not
# the name in the certificate.
LOOPBACK_NAMES = ("localhost",)
LOOPBACK_IPS = ("127.0.0.1",)


def _env_file() -> Path:
    """The settings file.

    COUNSELOG_ENV_FILE overrides it. The tests point that at a path that does
    not exist, so a real .env on a developer's machine cannot leak into them and
    make results depend on who is running them (Law 7).
    """
    override = os.environ.get("COUNSELOG_ENV_FILE")
    if override:
        return Path(override).expanduser()
    return Path(__file__).resolve().parent.parent / ".env"


def load_env() -> None:
    """Read `.env` into the environment, without adding a dependency.

    Real environment variables win, so a one-off override on the command line
    does not need the file edited.
    """
    path = _env_file()
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def desktop_host() -> str:
    """The name the laptop dials. Prefer the tailnet MagicDNS name."""
    load_env()
    return os.environ.get("COUNSELOG_DESKTOP_HOST", "localhost")


def desktop_addresses() -> list[str]:
    """Extra IP addresses the desktop answers on, for the certificate's SANs.

    A certificate issued for a name but dialled by address fails verification
    with an error that reads like a network fault. Listing both avoids that.
    """
    load_env()
    raw = os.environ.get("COUNSELOG_DESKTOP_IPS", "")
    return [item.strip() for item in raw.split(",") if item.strip()]


def bind_address() -> str:
    """What the service listens on.

    Deliberately not 0.0.0.0. Binding everywhere would put the service on the
    LAN as well as the tailnet, which is a wider door than this needs.
    """
    load_env()
    return os.environ.get("COUNSELOG_BIND", "127.0.0.1")


def port() -> int:
    load_env()
    return int(os.environ.get("COUNSELOG_PORT", DEFAULT_PORT))


def ollama_url() -> str:
    load_env()
    return os.environ.get("COUNSELOG_OLLAMA_URL", DEFAULT_OLLAMA)


def session_ttl() -> int:
    """How long the desktop may hold the key after the laptop hands it over."""
    load_env()
    return int(os.environ.get("COUNSELOG_SESSION_TTL", "900"))
