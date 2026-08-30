"""Talking to the desktop.

Every call goes over mutual TLS with the CA pinned, so this cannot be pointed at
an impostor even on a hostile network — which is what makes the tailnet
assumption in the spec safe rather than merely convenient.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from core import config, protocol
from core.certs import CertificateError, CertPaths, client_context, default_paths

DEFAULT_TIMEOUT = 30.0


class TransportError(Exception):
    """The desktop could not be reached, or refused the request."""


@dataclass
class DesktopClient:
    """A connection to the desktop service.

    `device` names the client certificate to present, so a second capture device
    later gets its own identity rather than sharing the laptop's.
    """

    host: str
    port: int
    device: str = "laptop"
    paths: CertPaths | None = None
    timeout: float = DEFAULT_TIMEOUT

    @classmethod
    def from_config(cls, *, loopback: bool = False, device: str = "laptop") -> "DesktopClient":
        host = "localhost" if loopback else config.desktop_host()
        return cls(host=host, port=config.port(), device=device)

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}"

    def _client(self) -> httpx.Client:
        try:
            context = client_context(self.paths or default_paths(), self.device)
        except CertificateError as exc:
            raise TransportError(str(exc)) from exc
        return httpx.Client(base_url=self.base_url, verify=context, timeout=self.timeout)

    def _request(self, method: str, path: str, payload: dict | None = None) -> dict[str, Any]:
        try:
            with self._client() as client:
                response = client.request(method, path, json=payload)
        except httpx.ConnectError as exc:
            raise TransportError(
                f"Could not reach the desktop at {self.base_url}. Is counselogd running?"
            ) from exc
        except (httpx.TransportError, OSError) as exc:
            raise TransportError(f"Could not talk to the desktop: {exc}") from exc

        if response.status_code >= 400:
            detail = _error_of(response)
            raise TransportError(f"The desktop refused the request: {detail}")
        return response.json()

    # ── endpoints ────────────────────────────────────────────────────────────

    def health(self) -> dict[str, Any]:
        return self._request("GET", "/health")

    def open_session(self, dek: bytes) -> str:
        """Lend the desktop the database key for one session.

        This is the moment note data becomes readable on another machine, which
        is why the CLI announces it every time (Law 2).
        """
        return self._request("POST", "/session", {"key": protocol.encode_key(dek)})["session_id"]

    def close_session(self, session_id: str) -> bool:
        try:
            return bool(self._request("DELETE", f"/session/{session_id}")["closed"])
        except TransportError:
            # Best effort. The session expires on its own, so failing to close
            # it early is not worth failing the whole command over.
            return False

    def mirror_status(self, session_id: str) -> dict[str, Any]:
        return self._request("POST", "/mirror/status", {"session_id": session_id})

    def sync(self, session_id: str, payloads: list[protocol.NotePayload]) -> dict[str, Any]:
        return self._request("POST", "/sync", {
            "session_id": session_id,
            "notes": [p.to_json() for p in payloads],
        })


def _error_of(response: "httpx.Response") -> str:
    try:
        return response.json().get("error", response.text[:200])
    except ValueError:
        return f"HTTP {response.status_code}"
