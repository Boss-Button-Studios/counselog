"""Envelope encryption: one database key, wrapped once per unlock method.

The database is encrypted with a single 32-byte DEK that is generated once and
never written down in the clear. Each registered factor (a YubiKey, a password)
derives its own KEK, and each KEK encrypts a copy of that same DEK. Any one of
them opens the database.

That indirection is the whole point of spec §6: registering a second YubiKey, or
dropping a lost one, only rewrites a small wrapper — it never re-encrypts the
notes.

The keyring file itself holds no secrets. Salts, challenges and ciphertext are
all safe to read; without the matching password or physical key they are inert.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.crypto.factors import FactorError, FactorUnavailable, KeyFactor

KEYRING_VERSION = 1
DEK_BYTES = 32
NONCE_BYTES = 12


class KeyringError(Exception):
    """Base class for keyring problems."""


class UnlockFailed(KeyringError):
    """No wrapper could be opened with the factor provided."""


class LastWrapperError(KeyringError):
    """Refusing to remove the only remaining way into the database."""


def new_dek() -> bytes:
    """A fresh database key. The only place a DEK is ever born."""
    return secrets.token_bytes(DEK_BYTES)


def _aad(wrapper_id: str, factor: str) -> bytes:
    """Authenticated associated data binding ciphertext to its entry.

    Without this, a wrapper could be copied over another entry, or relabelled to
    a different factor, and still decrypt. Binding id and factor into the AEAD
    makes that tampering fail loudly instead of silently succeeding.
    """
    return f"counselog-keyring-v{KEYRING_VERSION}|{wrapper_id}|{factor}".encode()


@dataclass(frozen=True)
class Wrapper:
    """One registered way to unlock the database."""

    id: str
    label: str
    factor: str
    created_at: str
    params: dict[str, Any]
    nonce: bytes
    ciphertext: bytes

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "factor": self.factor,
            "created_at": self.created_at,
            "params": self.params,
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
        }

    @classmethod
    def from_json(cls, raw: Mapping[str, Any]) -> "Wrapper":
        try:
            return cls(
                id=str(raw["id"]),
                label=str(raw["label"]),
                factor=str(raw["factor"]),
                created_at=str(raw["created_at"]),
                params=dict(raw["params"]),
                nonce=base64.b64decode(raw["nonce"]),
                ciphertext=base64.b64decode(raw["ciphertext"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise KeyringError(f"Damaged keyring entry: {exc}") from exc


class Keyring:
    """The set of registered unlock methods for one database."""

    def __init__(self, path: Path, wrappers: Iterable[Wrapper] = ()) -> None:
        self.path = Path(path)
        self._wrappers: list[Wrapper] = list(wrappers)

    # ── persistence ──────────────────────────────────────────────────────────

    @classmethod
    def load(cls, path: Path) -> "Keyring":
        path = Path(path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise KeyringError(
                f"No keyring at {path}. Run `counselog keys init` first."
            ) from exc
        except json.JSONDecodeError as exc:
            raise KeyringError(f"The keyring at {path} is not valid JSON: {exc}") from exc

        version = raw.get("version")
        if version != KEYRING_VERSION:
            raise KeyringError(
                f"Keyring version {version!r} is not supported by this build "
                f"(expected {KEYRING_VERSION})."
            )
        return cls(path, [Wrapper.from_json(w) for w in raw.get("wrappers", [])])

    def save(self) -> None:
        """Write the keyring atomically, owner-readable only.

        Atomic because a half-written keyring during a power cut would strand
        every note in the database behind an unopenable file. The temp file is
        created in the same directory so os.replace stays on one filesystem.
        """
        payload = {
            "version": KEYRING_VERSION,
            "wrappers": [w.to_json() for w in self._wrappers],
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), prefix=".keyring-", suffix=".tmp")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    # ── inspection ───────────────────────────────────────────────────────────

    @property
    def wrappers(self) -> list[Wrapper]:
        return list(self._wrappers)

    def __len__(self) -> int:
        return len(self._wrappers)

    # ── registration ─────────────────────────────────────────────────────────

    def add(self, dek: bytes, factor: KeyFactor, label: str) -> Wrapper:
        """Register another way to unlock the database.

        Takes the DEK because the caller must already have unlocked with an
        existing factor — you cannot add a key without proving you hold one.
        """
        if len(dek) != DEK_BYTES:
            raise KeyringError(f"A DEK must be {DEK_BYTES} bytes, got {len(dek)}.")

        wrapper_id = secrets.token_hex(8)
        params = factor.new_params()
        kek = factor.derive_kek(params)
        nonce = os.urandom(NONCE_BYTES)
        ciphertext = AESGCM(kek).encrypt(nonce, dek, _aad(wrapper_id, factor.name))

        wrapper = Wrapper(
            id=wrapper_id,
            label=label,
            factor=factor.name,
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            params=params,
            nonce=nonce,
            ciphertext=ciphertext,
        )
        self._wrappers.append(wrapper)
        return wrapper

    def revoke(self, wrapper_id: str) -> Wrapper:
        """Remove a registered unlock method.

        Refuses to remove the last one. Emptying the keyring would make every
        note permanently unreadable with no warning and no undo — exactly the
        self-inflicted disaster Guideline 2 exists to prevent.

        Note what this does and does not do: it stops that key opening the
        database in future. It does not reach back in time. If the key was
        copied, or an old backup exists, only `rotate` genuinely helps.
        """
        match = next((w for w in self._wrappers if w.id == wrapper_id), None)
        if match is None:
            raise KeyringError(f"No registered key with id {wrapper_id!r}.")
        if len(self._wrappers) == 1:
            raise LastWrapperError(
                "This is the only way into your notes. Register another key or "
                "password first, then revoke this one."
            )
        self._wrappers.remove(match)
        return match

    # ── unlocking ────────────────────────────────────────────────────────────

    def unlock(self, factor: KeyFactor, *, wrapper_id: str | None = None) -> bytes:
        """Recover the DEK using one factor.

        Tries every entry registered for that factor. Trying and failing is the
        normal path — with two YubiKeys registered, the one in your hand only
        matches one of the entries — so a failure here is not an error until
        every candidate has been tried.
        """
        candidates = [w for w in self._wrappers if w.factor == factor.name]
        if wrapper_id is not None:
            candidates = [w for w in candidates if w.id == wrapper_id]
        if not candidates:
            raise UnlockFailed(f"No {factor.name} is registered for this database.")

        unavailable: FactorUnavailable | None = None
        for wrapper in candidates:
            try:
                kek = factor.derive_kek(wrapper.params)
            except FactorUnavailable as exc:
                # Hardware missing: no point trying the remaining entries, but
                # report it as "not present" rather than "wrong key".
                unavailable = exc
                break
            except FactorError:
                continue
            try:
                return AESGCM(kek).decrypt(
                    wrapper.nonce, wrapper.ciphertext, _aad(wrapper.id, wrapper.factor)
                )
            except InvalidTag:
                continue  # not this entry; try the next

        if unavailable is not None:
            raise UnlockFailed(str(unavailable)) from unavailable
        raise UnlockFailed(
            f"That {factor.name} did not unlock the database. "
            "Check you are using a registered key or the right password."
        )

    def rewrap_all(self, new_dek: bytes, factors: Mapping[str, KeyFactor]) -> None:
        """Re-wrap every entry around a new DEK, in place.

        Used by key rotation, which is the only honest answer to a key that may
        have been copied. The caller is responsible for re-keying the database
        itself; this only moves the keyring across. Every surviving entry must
        be satisfiable right now — a YubiKey that is not plugged in cannot be
        re-wrapped, and silently dropping it would lock that key out.
        """
        if len(new_dek) != DEK_BYTES:
            raise KeyringError(f"A DEK must be {DEK_BYTES} bytes, got {len(new_dek)}.")

        missing = {w.factor for w in self._wrappers} - set(factors)
        if missing:
            raise KeyringError(
                "Cannot rotate without every registered method present: missing "
                + ", ".join(sorted(missing))
            )

        rebuilt: list[Wrapper] = []
        for old in self._wrappers:
            factor = factors[old.factor]
            params = factor.new_params()
            kek = factor.derive_kek(params)
            nonce = os.urandom(NONCE_BYTES)
            rebuilt.append(
                Wrapper(
                    id=old.id,
                    label=old.label,
                    factor=old.factor,
                    created_at=old.created_at,
                    params=params,
                    nonce=nonce,
                    ciphertext=AESGCM(kek).encrypt(
                        nonce, new_dek, _aad(old.id, old.factor)
                    ),
                )
            )
        # Swap only after every re-wrap succeeded, so a failure part-way through
        # leaves the old keyring intact rather than a half-rotated one.
        self._wrappers = rebuilt
