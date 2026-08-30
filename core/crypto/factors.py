"""Key factors: the things that can derive a key-encryption key (KEK).

A factor never sees the DEK. It turns something the user *has* (a YubiKey) or
*knows* (a password) into a 32-byte KEK. `core.crypto.envelope` then uses that
KEK to unwrap the real database key. Keeping the two apart is what lets several
different unlock methods share one database (spec §6): each factor produces its
own KEK, each KEK wraps the same DEK, and any one of them opens the door.

Adding a new kind of unlock means adding a class here and nothing else.
"""

from __future__ import annotations

import base64
import os
import unicodedata
from typing import Any, Callable, ClassVar, Mapping, Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEK_BYTES = 32


class FactorError(Exception):
    """Base class for anything that goes wrong deriving a KEK."""


class FactorUnavailable(FactorError):
    """The factor's hardware or input is not present right now.

    Distinct from a wrong password or a wrong key: this means we could not even
    attempt the derivation, so the caller should say "plug in your key", not
    "that was incorrect".
    """


@runtime_checkable
class KeyFactor(Protocol):
    """Anything that can turn stored, non-secret parameters into a KEK."""

    name: ClassVar[str]

    def new_params(self) -> dict[str, Any]:
        """Fresh public parameters for a new keyring entry (salt, challenge...).

        Whatever this returns is stored in the clear in keyring.json, so it must
        never contain a secret.
        """

    def derive_kek(self, params: Mapping[str, Any]) -> bytes:
        """Reproduce the KEK from those parameters plus the user's secret."""


class PasswordFactor:
    """Password unlock, stretched with scrypt.

    The spec is explicit that the password is not a separate mechanism — it is
    one more entry in the same wrapped-key scheme, so a forgotten YubiKey is an
    inconvenience rather than a lockout.
    """

    name: ClassVar[str] = "password"

    # 2**17 * 8 * 128 = 128 MB and ~260 ms on the reference desktop. Measured,
    # not guessed. High enough to make offline guessing expensive, low enough
    # that unlocking does not feel broken.
    SCRYPT_N = 2**17
    SCRYPT_R = 8
    SCRYPT_P = 1
    SALT_BYTES = 16

    def __init__(self, password: str) -> None:
        if not password:
            raise FactorUnavailable("No password given.")
        # NFC-normalise so a password typed on a different keyboard or OS still
        # derives the same KEK. Without this, an accented character entered as a
        # combining sequence would silently fail to unlock.
        self._password = unicodedata.normalize("NFC", password).encode("utf-8")

    def new_params(self) -> dict[str, Any]:
        return {
            "salt": base64.b64encode(os.urandom(self.SALT_BYTES)).decode("ascii"),
            "n": self.SCRYPT_N,
            "r": self.SCRYPT_R,
            "p": self.SCRYPT_P,
        }

    def derive_kek(self, params: Mapping[str, Any]) -> bytes:
        try:
            salt = base64.b64decode(params["salt"])
            n, r, p = int(params["n"]), int(params["r"]), int(params["p"])
        except (KeyError, ValueError, TypeError) as exc:
            raise FactorError(f"Malformed password parameters: {exc}") from exc
        # Parameters come from the keyring file, which sits outside the encrypted
        # database and so is attacker-writable in the worst case. Reject absurd
        # costs rather than letting a tampered file wedge the process (Law 5).
        if not (2**12 <= n <= 2**20) or not (1 <= r <= 32) or not (1 <= p <= 16):
            raise FactorError("Password parameters out of accepted range.")
        return Scrypt(salt=salt, length=KEK_BYTES, n=n, r=r, p=p).derive(self._password)


# A responder takes (challenge, slot) and returns the YubiKey's raw HMAC-SHA1
# response. Injectable so the derivation logic is testable on a machine with no
# key attached — the desktop, for instance.
Responder = Callable[[bytes, int], bytes]


class YubiKeyFactor:
    """YubiKey unlock via HMAC-SHA1 challenge-response on an OTP slot.

    Each registered key gets its own random challenge, so two keys registered
    against the same database stay independent: revoking one does not disturb
    the other, and neither can be derived from the other's stored parameters.

    The 20-byte HMAC-SHA1 response is stretched through HKDF-SHA256 to a full
    32-byte KEK. HMAC-SHA1 is the primitive the OTP slot offers; HKDF here is
    about width and domain separation, not about repairing SHA-1.
    """

    name: ClassVar[str] = "yubikey"

    CHALLENGE_BYTES = 64  # the YubiKey's HMAC-SHA1 challenge size
    HKDF_INFO = b"counselog-kek-v1"
    DEFAULT_SLOT = 2

    def __init__(self, slot: int = DEFAULT_SLOT, responder: Responder | None = None) -> None:
        if slot not in (1, 2):
            raise FactorError(f"YubiKey OTP slot must be 1 or 2, got {slot}.")
        self._slot = slot
        self._responder = responder or _hardware_responder

    def new_params(self) -> dict[str, Any]:
        return {
            "challenge": base64.b64encode(os.urandom(self.CHALLENGE_BYTES)).decode("ascii"),
            "slot": self._slot,
        }

    def derive_kek(self, params: Mapping[str, Any]) -> bytes:
        try:
            challenge = base64.b64decode(params["challenge"])
            slot = int(params["slot"])
        except (KeyError, ValueError, TypeError) as exc:
            raise FactorError(f"Malformed YubiKey parameters: {exc}") from exc
        if len(challenge) != self.CHALLENGE_BYTES:
            raise FactorError("YubiKey challenge is the wrong length.")

        response = self._responder(challenge, slot)
        if not response:
            raise FactorUnavailable("The YubiKey returned an empty response.")

        # Salting HKDF with the challenge keeps each registered key's KEK in its
        # own domain without the factor needing to know its keyring entry's id.
        return HKDF(
            algorithm=hashes.SHA256(),
            length=KEK_BYTES,
            salt=challenge,
            info=self.HKDF_INFO,
        ).derive(response)


def _hardware_responder(challenge: bytes, slot: int) -> bytes:
    """Ask a physically present YubiKey to answer the challenge.

    Imported lazily and deliberately: the desktop has no YubiKey and does not
    install the [yubikey] extra, so `import ykman` at module scope would break
    every desktop process (see CLAUDE.md). Note this path talks OTP over HID and
    needs no pyscard at runtime, even though pip installs it.

    Unverified against real hardware — the reference desktop has no key. Confirm
    on the laptop before phase 7.
    """
    try:
        from ykman.hid import list_otp_devices
        from yubikit.core.otp import OtpConnection
        from yubikit.yubiotp import SLOT, YubiOtpSession
    except ImportError as exc:  # pragma: no cover - depends on the [yubikey] extra
        raise FactorUnavailable(
            "YubiKey support is not installed. Install it with: "
            'pip install -e ".[yubikey]"'
        ) from exc

    devices = list(list_otp_devices())
    if not devices:
        raise FactorUnavailable("No YubiKey found. Plug one in and try again.")
    if len(devices) > 1:
        raise FactorUnavailable(
            f"{len(devices)} YubiKeys are plugged in. Leave exactly one attached "
            "so there is no doubt which key is being used."
        )

    otp_slot = SLOT.ONE if slot == 1 else SLOT.TWO
    with devices[0].open_connection(OtpConnection) as connection:
        return YubiOtpSession(connection).calculate_hmac_sha1(otp_slot, challenge)
