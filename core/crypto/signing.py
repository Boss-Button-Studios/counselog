"""Signing the chain head, so the record can say *who* recorded it.

The chain proves the notes have not been altered. It cannot prove who wrote
them: anyone holding the database could rebuild the whole chain and produce
something internally consistent (phase 2 recorded this — an orphaned note is
detected, but not attributed). A signature over the head closes that, because
producing one needs a key that lives on a device and never leaves it.

**One signature per session, not per note.** Signing every note would mean a PIN
for every note, and capture has to stay as fast as typing. The head covers
everything before it, so one signature vouches for the whole record as it stood
at that moment.

**What a signature does not prove.** That the notes are true, or when the events
in them happened, or even when they were written — only that whoever held the
key vouched for this record at the moment they signed. Third-party proof of time
needs a timestamping authority, which would leak note counts and timing to it;
v0 does not build that.

Nothing here assumes a YubiKey. `SoftwareSigner` is a real signer with the key
in memory — the desktop uses it, and it is what the tests exercise; `PivSigner`
talks to a key that cannot be copied. Both produce signatures the same verifier
accepts, so the hardware is a change of custody, not of format.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

# Bumped only if the signed bytes change shape. An old signature keeps verifying
# under the version it was made with, the way chain entries record their canon
# version — trying versions until one matches would let a signature be replayed
# under whichever rules ignore the field that was tampered with.
SIGNED_VERSION = 1

# Separates these bytes from anything else this project ever signs. Without it a
# signature made for one purpose could be presented as one made for another.
DOMAIN = b"counselog.chain-head.v1"

ALGORITHM = "ecdsa-p256-sha256"


class SigningError(Exception):
    """The signature could not be made."""


class SignerUnavailable(SigningError):
    """The key is not here — not plugged in, or not installed.

    Its own class because "plug in your key" and "that key is wrong" are
    different problems for the person holding it (Law 6), exactly as
    `FactorUnavailable` is kept apart from a failed unlock.
    """


def signed_bytes(*, seq: int, entry_hash: str, signed_at: str,
                 version: int = SIGNED_VERSION) -> bytes:
    """The exact bytes a signature covers.

    Length-prefixed like everything else hashed here, so no field can be
    re-split at different boundaries to make two different claims collide.

    All three fields are inside on purpose. The `entry_hash` alone would be a
    signature that could be lifted onto a different position in the chain; the
    `seq` pins where it sits; and `signed_at` inside the signed bytes means the
    recorded time cannot be edited afterwards without breaking the signature —
    which is the only thing making the timestamp worth anything at all.
    """
    from core.chain import length_prefixed

    return DOMAIN + b"".join(length_prefixed(field) for field in (
        str(version).encode("utf-8"),
        str(seq).encode("utf-8"),
        entry_hash.encode("utf-8"),
        signed_at.encode("utf-8"),
    ))


def key_id(public_key_der: bytes) -> str:
    """A short, stable name for a public key.

    The first 16 bytes of SHA-256 over the key's DER, as hex. Long enough not to
    collide in a record that will hold a handful of keys, short enough to print
    next to a signature and compare by eye. Derived from the key rather than
    assigned, so the same key is recognisable across machines and re-enrolments.
    """
    return hashlib.sha256(public_key_der).hexdigest()[:32]


class Signer(Protocol):
    """Something that can sign the head. Software or hardware, same contract."""

    def public_key_der(self) -> bytes:
        """The public half, DER SubjectPublicKeyInfo."""

    def sign(self, payload: bytes) -> bytes:
        """A DER-encoded ECDSA signature over `payload`."""


@dataclass
class SoftwareSigner:
    """A signer holding its private key in memory.

    Not a stand-in for the hardware — it is what the desktop has, and the tests
    exercise the same code path the YubiKey will. What it does not give is
    custody: a key in memory can be copied, so a signature from one proves the
    record passed through a machine that had the key, not through a device
    nobody could clone.
    """

    private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def generate(cls) -> "SoftwareSigner":
        return cls(private_key=ec.generate_private_key(ec.SECP256R1()))

    def public_key_der(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, payload: bytes) -> bytes:
        return self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))


def verify_signature(public_key_der: bytes, signature: bytes, payload: bytes) -> bool:
    """Does this signature match these bytes and this key?

    Returns a bool rather than raising: a signature that does not verify is an
    expected answer here — it is what `verify` is looking for — not an
    exceptional one. A malformed key or signature is also just "no", because the
    caller's question is the same either way.
    """
    try:
        key = serialization.load_der_public_key(public_key_der)
        if not isinstance(key, ec.EllipticCurvePublicKey):
            return False
        key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


# ── the hardware path, laptop only ───────────────────────────────────────────


@dataclass
class PivSigner:
    """A signer backed by a YubiKey's PIV slot.

    The key is generated on the device and cannot be extracted, so a signature
    means the device was physically present and the PIN was entered. That is the
    whole reason this exists: `SoftwareSigner` proves a machine had a key,
    this proves a person had a key.

    Imported lazily, inside the methods, because the desktop does not install
    the [yubikey] extra and a module-scope import would break every desktop
    process (see CLAUDE.md). Unlike phase 1's unlock path, PIV speaks over a
    smartcard connection, so this one does need pyscard and a running pcscd.

    **Unverified against real hardware.** The reference desktop has no key. Every
    line below is written from the documented API and must be run on the laptop
    before it is trusted — the same status `_hardware_responder` carried through
    phase 1, and for the same reason.
    """

    pin: str
    slot: str = "9c"  # PIV "digital signature": PIN required for every operation

    def _session(self):
        try:
            from ykman.device import list_all_devices
            from yubikit.core.smartcard import SmartCardConnection
            from yubikit.piv import PivSession
        except ImportError as exc:  # pragma: no cover - needs the [yubikey] extra
            raise SignerUnavailable(
                "YubiKey support is not installed. Install it with: "
                'pip install -e ".[yubikey]"'
            ) from exc

        devices = list(list_all_devices())
        if not devices:
            raise SignerUnavailable("No YubiKey found. Plug one in and try again.")
        if len(devices) > 1:
            raise SignerUnavailable(
                f"{len(devices)} YubiKeys are plugged in. Leave exactly one "
                "attached so there is no doubt which key signed."
            )
        device, _info = devices[0]
        return PivSession(device.open_connection(SmartCardConnection))

    def public_key_der(self) -> bytes:  # pragma: no cover - needs the hardware
        from yubikit.piv import SLOT
        certificate = self._session().get_certificate(SLOT.SIGNATURE)
        return certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, payload: bytes) -> bytes:  # pragma: no cover - needs the hardware
        from yubikit.piv import SLOT, KEY_TYPE

        session = self._session()
        session.verify_pin(self.pin)
        # The card signs a digest, not the message: PIV has no hash step of its
        # own, so the hashing happens here and the card does the curve maths.
        digest = hashlib.sha256(payload).digest()
        return session.sign(SLOT.SIGNATURE, KEY_TYPE.ECCP256, digest,
                            hashes.SHA256(), utils.Prehashed(hashes.SHA256()))
