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

import contextlib
import hashlib
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

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


@contextlib.contextmanager
def _card_errors(doing: str):
    """Turn what the card says into what a person can act on (Law 6).

    Every one of these is a thing that will actually happen: a mistyped PIN, a
    slot generated with the wrong algorithm, a slot with a key but no
    certificate. Left alone they surface as an APDU status code in a traceback,
    which tells the person holding the key nothing about what to do next.

    The remaining PIN attempts are worth repeating exactly, because the next
    piece of information after "wrong PIN" is how many tries are left before the
    key locks itself.
    """
    try:
        from yubikit.core import BadResponseError, InvalidPinError, NotSupportedError
        from yubikit.core.smartcard import ApduError
    except ImportError as exc:  # pragma: no cover - needs the [yubikey] extra
        raise SignerUnavailable(
            "YubiKey support is not installed. Install it with: "
            'pip install -e ".[yubikey]"'
        ) from exc

    try:
        yield
    except InvalidPinError as exc:
        remaining = getattr(exc, "attempts_remaining", None)
        raise SigningError(
            "That PIN was not accepted."
            + (f" {remaining} attempt(s) remain before the key blocks itself."
               if remaining is not None else "")) from exc
    except BadResponseError as exc:
        raise SigningError(
            f"The YubiKey answered in a way this could not read, trying to "
            f"{doing}. If slot 9c has no certificate in it, generate one — the "
            "public key is read from there.") from exc
    except NotSupportedError as exc:
        raise SigningError(f"This YubiKey cannot {doing}: {exc}") from exc
    except ApduError as exc:
        raise SigningError(
            f"The YubiKey refused to {doing} (card status 0x{exc.sw:04x}). If "
            "slot 9c is empty, or holds a key that is not ECCP256, generate it "
            "again with that algorithm.") from exc


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

    **Unverified against real hardware.** The reference desktop has no key, so
    the custody claim is untested until this runs on the laptop — the same status
    `_hardware_responder` carried through phase 1, and for the same reason.

    What *is* verified is the API contract: every call here was checked against
    the `yubikey-manager` 5.9.2 source, and the tests drive it through a fake
    card that mimics the library's own `_pad_message` behaviour. That is what
    caught the signing call being wrong in a way no amount of re-reading my own
    code would have shown.
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

    def public_key_der(self) -> bytes:
        """Read the public half out of the certificate in the slot.

        The key type is checked here rather than left to the card, because the
        card's refusal is an APDU status code and this is a sentence. Generating
        a slot through the manager GUI defaults to RSA, so a key of the wrong
        type is the most likely thing to be sitting there.
        """
        from yubikit.piv import SLOT

        with _card_errors("read the certificate in slot 9c"):
            certificate = self._session().get_certificate(SLOT.SIGNATURE)

        public = certificate.public_key()
        if not isinstance(public, ec.EllipticCurvePublicKey):
            raise SigningError(
                f"The key in slot 9c is {type(public).__name__.replace('PublicKey', '')}, "
                "and Counselog signs with ECDSA P-256. Generate the slot again "
                "choosing ECCP256 — in the manager GUI it is the algorithm "
                "dropdown, which defaults to RSA.")
        if not isinstance(public.curve, ec.SECP256R1):
            raise SigningError(
                f"The key in slot 9c is on curve {public.curve.name}, and "
                "Counselog signs with P-256 (ECCP256). Generate the slot again.")

        return public.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign(self, payload: bytes) -> bytes:
        """Sign with the key in the slot. The PIN is verified for every call.

        The message goes in **whole**, with SHA-256 named as the algorithm to
        hash it with. The first version of this hashed the payload here and
        passed `Prehashed` as the *padding* argument, which does nothing: the
        library checks for `Prehashed` on the `hash_algorithm` argument, and
        padding is only read for RSA. The card would have signed
        `SHA256(SHA256(payload))` — a signature that could never verify, and
        `sign_head` would have refused to record it. Found by reading the
        package source before the key was ever plugged in.

        This is now the same call `ykman`'s own `check_key` makes, and the
        signature it returns verifies with `ec.ECDSA(SHA256)` over the message,
        which is exactly what `verify_signature` does.
        """
        from yubikit.piv import SLOT, KEY_TYPE

        session = self._session()
        with _card_errors("verify the PIN"):
            session.verify_pin(self.pin)
        with _card_errors("sign with the key in slot 9c"):
            return session.sign(SLOT.SIGNATURE, KEY_TYPE.ECCP256, payload,
                                hashes.SHA256())
