"""Signing a record on a machine that does not hold it.

The key and the notes do not have to live together. Signing needs the chain
position and the head's hash — it never touches note text — so the record can
stay on one machine while the key stays on another, and only a hash crosses
between them.

That is not a workaround. A machine holding both the notes and the key is a
machine where one compromise takes everything; keeping them apart means the
worst case on either side is bounded. The original design assumed one machine
held both because it assumed the same laptop would; this is strictly better.

Three steps, three files, and nothing secret in any of them:

  1. **request** — written where the record is: which position, and the hash of
     the head at that position. A hash the tool already tells you to write down
     somewhere else.
  2. **signature** — written where the key is: the same fields, plus when it was
     signed, the public key, and the signature itself. All public.
  3. **attach** — back where the record is: checked against the chain, then
     stored.

Both files are untrusted input on the way in. They have crossed a machine
boundary, possibly on a USB stick, and are trivially editable — so every field
is checked for shape before anything is believed, and a file that does not
parse exactly is refused rather than interpreted generously (Law 5).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import datetime

from core.crypto.signing import ALGORITHM, SIGNED_VERSION

FORMAT_VERSION = 1
REQUEST_MARKER = "counselog.sign-request"
SIGNATURE_MARKER = "counselog.signature"

# A hash is 64 lowercase hex characters, always. Accepting anything else would
# mean accepting a file that never came from this program.
HASH = re.compile(r"^[0-9a-f]{64}$")

# Nothing legitimate here is large. A cap means a malformed or hostile file
# cannot make the reader allocate an unbounded amount before it is rejected.
MAX_FILE_BYTES = 64 * 1024


class DetachedError(Exception):
    """The file could not be read, or does not say what it must."""


@dataclass(frozen=True)
class SigningRequest:
    """What needs signing: a position in the chain, and the hash there."""

    seq: int
    entry_hash: str

    def to_json(self) -> str:
        return json.dumps({
            "format": REQUEST_MARKER,
            "format_version": FORMAT_VERSION,
            "signed_version": SIGNED_VERSION,
            "seq": self.seq,
            "entry_hash": self.entry_hash,
        }, indent=2) + "\n"


@dataclass(frozen=True)
class DetachedSignature:
    """A signature made elsewhere, and everything needed to check it."""

    seq: int
    entry_hash: str
    signed_at: str
    algorithm: str
    public_key: bytes
    signature: bytes

    def to_json(self) -> str:
        return json.dumps({
            "format": SIGNATURE_MARKER,
            "format_version": FORMAT_VERSION,
            "signed_version": SIGNED_VERSION,
            "seq": self.seq,
            "entry_hash": self.entry_hash,
            "signed_at": self.signed_at,
            "algorithm": self.algorithm,
            "public_key": base64.b64encode(self.public_key).decode("ascii"),
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }, indent=2) + "\n"


def read_request(text: str) -> SigningRequest:
    fields = _parse(text, REQUEST_MARKER)
    return SigningRequest(seq=_seq(fields), entry_hash=_hash(fields))


def read_signature(text: str) -> DetachedSignature:
    fields = _parse(text, SIGNATURE_MARKER)

    algorithm = fields.get("algorithm")
    if algorithm != ALGORITHM:
        raise DetachedError(
            f"That signature uses {algorithm!r}, which this build cannot check.")

    return DetachedSignature(
        seq=_seq(fields),
        entry_hash=_hash(fields),
        signed_at=_signed_at(fields),
        algorithm=algorithm,
        public_key=_bytes(fields, "public_key"),
        signature=_bytes(fields, "signature"),
    )


# ── reading, suspiciously ────────────────────────────────────────────────────


def _parse(text: str, marker: str) -> dict:
    """Turn a file into fields, refusing anything that is not exactly right.

    The marker is checked before anything else: a request read as a signature,
    or a file from some other program entirely, should fail with a sentence
    saying so rather than with a missing-field error that reads like corruption.
    """
    if len(text.encode("utf-8")) > MAX_FILE_BYTES:
        raise DetachedError("That file is far too big to be one of ours.")
    try:
        fields = json.loads(text)
    except ValueError as exc:
        raise DetachedError("That file is not readable as JSON.") from exc
    if not isinstance(fields, dict):
        raise DetachedError("That file does not contain what this expects.")

    if fields.get("format") != marker:
        found = fields.get("format")
        raise DetachedError(
            f"That is not a {marker} file"
            + (f" — it says it is {found!r}." if isinstance(found, str) else "."))

    # Missing and different are not the same problem, and were reported as if
    # they were: a file copied by hand loses a line far more often than it comes
    # from another version, and "version None" sends someone looking for a
    # compatibility fault that is not there.
    _present(fields, "format_version")
    version = fields["format_version"]
    if version != FORMAT_VERSION:
        raise DetachedError(
            f"That file is version {version!r}; this build writes and reads "
            f"version {FORMAT_VERSION}.")

    _present(fields, "signed_version")
    signed = fields["signed_version"]
    if signed != SIGNED_VERSION:
        raise DetachedError(
            f"It covers signature version {signed!r}, and this build makes "
            f"version {SIGNED_VERSION}.")
    return fields


def _present(fields: dict, name: str) -> None:
    """Complain about an absent field as an absence, and say the likely cause."""
    if name not in fields:
        raise DetachedError(
            f"That file has no {name!r} line. These files are usually copied by "
            "hand, and the usual cause is a line lost on the way — check it "
            "against the one you copied from.")


def _seq(fields: dict) -> int:
    value = fields.get("seq")
    # bool is an int in Python, and `True` as a chain position is nonsense.
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise DetachedError("The chain position in that file is not a position.")
    return value


def _hash(fields: dict) -> str:
    value = fields.get("entry_hash")
    if not isinstance(value, str) or not HASH.match(value):
        raise DetachedError("The record hash in that file is not a hash.")
    return value


def _signed_at(fields: dict) -> str:
    value = fields.get("signed_at")
    if not isinstance(value, str):
        raise DetachedError("That file does not say when it was signed.")
    try:
        datetime.fromisoformat(value)
    except ValueError as exc:
        raise DetachedError(
            "The time in that file is not a time this can read.") from exc
    return value


def _bytes(fields: dict, name: str) -> bytes:
    value = fields.get(name)
    if not isinstance(value, str):
        raise DetachedError(f"That file has no {name.replace('_', ' ')}.")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise DetachedError(
            f"The {name.replace('_', ' ')} in that file is not readable.") from exc
    if not raw:
        raise DetachedError(f"The {name.replace('_', ' ')} in that file is empty.")
    return raw
