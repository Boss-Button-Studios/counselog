"""What the laptop and the desktop say to each other.

Everything here crosses a trust boundary, so everything here is validated on
arrival (Law 5). Mutual TLS already proves *which device* is talking; it says
nothing about whether the payload is well formed, so the two checks are separate
and both are done.

The important one is `NotePayload.verify_self_consistency`. A note arrives with
the chain entry that covers it, and the desktop recomputes that hash from the
note's own fields before storing anything. A mirror that accepted a note whose
body did not match its chain entry would be a mirror of something that never
existed.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Mapping

from core import chain

PROTOCOL_VERSION = 1

SOURCE_TYPES = ("text_prompt", "file_import")
TRUST_LEVELS = ("self_authored", "third_party")
MAX_NOTE_CHARS = 1_000_000
MAX_BATCH = 500


class ProtocolError(Exception):
    """The message was malformed, or claimed something inconsistent."""


def _string(data: Mapping[str, Any], key: str, *, max_length: int = 512) -> str:
    value = data.get(key)
    if not isinstance(value, str):
        raise ProtocolError(f"{key!r} must be text.")
    if len(value) > max_length:
        raise ProtocolError(f"{key!r} is longer than {max_length} characters.")
    return value


def _optional_string(data: Mapping[str, Any], key: str, *, max_length: int = 512) -> str | None:
    if data.get(key) is None:
        return None
    return _string(data, key, max_length=max_length)


def _integer(data: Mapping[str, Any], key: str, *, minimum: int = 0) -> int:
    value = data.get(key)
    # bool is an int in Python; accepting it here would let `true` mean 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{key!r} must be a whole number.")
    if value < minimum:
        raise ProtocolError(f"{key!r} must be at least {minimum}.")
    return value


def _hex_hash(data: Mapping[str, Any], key: str) -> str:
    value = _string(data, key, max_length=64)
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ProtocolError(f"{key!r} is not a valid hash.")
    return value


def _choice(data: Mapping[str, Any], key: str, allowed: tuple[str, ...]) -> str:
    value = _string(data, key, max_length=32)
    if value not in allowed:
        raise ProtocolError(f"{key!r} must be one of: {', '.join(allowed)}.")
    return value


@dataclass(frozen=True)
class NotePayload:
    """One note plus the chain entry that covers it."""

    note_id: int
    captured_at: str
    backdated_at: str | None
    source_type: str
    source_trust: str
    raw_text: str
    tombstoned_at: str | None
    seq: int
    body_hash: str
    prev_hash: str
    entry_hash: str
    hashed_at: str

    def to_json(self) -> dict[str, Any]:
        return {
            "note_id": self.note_id,
            "captured_at": self.captured_at,
            "backdated_at": self.backdated_at,
            "source_type": self.source_type,
            "source_trust": self.source_trust,
            "raw_text": self.raw_text,
            "tombstoned_at": self.tombstoned_at,
            "seq": self.seq,
            "body_hash": self.body_hash,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
            "hashed_at": self.hashed_at,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "NotePayload":
        if not isinstance(data, Mapping):
            raise ProtocolError("Each note must be an object.")
        return cls(
            note_id=_integer(data, "note_id", minimum=1),
            captured_at=_string(data, "captured_at", max_length=64),
            backdated_at=_optional_string(data, "backdated_at", max_length=64),
            source_type=_choice(data, "source_type", SOURCE_TYPES),
            source_trust=_choice(data, "source_trust", TRUST_LEVELS),
            raw_text=_string(data, "raw_text", max_length=MAX_NOTE_CHARS),
            tombstoned_at=_optional_string(data, "tombstoned_at", max_length=64),
            seq=_integer(data, "seq", minimum=1),
            body_hash=_hex_hash(data, "body_hash"),
            prev_hash=_hex_hash(data, "prev_hash"),
            entry_hash=_hex_hash(data, "entry_hash"),
            hashed_at=_string(data, "hashed_at", max_length=64),
        )

    def verify_self_consistency(self) -> None:
        """Check the note actually matches the chain entry sent with it.

        A tombstoned note is exempt from the body check: its text was destroyed
        on purpose, so it cannot be recomputed. Its link is still checked, which
        is the same split the local chain uses.
        """
        if self.tombstoned_at is None:
            recomputed = chain.body_hash(
                note_id=self.note_id,
                captured_at=self.captured_at,
                backdated_at=self.backdated_at,
                source_type=self.source_type,
                source_trust=self.source_trust,
                raw_text=self.raw_text,
            )
            if recomputed != self.body_hash:
                raise ProtocolError(
                    f"Note {self.note_id} does not match the chain entry sent with it."
                )
        if chain.link_hash(self.prev_hash, self.body_hash) != self.entry_hash:
            raise ProtocolError(f"The chain entry for note {self.note_id} is not self-consistent.")


def parse_batch(data: Any) -> list[NotePayload]:
    """Validate a whole batch, refusing the lot if any part is wrong.

    All-or-nothing on purpose: a partially accepted batch would leave the mirror
    with a gap in the chain, which is indistinguishable from tampering.
    """
    if not isinstance(data, list):
        raise ProtocolError("Expected a list of notes.")
    if len(data) > MAX_BATCH:
        raise ProtocolError(f"Too many notes at once — send at most {MAX_BATCH}.")

    payloads = [NotePayload.from_json(item) for item in data]
    for payload in payloads:
        payload.verify_self_consistency()

    sequences = [p.seq for p in payloads]
    if sequences != sorted(sequences) or len(set(sequences)) != len(sequences):
        raise ProtocolError("Notes must arrive in chain order, with no repeats.")
    return payloads


def encode_key(dek: bytes) -> str:
    return base64.b64encode(dek).decode("ascii")


def decode_key(value: Any) -> bytes:
    """Decode the key the laptop lends the desktop for a session."""
    if not isinstance(value, str):
        raise ProtocolError("The key must be text.")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise ProtocolError("The key is not valid base64.") from exc
    if len(raw) != 32:
        raise ProtocolError("The key must be 32 bytes.")
    return raw
