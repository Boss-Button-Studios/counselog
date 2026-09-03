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
import re
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


def _integer(data: Mapping[str, Any], key: str, *, minimum: int = 0,
             default: int | None = None) -> int:
    value = data.get(key)
    if value is None and default is not None:
        # A field a older peer does not send yet. Only ever used where the
        # absent case has one unambiguous meaning, never to paper over a
        # missing required field.
        return default
    # bool is an int in Python; accepting it here would let `true` mean 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProtocolError(f"{key!r} must be a whole number.")
    if value < minimum:
        raise ProtocolError(f"{key!r} must be at least {minimum}.")
    return value


def _optional_integer(data: Mapping[str, Any], key: str, *,
                      minimum: int = 0) -> int | None:
    """A whole number, or nothing. Absent and null both mean nothing."""
    if data.get(key) is None:
        return None
    return _integer(data, key, minimum=minimum)


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
    # Both are hashed into the body from canon version 2, so the mirror cannot
    # recompute the hash without them.
    supersedes: int | None
    canon_version: int
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
            "supersedes": self.supersedes,
            "canon_version": self.canon_version,
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
            supersedes=_optional_integer(data, "supersedes", minimum=1),
            # Absent means a note from before revisions existed, hashed under
            # the original rules. Defaulting keeps an older laptop working.
            canon_version=_integer(data, "canon_version", minimum=1, default=1),
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
                supersedes=self.supersedes,
                version=self.canon_version,
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

# ── people and tags ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PersonPayload:
    """One person, as the desktop needs to see them.

    The laptop's id travels with them, because 'person:<id>' is the bin key on
    both machines and it has to mean the same thing on each.
    """

    person_id: int
    display_name: str
    aliases: tuple[str, ...]
    active: bool
    created_at: str

    def to_json(self) -> dict[str, Any]:
        return {
            "person_id": self.person_id,
            "display_name": self.display_name,
            "aliases": list(self.aliases),
            "active": self.active,
            "created_at": self.created_at,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "PersonPayload":
        if not isinstance(data, Mapping):
            raise ProtocolError("Each person must be an object.")
        raw_aliases = data.get("aliases")
        if not isinstance(raw_aliases, list) or len(raw_aliases) > 64:
            raise ProtocolError("'aliases' must be a list of at most 64 names.")
        aliases = []
        for alias in raw_aliases:
            if not isinstance(alias, str) or len(alias) > 128:
                raise ProtocolError("Each alias must be text of at most 128 characters.")
            aliases.append(alias)
        active = data.get("active")
        if not isinstance(active, bool):
            raise ProtocolError("'active' must be true or false.")
        return cls(
            person_id=_integer(data, "person_id", minimum=1),
            display_name=_string(data, "display_name", max_length=128),
            aliases=tuple(aliases),
            active=active,
            created_at=_string(data, "created_at", max_length=64),
        )


def parse_people(data: Any) -> list[PersonPayload]:
    if not isinstance(data, list):
        raise ProtocolError("Expected a list of people.")
    if len(data) > 500:
        raise ProtocolError("Too many people in one request.")
    return [PersonPayload.from_json(item) for item in data]


BIN_KEY_PATTERN = re.compile(r"^(self|team|person:[1-9][0-9]{0,17})$")


def parse_tags(data: Any) -> dict[int, list[tuple[str, float | None]]]:
    """Read tagging results coming back from the desktop.

    Bin keys are checked against a pattern rather than trusted: they are used to
    look up a local bin, and an unexpected shape should be refused here rather
    than discovered further in.
    """
    if not isinstance(data, Mapping):
        raise ProtocolError("Expected an object of tags per note.")
    result: dict[int, list[tuple[str, float | None]]] = {}
    for raw_id, entries in data.items():
        try:
            note_id = int(raw_id)
        except (TypeError, ValueError) as exc:
            raise ProtocolError(f"{raw_id!r} is not a note id.") from exc
        if not isinstance(entries, list):
            raise ProtocolError(f"Tags for note {note_id} must be a list.")
        tags: list[tuple[str, float | None]] = []
        for entry in entries:
            if not isinstance(entry, Mapping):
                raise ProtocolError("Each tag must be an object.")
            key = _string(entry, "bin", max_length=32)
            if not BIN_KEY_PATTERN.match(key):
                raise ProtocolError(f"{key!r} is not a valid bin.")
            confidence = entry.get("confidence")
            if confidence is not None:
                if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                    raise ProtocolError("'confidence' must be a number or null.")
                confidence = float(confidence)
                if not 0.0 <= confidence <= 1.0:
                    raise ProtocolError("'confidence' must be between 0 and 1.")
            tags.append((key, confidence))
        result[note_id] = tags
    return result

