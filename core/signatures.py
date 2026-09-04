"""Recording who vouched for the record, and checking those claims later.

The crypto is in `core/crypto/signing.py`; this is the storage and the reading
of it. Split because they answer different questions — one is "is this signature
valid", the other is "what does this record claim, and how much of it is
covered".

**The coverage question is the one people get wrong.** A record with a valid
signature is not a signed record: the signature covers the chain *as it stood
when it was made*, and every note written since is vouched for by nobody. So
verification reports how far the newest signature reaches, and a page or a
command that says "signed" without saying "up to here" is overstating what it
knows.
"""

from __future__ import annotations

from dataclasses import dataclass

from core import models
from core.crypto.signing import (
    ALGORITHM,
    SIGNED_VERSION,
    Signer,
    key_id,
    signed_bytes,
    verify_signature,
)


class SignatureError(Exception):
    """The record could not be signed."""


@dataclass(frozen=True)
class Signature:
    """One attestation: a key, a position in the chain, and when it was made."""

    id: int
    covers_seq: int
    algorithm: str
    pubkey_id: str
    signature: bytes
    signed_at: str


@dataclass(frozen=True)
class SignatureCheck:
    """What one recorded signature turned out to be worth."""

    signature: Signature
    valid: bool
    reason: str  # empty when valid; otherwise plain enough to show a person


@dataclass(frozen=True)
class CoverageResult:
    """Every signature in the record, and how much of the record they reach.

    `head_seq` is where the chain now ends; `covered_seq` is the furthest point
    any *valid* signature reaches. An invalid one covers nothing — counting it
    would be the same mistake as trusting it.
    """

    checks: tuple[SignatureCheck, ...]
    head_seq: int
    covered_seq: int

    @property
    def signed(self) -> bool:
        return self.covered_seq > 0

    @property
    def ok(self) -> bool:
        """Every signature valid, and the newest one reaching the head."""
        return all(check.valid for check in self.checks) and self.covered_seq == self.head_seq

    @property
    def uncovered(self) -> int:
        """Entries written since the furthest valid signature."""
        return max(self.head_seq - self.covered_seq, 0)


def sign_head(conn, signer: Signer, *, label: str | None = None) -> Signature:
    """Vouch for the record as it stands now.

    One signature per session rather than per note: signing every note would
    mean a PIN for every note, and the head already covers everything before it.

    Refuses an empty record. A signature over nothing says nothing, and storing
    one would put a reassuring row in front of a reader for no reason.
    """
    head = models.chain_head(conn)
    if head is None:
        raise SignatureError("There are no notes to sign yet.")

    public_der = signer.public_key_der()
    identifier = key_id(public_der)
    signed_at = models.utc_now()
    payload = signed_bytes(seq=head.seq, entry_hash=head.entry_hash, signed_at=signed_at)
    raw = signer.sign(payload)

    # Check our own work before storing it. A signer that silently produced
    # something unverifiable would leave the record claiming an attestation that
    # fails the moment anyone looks — worse than refusing to sign at all.
    if not verify_signature(public_der, raw, payload):
        raise SignatureError(
            "The signature this key produced does not verify. Nothing was recorded.")

    with conn:
        conn.execute(
            "INSERT INTO signing_keys (id, algorithm, public_key, label, first_seen) "
            "VALUES (?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
            (identifier, ALGORITHM, public_der, label, signed_at),
        )
        cursor = conn.execute(
            "INSERT INTO signatures (covers_seq, algorithm, pubkey_id, signature, "
            "signed_at) VALUES (?, ?, ?, ?, ?)",
            (head.seq, ALGORITHM, identifier, raw, signed_at),
        )
        signature_id = int(cursor.lastrowid)
    return _signature(conn, signature_id)


def list_signatures(conn) -> list[Signature]:
    """Every attestation, oldest first."""
    return [_from_row(row) for row in conn.execute(
        "SELECT * FROM signatures ORDER BY covers_seq, id")]


def known_key(conn, pubkey_id: str) -> bytes | None:
    row = conn.execute("SELECT public_key FROM signing_keys WHERE id = ?",
                       (pubkey_id,)).fetchone()
    return bytes(row["public_key"]) if row else None


def verify_coverage(conn) -> CoverageResult:
    """Check every recorded signature, and say how far the good ones reach."""
    head = models.chain_head(conn)
    head_seq = head.seq if head else 0
    entries = {entry.seq: entry for entry in models.chain_entries(conn)}

    checks = []
    covered = 0
    for signature in list_signatures(conn):
        valid, reason = _check(conn, signature, entries)
        checks.append(SignatureCheck(signature=signature, valid=valid, reason=reason))
        if valid:
            covered = max(covered, signature.covers_seq)
    return CoverageResult(checks=tuple(checks), head_seq=head_seq, covered_seq=covered)


def _check(conn, signature: Signature, entries: dict) -> tuple[bool, str]:
    """Is this one signature worth anything, and if not, why not?

    The reasons are separated because they mean different things to a reader. A
    signature over a position that no longer exists is a broken record; one made
    by a key the record does not hold is unverifiable rather than wrong; one that
    simply does not match is the case everyone thinks of, and the rarest.
    """
    entry = entries.get(signature.covers_seq)
    if entry is None:
        return False, (f"covers position {signature.covers_seq}, which is not in "
                       "the chain")

    public_der = known_key(conn, signature.pubkey_id)
    if public_der is None:
        return False, (f"made by key {signature.pubkey_id}, which this record does "
                       "not hold — nothing here can check it")

    if signature.algorithm != ALGORITHM:
        return False, f"uses {signature.algorithm}, which this build cannot check"

    payload = signed_bytes(seq=signature.covers_seq, entry_hash=entry.entry_hash,
                           signed_at=signature.signed_at, version=SIGNED_VERSION)
    if not verify_signature(public_der, signature.signature, payload):
        return False, "does not match the record it claims to cover"
    return True, ""


def _signature(conn, signature_id: int) -> Signature:
    row = conn.execute("SELECT * FROM signatures WHERE id = ?", (signature_id,)).fetchone()
    if row is None:
        raise SignatureError(f"No signature with id {signature_id}.")
    return _from_row(row)


def _from_row(row) -> Signature:
    return Signature(
        id=int(row["id"]),
        covers_seq=int(row["covers_seq"]),
        algorithm=row["algorithm"],
        pubkey_id=row["pubkey_id"],
        signature=bytes(row["signature"]),
        signed_at=row["signed_at"],
    )
