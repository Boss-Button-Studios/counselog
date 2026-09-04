"""Phase 7: signing the chain head, and what a signature is worth afterwards.

The chain proves the record has not been altered. It cannot say who recorded it
— phase 2 wrote that down as the thing signing would close: an orphaned note is
detected but not attributed. So these tests are mostly about attribution and its
limits, and about the two ways a signature misleads a reader who trusts it:
covering less of the record than they assume, and being counted as valid when
the key that made it is gone.

The hardware path is not here. `PivSigner` cannot run without a YubiKey, and
pretending otherwise with a mock would test the mock. It stays unverified until
the laptop, like phase 1's unlock path before it.
"""

import secrets

import pytest
import sqlcipher3

from core import db, models, signatures
from core.crypto.signing import (
    SoftwareSigner,
    key_id,
    signed_bytes,
    verify_signature,
)

KEY = bytes(range(32))


@pytest.fixture
def conn(tmp_path):
    connection = db.create(tmp_path / "notes.db", KEY)
    yield connection
    connection.close()


@pytest.fixture
def signer():
    return SoftwareSigner.generate()


@pytest.fixture
def written(conn):
    for text in ("first", "second", "third"):
        models.add_note(conn, text)
    return models.chain_head(conn)


# ── the signed bytes ─────────────────────────────────────────────────────────


def test_a_signature_is_bound_to_its_position_in_the_chain(signer):
    """Signing the hash alone would let the same signature be lifted onto a
    different position and claim to cover a different amount of the record."""
    payload = signed_bytes(seq=3, entry_hash="a" * 64, signed_at="2026-09-04T10:00:00+00:00")
    moved = signed_bytes(seq=9, entry_hash="a" * 64, signed_at="2026-09-04T10:00:00+00:00")

    made = signer.sign(payload)
    assert verify_signature(signer.public_key_der(), made, payload)
    assert not verify_signature(signer.public_key_der(), made, moved)


def test_the_recorded_time_cannot_be_changed_afterwards(signer):
    """`signed_at` is inside the signed bytes, which is the only thing that makes
    the timestamp worth reading."""
    payload = signed_bytes(seq=1, entry_hash="b" * 64, signed_at="2026-09-04T10:00:00+00:00")
    backdated = signed_bytes(seq=1, entry_hash="b" * 64, signed_at="2020-01-01T00:00:00+00:00")

    made = signer.sign(payload)
    assert not verify_signature(signer.public_key_der(), made, backdated)


def test_a_key_is_named_by_itself_not_by_assignment():
    """Two machines must recognise one key without keeping a register."""
    signer = SoftwareSigner.generate()
    assert key_id(signer.public_key_der()) == key_id(signer.public_key_der())
    assert key_id(signer.public_key_der()) != key_id(SoftwareSigner.generate().public_key_der())


def test_a_signature_from_another_key_does_not_verify(signer):
    payload = signed_bytes(seq=1, entry_hash="c" * 64, signed_at="2026-09-04T10:00:00+00:00")
    other = SoftwareSigner.generate()
    assert not verify_signature(signer.public_key_der(), other.sign(payload), payload)


@pytest.mark.parametrize("rubbish", [b"", b"not a key", b"\x30\x82\x01\x00"])
def test_a_malformed_key_or_signature_is_answered_no_not_raised(rubbish, signer):
    """`verify` asks a question whose honest answer is sometimes no; a traceback
    on malformed input would turn one break into an outage (Law 6)."""
    payload = signed_bytes(seq=1, entry_hash="d" * 64, signed_at="2026-09-04T10:00:00+00:00")
    assert verify_signature(rubbish, signer.sign(payload), payload) is False
    assert verify_signature(signer.public_key_der(), rubbish, payload) is False


# ── recording one ────────────────────────────────────────────────────────────


def test_signing_records_the_key_so_the_record_can_check_itself(conn, written, signer):
    """A copy of the database must be verifiable by someone holding nothing else."""
    recorded = signatures.sign_head(conn, signer, label="laptop")

    assert recorded.covers_seq == written.seq
    assert signatures.known_key(conn, recorded.pubkey_id) == signer.public_key_der()
    assert signatures.verify_coverage(conn).ok


def test_an_empty_record_is_refused(conn, signer):
    """A signature over nothing says nothing, and would still look reassuring."""
    with pytest.raises(signatures.SignatureError):
        signatures.sign_head(conn, signer)


def test_signing_twice_with_one_key_keeps_one_copy_of_it(conn, written, signer):
    signatures.sign_head(conn, signer)
    models.add_note(conn, "fourth")
    signatures.sign_head(conn, signer)

    keys = conn.execute("SELECT COUNT(*) AS n FROM signing_keys").fetchone()["n"]
    assert keys == 1
    assert len(signatures.list_signatures(conn)) == 2


def test_signatures_and_keys_cannot_be_edited_or_deleted(conn, written, signer):
    """Editing one would re-point an attestation at a record it never covered;
    deleting a key leaves its signatures unverifiable, which destroys evidence
    rather than a claim."""
    signatures.sign_head(conn, signer)

    for statement in (
        "UPDATE signatures SET covers_seq = 1",
        "DELETE FROM signatures",
        "UPDATE signing_keys SET public_key = x'00'",
        "DELETE FROM signing_keys",
    ):
        with pytest.raises(sqlcipher3.DatabaseError):
            conn.execute(statement)


# ── what it is worth later ───────────────────────────────────────────────────


def test_notes_written_after_a_signature_are_reported_as_uncovered(conn, written, signer):
    """The mistake this exists to prevent: reading "signed" as "all of it"."""
    signatures.sign_head(conn, signer)
    models.add_note(conn, "written after the signature")
    models.add_note(conn, "and another")

    result = signatures.verify_coverage(conn)
    assert result.signed
    assert result.uncovered == 2
    assert not result.ok  # valid, but no longer reaching the head


def test_a_rewritten_record_fails_the_signature_it_kept(conn, written, signer):
    """The attack the chain alone cannot catch: rebuild the whole chain and it
    verifies clean, because it is internally consistent. The signature is what
    contradicts it."""
    signatures.sign_head(conn, signer)

    # Exactly what someone holding the key would do: the triggers are theirs to
    # drop, which is why they were never the real defence.
    conn.execute("DROP TRIGGER chain_is_append_only_update")
    conn.execute("UPDATE note_chain SET entry_hash = ? WHERE seq = ?",
                 ("f" * 64, written.seq))
    conn.commit()

    result = signatures.verify_coverage(conn)
    assert not result.ok
    assert result.covered_seq == 0
    assert "does not match" in result.checks[0].reason


def test_a_signature_by_a_key_the_record_lost_is_not_counted_as_valid(conn, written, signer):
    """Unverifiable is not the same as wrong, and neither is the same as fine."""
    signatures.sign_head(conn, signer)
    conn.execute("DROP TRIGGER signing_keys_undeletable")
    conn.execute("DELETE FROM signing_keys")
    conn.commit()

    result = signatures.verify_coverage(conn)
    assert not result.ok
    assert result.covered_seq == 0
    assert "does not hold" in result.checks[0].reason


def test_an_unsigned_record_says_so_rather_than_looking_checked(conn, written):
    result = signatures.verify_coverage(conn)
    assert not result.signed
    assert result.uncovered == written.seq
    assert result.checks == ()


def test_a_second_signature_extends_the_coverage(conn, written, signer):
    signatures.sign_head(conn, signer)
    models.add_note(conn, "later")
    signatures.sign_head(conn, signer)

    result = signatures.verify_coverage(conn)
    assert result.ok
    assert result.uncovered == 0


def test_a_signature_from_a_different_key_still_counts(conn, written, signer):
    """A second device signing is normal, not suspicious: the record holds both
    keys and says which one vouched for what."""
    signatures.sign_head(conn, signer)
    models.add_note(conn, "signed by the other device")
    signatures.sign_head(conn, SoftwareSigner.generate(), label="second device")

    result = signatures.verify_coverage(conn)
    assert result.ok
    assert len({check.signature.pubkey_id for check in result.checks}) == 2


def test_signing_does_not_disturb_the_chain(conn, written, signer):
    """Signing is a read of the record plus a row beside it, never a change."""
    before = models.verify(conn)
    signatures.sign_head(conn, signer)
    after = models.verify(conn)

    assert before.ok and after.ok
    assert models.chain_head(conn).entry_hash == written.entry_hash


def test_a_signature_never_claims_the_notes_are_true(conn, written, signer):
    """Not testable as behaviour, so it is asserted where it will be read: the
    module has to say what a signature does not prove, because the whole risk of
    this feature is a reader believing it proves more."""
    import core.crypto.signing as signing

    assert "does not prove" in signing.__doc__.lower()
    assert "true" in signing.__doc__.lower()
