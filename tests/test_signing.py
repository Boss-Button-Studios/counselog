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

from core import db, detached, models, signatures
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


# ── the hardware call, against a card that behaves like the real one ─────────
#
# The YubiKey itself cannot be tested here. What can be — and what actually went
# wrong — is the *call*: which argument carries the hash algorithm, and whether
# the message goes in whole or pre-hashed. This fake reproduces the branch in
# `yubikit.piv._pad_message` exactly, so a wrong call fails here the way it would
# fail on the key.


class FakeCard:
    """A stand-in for `PivSession`, faithful to the parts this code uses.

    Deliberately not a mock that records calls and agrees with everything: the
    bug this exists to catch was a call that a permissive mock would have
    accepted happily. It hashes the way the library hashes, so the only
    signatures it produces are ones the real card would produce too.
    """

    def __init__(self, key):
        self.key = key
        self.pin_verified = False
        self.signed_message = None
        self.hash_algorithm = None
        self.padding = "not passed"

    def verify_pin(self, pin):
        self.pin_verified = True

    def get_certificate(self, slot):
        class Certificate:
            def __init__(self, key):
                self._key = key

            def public_key(self):
                return self._key.public_key()

        return Certificate(self.key)

    def sign(self, slot, key_type, message, hash_algorithm, padding=None):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        assert self.pin_verified, "PIV slot 9c requires the PIN for every operation"
        assert int(slot) == PIV_SLOT_SIGNATURE, "must be slot 9c, not another key"
        assert int(key_type) == PIV_KEY_TYPE_ECCP256, "the record's curve is P-256"
        self.signed_message = message
        self.hash_algorithm = hash_algorithm
        self.padding = padding

        # The branch from yubikit.piv._pad_message: for EC keys, `Prehashed` is
        # looked for on the hash algorithm, and padding is read only for RSA.
        if isinstance(hash_algorithm, utils.Prehashed):
            digest = message
        else:
            hasher = hashes.Hash(hash_algorithm)
            hasher.update(message)
            digest = hasher.finalize()
        return self.key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


# The desktop does not install the [yubikey] extra — that is the whole reason it
# is an extra — so `yubikit.piv` is not importable here. These are the real
# values, read out of yubikey-manager 5.9.2: SLOT.SIGNATURE is PIV slot 9c, the
# one that demands the PIN for every operation, and ECCP256 is P-256. Pinning
# the numbers means the test asserts what the card will actually be told.
PIV_SLOT_SIGNATURE = 0x9C
PIV_KEY_TYPE_ECCP256 = 0x11


@pytest.fixture
def card(monkeypatch):
    """A fake card, and just enough of `yubikit.piv` for the lazy import to find."""
    import sys
    import types
    from enum import IntEnum

    class SLOT(IntEnum):
        SIGNATURE = PIV_SLOT_SIGNATURE

    class KEY_TYPE(IntEnum):
        ECCP256 = PIV_KEY_TYPE_ECCP256

    module = types.ModuleType("yubikit.piv")
    module.SLOT = SLOT
    module.KEY_TYPE = KEY_TYPE
    package = types.ModuleType("yubikit")
    package.piv = module
    monkeypatch.setitem(sys.modules, "yubikit", package)
    monkeypatch.setitem(sys.modules, "yubikit.piv", module)

    from core.crypto import signing

    fake = FakeCard(SoftwareSigner.generate().private_key)
    monkeypatch.setattr(signing.PivSigner, "_session", lambda self: fake)
    return fake


def test_a_signature_from_the_card_verifies_against_the_payload(card):
    """The bug this catches: hashing the payload here and passing `Prehashed` as
    the padding meant the card signed SHA256(SHA256(payload)), which nothing
    could ever verify."""
    from core.crypto.signing import PivSigner

    signer = PivSigner(pin="123456")
    payload = signed_bytes(seq=4, entry_hash="e" * 64, signed_at="2026-09-06T09:00:00+00:00")

    made = signer.sign(payload)

    assert verify_signature(signer.public_key_der(), made, payload)


def test_the_whole_message_is_sent_not_a_digest(card):
    """PIV hashes what it is given. Sending a digest and naming a hash algorithm
    hashes it a second time."""
    from cryptography.hazmat.primitives import hashes
    from core.crypto.signing import PivSigner

    payload = signed_bytes(seq=1, entry_hash="a" * 64, signed_at="2026-09-06T09:00:00+00:00")
    PivSigner(pin="123456").sign(payload)

    assert card.signed_message == payload, "the payload must go to the card whole"
    assert isinstance(card.hash_algorithm, hashes.SHA256)
    assert card.padding is None, "padding is read only for RSA and must stay out of it"


def test_the_pin_is_verified_before_every_signature(card):
    """Slot 9c is the one that asks every time; that is why it was chosen."""
    from core.crypto.signing import PivSigner

    PivSigner(pin="123456").sign(b"anything")
    assert card.pin_verified


def test_the_public_key_comes_from_the_certificate_in_the_slot(card):
    """The record stores the key it will later verify against, so this must be
    the key in the slot and not some other one the process happens to hold."""
    from cryptography.hazmat.primitives import serialization
    from core.crypto.signing import PivSigner, key_id

    expected = card.key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    assert key_id(PivSigner(pin="123456").public_key_der()) == key_id(expected)


def test_a_record_can_be_signed_by_the_card(conn, written, card):
    """End to end through the same path the laptop will take, with only the
    custody faked."""
    from core.crypto.signing import PivSigner

    recorded = signatures.sign_head(conn, PivSigner(pin="123456"), label="yubikey")

    assert signatures.verify_coverage(conn).ok
    assert recorded.covers_seq == written.seq


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


# ── the commands and the page ────────────────────────────────────────────────


def test_signing_needs_the_key_and_says_so_when_it_is_absent(tmp_path, monkeypatch):
    """There is no software fallback, on purpose: a signing key kept on disk
    could be used by anyone who can already open the database, so a signature
    made with one would prove nothing the reader did not already have."""
    from click.testing import CliRunner
    from laptop.cli import cli

    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("COUNSELOG_ENV_FILE", str(tmp_path / "absent.env"))
    runner = CliRunner()
    runner.invoke(cli, ["keys", "init", "--factor", "password", "--label", "t"],
                  input="pw\npw\n", catch_exceptions=False)
    runner.invoke(cli, ["init", "--unlock-with", "password"], input="pw\n",
                  catch_exceptions=False)
    runner.invoke(cli, ["note", "-m", "something", "--unlock-with", "password"],
                  input="pw\n", catch_exceptions=False)

    from core.crypto import SignerUnavailable
    import laptop.sign_cli as sign_cli

    def no_key(pin):
        raise SignerUnavailable("No YubiKey found. Plug one in and try again.")

    monkeypatch.setattr(sign_cli, "build_signer", no_key)
    result = runner.invoke(cli, ["sign", "--unlock-with", "password"], input="pw\n1234\n")

    assert result.exit_code != 0
    assert "Plug one in" in result.output


def test_signing_from_the_command_line_records_and_reports_it(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from laptop.cli import cli
    import laptop.sign_cli as sign_cli

    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("COUNSELOG_ENV_FILE", str(tmp_path / "absent.env"))
    runner = CliRunner()
    runner.invoke(cli, ["keys", "init", "--factor", "password", "--label", "t"],
                  input="pw\npw\n", catch_exceptions=False)
    runner.invoke(cli, ["init", "--unlock-with", "password"], input="pw\n",
                  catch_exceptions=False)
    runner.invoke(cli, ["note", "-m", "something", "--unlock-with", "password"],
                  input="pw\n", catch_exceptions=False)

    monkeypatch.setattr(sign_cli, "build_signer", lambda pin: SoftwareSigner.generate())
    signed = runner.invoke(cli, ["sign", "--unlock-with", "password"], input="pw\n1234\n")
    assert signed.exit_code == 0, signed.output
    assert "Signed 1 entry" in signed.output
    # The limit is stated every time, next to the reassuring part.
    assert "does not" in signed.output

    checked = runner.invoke(cli, ["verify", "--unlock-with", "password"], input="pw\n")
    assert checked.exit_code == 0, checked.output
    assert "Signed up to entry 1 of 1" in checked.output

    # A note written after the signature must be reported as covered by nobody.
    runner.invoke(cli, ["note", "-m", "written after", "--unlock-with", "password"],
                  input="pw\n", catch_exceptions=False)
    after = runner.invoke(cli, ["verify", "--unlock-with", "password"], input="pw\n")
    assert "vouched for by nobody" in after.output


def test_verify_says_plainly_when_nothing_has_been_signed(tmp_path, monkeypatch):
    """A clean chain nobody signed must not read as fully checked."""
    from click.testing import CliRunner
    from laptop.cli import cli

    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("COUNSELOG_ENV_FILE", str(tmp_path / "absent.env"))
    runner = CliRunner()
    runner.invoke(cli, ["keys", "init", "--factor", "password", "--label", "t"],
                  input="pw\npw\n", catch_exceptions=False)
    runner.invoke(cli, ["init", "--unlock-with", "password"], input="pw\n",
                  catch_exceptions=False)
    runner.invoke(cli, ["note", "-m", "something", "--unlock-with", "password"],
                  input="pw\n", catch_exceptions=False)

    result = runner.invoke(cli, ["verify", "--unlock-with", "password"], input="pw\n")
    assert "Not signed" in result.output
    assert "who recorded it" in result.output


# ── the three-step path, as two machines would run it ────────────────────────


def _record_at(runner, cli, tmp_path, monkeypatch, home_name):
    """A record in its own home, so the two machines are genuinely separate."""
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / home_name))
    monkeypatch.setenv("COUNSELOG_ENV_FILE", str(tmp_path / "absent.env"))
    runner.invoke(cli, ["keys", "init", "--factor", "password", "--label", "t"],
                  input="pw\npw\n", catch_exceptions=False)
    runner.invoke(cli, ["init", "--unlock-with", "password"], input="pw\n",
                  catch_exceptions=False)
    runner.invoke(cli, ["note", "-m", "Ada raised the timeline",
                        "--unlock-with", "password"], input="pw\n",
                  catch_exceptions=False)


def test_the_three_steps_sign_a_record_the_key_never_met(tmp_path, monkeypatch):
    """The whole point, driven the way a person would: the machine with the
    record never sees the key, and the machine with the key never sees a note."""
    from click.testing import CliRunner
    from laptop.cli import cli
    import laptop.sign_cli as sign_cli

    runner = CliRunner()
    _record_at(runner, cli, tmp_path, monkeypatch, "desktop")
    request_file = tmp_path / "request.json"
    signature_file = tmp_path / "signature.json"

    asked = runner.invoke(cli, ["sign-request", str(request_file),
                                "--unlock-with", "password"], input="pw\n")
    assert asked.exit_code == 0, asked.output
    assert "Ada raised the timeline" not in request_file.read_text()

    # On the other machine: a key, no database, no passphrase prompt at all.
    monkeypatch.setattr(sign_cli, "build_signer",
                        lambda pin: SoftwareSigner.generate())
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "nothing-here"))
    made = runner.invoke(cli, ["sign-offline", str(request_file),
                               str(signature_file)], input="1234\n")
    assert made.exit_code == 0, made.output

    # Back where the record is.
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "desktop"))
    attached = runner.invoke(cli, ["sign-attach", str(signature_file),
                                   "--label", "laptop", "--unlock-with", "password"],
                             input="pw\n")
    assert attached.exit_code == 0, attached.output
    assert "Signed up to entry 1 of 1" in attached.output

    checked = runner.invoke(cli, ["verify", "--unlock-with", "password"], input="pw\n")
    assert "Signed up to entry 1 of 1" in checked.output


def test_a_signature_for_another_record_is_refused_at_the_door(tmp_path, monkeypatch):
    """Two records, one key. The file looks right and is not."""
    from click.testing import CliRunner
    from laptop.cli import cli
    import laptop.sign_cli as sign_cli

    runner = CliRunner()
    signer = SoftwareSigner.generate()
    monkeypatch.setattr(sign_cli, "build_signer", lambda pin: signer)

    _record_at(runner, cli, tmp_path, monkeypatch, "theirs")
    theirs = tmp_path / "theirs.json"
    runner.invoke(cli, ["sign-request", str(theirs), "--unlock-with", "password"],
                  input="pw\n")
    signature = tmp_path / "signature.json"
    runner.invoke(cli, ["sign-offline", str(theirs), str(signature)], input="1234\n")

    # A different record, at the same position, with different notes in it.
    _record_at(runner, cli, tmp_path, monkeypatch, "mine")
    result = runner.invoke(cli, ["sign-attach", str(signature),
                                 "--unlock-with", "password"], input="pw\n")

    assert result.exit_code != 0
    assert "different record" in result.output


def test_a_file_that_is_not_ours_is_refused_by_the_command(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from laptop.cli import cli

    runner = CliRunner()
    _record_at(runner, cli, tmp_path, monkeypatch, "desktop")
    rubbish = tmp_path / "rubbish.json"
    rubbish.write_text("{\"format\": \"something.else\"}")

    result = runner.invoke(cli, ["sign-attach", str(rubbish),
                                 "--unlock-with", "password"], input="pw\n")
    assert result.exit_code != 0
    assert "not a counselog" in result.output


def test_signing_offline_needs_no_record_and_says_so_when_the_key_is_absent(tmp_path,
                                                                           monkeypatch):
    from click.testing import CliRunner
    from core.crypto import SignerUnavailable
    from laptop.cli import cli
    import laptop.sign_cli as sign_cli

    runner = CliRunner()
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "no-record-here"))
    monkeypatch.setenv("COUNSELOG_ENV_FILE", str(tmp_path / "absent.env"))

    request = tmp_path / "request.json"
    request.write_text(detached.SigningRequest(seq=3, entry_hash="a" * 64).to_json())

    def no_key(pin):
        raise SignerUnavailable("No YubiKey found. Plug one in and try again.")

    monkeypatch.setattr(sign_cli, "build_signer", no_key)
    result = runner.invoke(cli, ["sign-offline", str(request),
                                 str(tmp_path / "out.json")], input="1234\n")

    assert result.exit_code != 0
    assert "Plug one in" in result.output
