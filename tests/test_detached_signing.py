"""Signing a record on a machine that does not hold it.

The key and the notes do not have to live together, and it is better when they
do not: a machine holding both is a machine where one compromise takes
everything. Signing needs the chain position and the head's hash and never
touches note text, so only a hash has to travel.

The two files cross a machine boundary, possibly on a USB stick, and are
trivially editable. Most of what is tested here is therefore refusal: a
signature about a different record, a file from a different version, a hash that
is not a hash. The rest is that the honest round trip works and that nothing
private is in either file.
"""

import json

import pytest

from core import db, detached, models, signatures
from core.crypto.signing import SoftwareSigner

KEY = bytes(range(32))


@pytest.fixture
def conn(tmp_path):
    connection = db.create(tmp_path / "notes.db", KEY)
    yield connection
    connection.close()


@pytest.fixture
def written(conn):
    for text in ("Ada raised the timeline", "Tom asked for Friday"):
        models.add_note(conn, text)
    return models.chain_head(conn)


@pytest.fixture
def signer():
    return SoftwareSigner.generate()


# ── the round trip ───────────────────────────────────────────────────────────


def test_a_record_can_be_signed_on_a_machine_that_does_not_hold_it(conn, written,
                                                                   signer):
    request = signatures.request_for_head(conn)

    # Everything from here would happen on the other machine, with no database.
    carried = request.to_json()
    signed = signatures.sign_request(detached.read_request(carried), signer)

    # And back again.
    recorded = signatures.attach(conn, detached.read_signature(signed.to_json()),
                                 label="laptop")

    assert recorded.covers_seq == written.seq
    assert signatures.verify_coverage(conn).ok


def test_the_carried_files_contain_no_note_text(conn, written, signer):
    """The whole argument for this rests on it, so it is asserted rather than
    reasoned about."""
    request = signatures.request_for_head(conn)
    signed = signatures.sign_request(request, signer)

    for carried in (request.to_json(), signed.to_json()):
        assert "Ada raised the timeline" not in carried
        assert "Tom asked for Friday" not in carried


def test_the_request_carries_only_a_position_and_a_hash(conn, written):
    """A hash the tool already tells you to keep somewhere else. If this file
    ever grows a field, it should be a decision, not a drift."""
    fields = json.loads(signatures.request_for_head(conn).to_json())
    assert set(fields) == {"format", "format_version", "signed_version", "seq",
                           "entry_hash"}


def test_signing_a_request_needs_no_database(signer):
    """The machine with the key may have no record on it at all."""
    request = detached.SigningRequest(seq=1, entry_hash="a" * 64)
    signed = signatures.sign_request(request, signer)

    assert signed.seq == 1
    assert signed.signature


# ── refusals ─────────────────────────────────────────────────────────────────


def test_a_signature_about_a_different_record_is_refused(conn, written, signer):
    """The failure that matters most: two records, one key, and a file that
    looks right. Position 2 exists here, but with a different hash."""
    elsewhere = detached.SigningRequest(seq=written.seq, entry_hash="b" * 64)
    signed = signatures.sign_request(elsewhere, signer)

    with pytest.raises(signatures.SignatureError, match="different record"):
        signatures.attach(conn, signed)


def test_a_signature_for_a_position_not_in_the_chain_is_refused(conn, written,
                                                                signer):
    ahead = detached.SigningRequest(seq=written.seq + 5, entry_hash="c" * 64)
    signed = signatures.sign_request(ahead, signer)

    with pytest.raises(signatures.SignatureError, match="not in this record"):
        signatures.attach(conn, signed)


def test_a_tampered_signature_is_refused(conn, written, signer):
    signed = signatures.sign_request(signatures.request_for_head(conn), signer)
    broken = detached.DetachedSignature(
        seq=signed.seq, entry_hash=signed.entry_hash,
        signed_at="2020-01-01T00:00:00+00:00",  # moved after signing
        algorithm=signed.algorithm, public_key=signed.public_key,
        signature=signed.signature)

    with pytest.raises(signatures.SignatureError, match="does not verify"):
        signatures.attach(conn, broken)


def test_nothing_is_stored_when_a_signature_is_refused(conn, written, signer):
    """A row that cannot be verified would be reported as tampering every time
    the record is checked from then on — a permanent false alarm."""
    elsewhere = detached.SigningRequest(seq=written.seq, entry_hash="b" * 64)
    with pytest.raises(signatures.SignatureError):
        signatures.attach(conn, signatures.sign_request(elsewhere, signer))

    assert signatures.list_signatures(conn) == []
    assert conn.execute("SELECT COUNT(*) AS n FROM signing_keys").fetchone()["n"] == 0


def test_attaching_the_same_file_twice_is_refused_kindly(conn, written, signer):
    """These files are carried by hand, so this will happen."""
    signed = signatures.sign_request(signatures.request_for_head(conn), signer)
    signatures.attach(conn, signed)

    with pytest.raises(signatures.SignatureError, match="already in this record"):
        signatures.attach(conn, signed)
    assert len(signatures.list_signatures(conn)) == 1


def test_two_keys_may_both_sign_the_same_position(conn, written, signer):
    """A second device vouching is normal, and must not look like a duplicate."""
    request = signatures.request_for_head(conn)
    signatures.attach(conn, signatures.sign_request(request, signer))
    signatures.attach(conn, signatures.sign_request(request, SoftwareSigner.generate()))

    assert len(signatures.list_signatures(conn)) == 2
    assert signatures.verify_coverage(conn).ok


def test_an_empty_record_has_nothing_to_request(conn):
    with pytest.raises(signatures.SignatureError):
        signatures.request_for_head(conn)


# ── reading files that crossed a boundary ────────────────────────────────────


@pytest.mark.parametrize("text, complaint", [
    ("not json at all", "not readable as JSON"),
    ("[]", "does not contain what this expects"),
    ('{"format": "something.else", "format_version": 1}', "not a counselog"),
    ('{"format": "counselog.sign-request", "format_version": 99}', "version"),
])
def test_a_file_that_is_not_ours_is_refused_with_a_sentence(text, complaint):
    with pytest.raises(detached.DetachedError, match=complaint):
        detached.read_request(text)


@pytest.mark.parametrize("seq", [0, -1, "3", 1.5, True, None])
def test_a_position_that_is_not_a_position_is_refused(seq):
    text = json.dumps({"format": detached.REQUEST_MARKER, "format_version": 1,
                       "signed_version": 1, "seq": seq, "entry_hash": "a" * 64})
    with pytest.raises(detached.DetachedError, match="not a position"):
        detached.read_request(text)


@pytest.mark.parametrize("value", ["", "z" * 64, "AB" * 32, "a" * 63, 12, None])
def test_a_hash_that_is_not_a_hash_is_refused(value):
    """Uppercase hex is refused too: this program writes lowercase, so anything
    else did not come from it."""
    text = json.dumps({"format": detached.REQUEST_MARKER, "format_version": 1,
                       "signed_version": 1, "seq": 1, "entry_hash": value})
    with pytest.raises(detached.DetachedError, match="not a hash"):
        detached.read_request(text)


def test_an_enormous_file_is_refused_before_it_is_parsed():
    with pytest.raises(detached.DetachedError, match="far too big"):
        detached.read_request("x" * (detached.MAX_FILE_BYTES + 1))


def test_a_signature_file_with_unreadable_key_material_is_refused(signer):
    signed = signatures.sign_request(
        detached.SigningRequest(seq=1, entry_hash="a" * 64), signer)
    fields = json.loads(signed.to_json())
    fields["public_key"] = "not base64!!"

    with pytest.raises(detached.DetachedError, match="not readable"):
        detached.read_signature(json.dumps(fields))


def test_a_signature_file_naming_another_algorithm_is_refused(signer):
    signed = signatures.sign_request(
        detached.SigningRequest(seq=1, entry_hash="a" * 64), signer)
    fields = json.loads(signed.to_json())
    fields["algorithm"] = "ed25519"

    with pytest.raises(detached.DetachedError, match="cannot check"):
        detached.read_signature(json.dumps(fields))


def test_a_request_read_as_a_signature_says_which_it_is():
    """The two files look alike and will be mixed up."""
    request = detached.SigningRequest(seq=1, entry_hash="a" * 64)
    with pytest.raises(detached.DetachedError, match="sign-request"):
        detached.read_signature(request.to_json())
