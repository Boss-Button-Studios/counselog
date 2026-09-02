"""Phase 6: capture while locked.

The spool exists so a note can be written without unlocking anything, which is
what lets the reading window be five minutes. That means it accepts writes from
a server holding no secret — so every test here is about what the *unlocked*
server catches afterwards.

These attack the spool the way someone with write access to the file would.
"""

import os

import pytest

from core import spool
from core.spool import SpoolError


@pytest.fixture
def identity():
    return spool.new_identity()


@pytest.fixture
def conn(tmp_path):
    connection = spool.connect(tmp_path / "spool.db")
    yield connection
    connection.close()


@pytest.fixture
def device():
    return "phone", os.urandom(32)


def _write(conn, public, device, text, captured_at=None):
    device_id, secret = device
    captured_at = captured_at or spool.utc_now()
    mac = spool.device_mac(secret, text, captured_at, device_id)
    return spool.append(conn, public, text=text, captured_at=captured_at,
                        device_id=device_id, mac=mac)


def _drain(conn, identity, device, from_seq=0, expected_head=None):
    private, _ = identity
    device_id, secret = device
    return spool.drain(conn, private_key=private, device_secrets={device_id: secret},
                       from_seq=from_seq,
                       expected_head=expected_head or spool.GENESIS)


# ── the point of it ──────────────────────────────────────────────────────────


def test_a_note_can_be_written_with_no_key_available(conn, identity, device):
    """Only the public half is needed to write — the whole reason this exists."""
    _, public = identity
    _write(conn, public, device, "Ada pushed back on the timeline.")
    accepted, quarantined = _drain(conn, identity, device)
    assert [n.text for n in accepted] == ["Ada pushed back on the timeline."]
    assert quarantined == []


def test_the_note_is_not_readable_in_the_file(conn, identity, device, tmp_path):
    _, public = identity
    _write(conn, public, device, "Ada pushed back on the timeline.")
    conn.commit()
    raw = (tmp_path / "spool.db").read_bytes()
    assert b"Ada pushed back" not in raw
    assert b"timeline" not in raw


def test_two_identical_notes_do_not_look_identical(conn, identity, device):
    """A fresh ephemeral key per note, so the file does not leak repetition."""
    _, public = identity
    _write(conn, public, device, "same words")
    _write(conn, public, device, "same words")
    rows = [r["ciphertext"] for r in conn.execute("SELECT ciphertext FROM entries")]
    assert rows[0] != rows[1]


def test_order_is_preserved(conn, identity, device):
    _, public = identity
    for text in ("first", "second", "third"):
        _write(conn, public, device, text)
    accepted, _ = _drain(conn, identity, device)
    assert [n.text for n in accepted] == ["first", "second", "third"]


def test_draining_twice_returns_nothing_the_second_time(conn, identity, device):
    _, public = identity
    _write(conn, public, device, "a note")
    accepted, _ = _drain(conn, identity, device)
    last = accepted[-1]
    head_hash = spool.head(conn)[1]
    again, _ = _drain(conn, identity, device, from_seq=last.seq, expected_head=head_hash)
    assert again == []


# ── tampering with the file ──────────────────────────────────────────────────


def test_altering_an_entry_is_caught(conn, identity, device):
    _, public = identity
    _write(conn, public, device, "the original note")
    conn.execute("UPDATE entries SET ciphertext = ? WHERE seq = 1", (os.urandom(80),))
    conn.commit()
    accepted, quarantined = _drain(conn, identity, device)
    assert accepted == []
    assert len(quarantined) == 1


def test_deleting_an_entry_is_caught(conn, identity, device):
    """The next entry no longer follows the one before it."""
    _, public = identity
    for text in ("first", "second", "third"):
        _write(conn, public, device, text)
    conn.execute("DELETE FROM entries WHERE seq = 2")
    conn.commit()
    accepted, quarantined = _drain(conn, identity, device)
    assert any("does not follow" in q.reason for q in quarantined)
    assert "second" not in [n.text for n in accepted]


def test_reordering_is_caught(conn, identity, device):
    _, public = identity
    _write(conn, public, device, "first")
    _write(conn, public, device, "second")
    rows = list(conn.execute("SELECT * FROM entries ORDER BY seq"))
    conn.execute("DELETE FROM entries")
    for new_seq, row in zip((1, 2), reversed(rows)):
        conn.execute(
            "INSERT INTO entries (seq, ciphertext, mac, device_id, prev_hash, "
            "entry_hash, received_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (new_seq, row["ciphertext"], row["mac"], row["device_id"],
             row["prev_hash"], row["entry_hash"], row["received_at"]),
        )
    conn.commit()
    _, quarantined = _drain(conn, identity, device)
    assert quarantined, "reordering must not pass"


def test_a_wholesale_rewrite_is_caught(conn, identity, device):
    """The head recorded in the encrypted database is the anchor.

    An attacker can rebuild a perfectly consistent spool from scratch — but not
    one that continues from a value they were never able to read.
    """
    _, public = identity
    _write(conn, public, device, "the real note")
    accepted, _ = _drain(conn, identity, device)
    anchored_head = spool.head(conn)[1]

    # Start over with an internally consistent spool of the attacker's choosing.
    conn.execute("DELETE FROM entries")
    conn.commit()
    _write(conn, public, device, "a note that was never written")

    accepted, quarantined = _drain(conn, identity, device, expected_head=anchored_head)
    assert accepted == []
    assert any("altered" in q.reason for q in quarantined)


# ── forgery ──────────────────────────────────────────────────────────────────


def test_a_note_from_an_unenrolled_device_is_quarantined(conn, identity, device):
    """Sealing needs only the public key, so anyone can write a well-formed
    entry. Being enrolled is what makes it genuine."""
    _, public = identity
    intruder_secret = os.urandom(32)
    now = spool.utc_now()
    text = "a note nobody wrote"
    spool.append(conn, public, text=text, captured_at=now, device_id="intruder",
                 mac=spool.device_mac(intruder_secret, text, now, "intruder"))

    accepted, quarantined = _drain(conn, identity, device)
    assert accepted == []
    assert "not enrolled" in quarantined[0].reason


def test_a_note_with_a_forged_mac_is_quarantined(conn, identity, device):
    """The attacker knows the device id but not its key."""
    _, public = identity
    device_id, _ = device
    now = spool.utc_now()
    text = "a note the phone never wrote"
    spool.append(conn, public, text=text, captured_at=now, device_id=device_id,
                 mac=spool.device_mac(os.urandom(32), text, now, device_id))

    accepted, quarantined = _drain(conn, identity, device)
    assert accepted == []
    assert "not written by the device" in quarantined[0].reason


def test_replaying_one_devices_note_as_another_is_caught(conn, identity, device):
    """The MAC covers the device id, so an entry cannot be relabelled."""
    _, public = identity
    device_id, secret = device
    now = spool.utc_now()
    text = "a genuine note"
    mac = spool.device_mac(secret, text, now, device_id)
    # Same content and MAC, but claiming a different device.
    spool.append(conn, public, text=text, captured_at=now, device_id="tablet", mac=mac)

    other_secret = os.urandom(32)
    private, _ = identity
    accepted, quarantined = spool.drain(
        conn, private_key=private,
        device_secrets={device_id: secret, "tablet": other_secret},
        from_seq=0, expected_head=spool.GENESIS)
    assert accepted == []
    assert quarantined


def test_moving_a_notes_timestamp_is_caught(conn, identity, device):
    """captured_at is inside what the device stamps."""
    _, public = identity
    device_id, secret = device
    text = "written today"
    honest = spool.utc_now()
    mac = spool.device_mac(secret, text, honest, device_id)
    # Seal it with a different time than the one that was stamped.
    spool.append(conn, public, text=text, captured_at="2020-01-01T00:00:00+00:00",
                 device_id=device_id, mac=mac)

    accepted, quarantined = _drain(conn, identity, device)
    assert accepted == []
    assert quarantined


def test_one_bad_entry_does_not_block_the_genuine_ones_behind_it(conn, identity, device):
    """Refusing everything after a single forgery would let an attacker deny you
    your own notes by writing one bad entry."""
    _, public = identity
    device_id, secret = device
    _write(conn, public, device, "genuine before")
    now = spool.utc_now()
    spool.append(conn, public, text="forged", captured_at=now, device_id=device_id,
                 mac=spool.device_mac(os.urandom(32), "forged", now, device_id))
    _write(conn, public, device, "genuine after")

    accepted, quarantined = _drain(conn, identity, device)
    assert [n.text for n in accepted] == ["genuine before", "genuine after"]
    assert len(quarantined) == 1


def test_an_empty_note_is_refused(conn, identity, device):
    _, public = identity
    with pytest.raises(SpoolError):
        _write(conn, public, device, "   ")


def test_an_enormous_note_is_refused(conn, identity, device):
    _, public = identity
    with pytest.raises(SpoolError):
        _write(conn, public, device, "x" * (spool.MAX_NOTE_CHARS + 1))


def test_the_spool_file_is_owner_only(conn, tmp_path):
    assert oct((tmp_path / "spool.db").stat().st_mode & 0o777) == "0o600"


def test_a_sealed_note_cannot_be_opened_with_the_wrong_key(identity):
    _, public = identity
    sealed = spool.seal(public, b"secret note")
    other_private, _ = spool.new_identity()
    with pytest.raises(Exception):
        spool.unseal(other_private, sealed)
