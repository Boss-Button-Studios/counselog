"""Phase 1: envelope encryption, factors, and key custody.

The scenario driving most of these is spec §6: a supervisor with two YubiKeys
and a password, one key lost, notes that must stay readable throughout.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

import pytest

from core.crypto import (
    DekSession,
    FactorError,
    FactorUnavailable,
    Keyring,
    KeyringError,
    LastWrapperError,
    PasswordFactor,
    SessionClosed,
    SessionExpired,
    UnlockFailed,
    YubiKeyFactor,
    new_dek,
)

# ── test doubles ─────────────────────────────────────────────────────────────


def fake_key(secret: bytes):
    """A stand-in for one physical YubiKey's OTP slot.

    Real HMAC-SHA1, fake hardware — so the derivation path under test is the
    production one. The desktop has no YubiKey, so this is how phase 1 gets
    tested at all (see tasks.md).
    """

    def responder(challenge: bytes, slot: int) -> bytes:
        return hmac.new(secret, challenge, hashlib.sha1).digest()

    return responder


def yubikey(secret: bytes) -> YubiKeyFactor:
    return YubiKeyFactor(responder=fake_key(secret))


@pytest.fixture
def keyring_path(tmp_path):
    return tmp_path / "keyring.json"


# ── the core promise: several ways in, one database ──────────────────────────


def test_three_factors_all_unwrap_the_same_dek(keyring_path):
    """Two YubiKeys and a password, one database. Spec §6's central claim."""
    dek = new_dek()
    ring = Keyring(keyring_path)
    key_a, key_b = secrets.token_bytes(20), secrets.token_bytes(20)

    ring.add(dek, yubikey(key_a), "primary yubikey")
    ring.add(dek, yubikey(key_b), "backup in the safe")
    ring.add(dek, PasswordFactor("correct horse battery staple"), "password fallback")

    assert ring.unlock(yubikey(key_a)) == dek
    assert ring.unlock(yubikey(key_b)) == dek
    assert ring.unlock(PasswordFactor("correct horse battery staple")) == dek


def test_adding_a_key_does_not_disturb_the_others(keyring_path):
    """Registering a third key must not invalidate the first two."""
    dek = new_dek()
    ring = Keyring(keyring_path)
    key_a, key_b = secrets.token_bytes(20), secrets.token_bytes(20)
    ring.add(dek, yubikey(key_a), "a")
    ring.add(dek, PasswordFactor("pw"), "pw")

    ring.add(ring.unlock(yubikey(key_a)), yubikey(key_b), "b")

    assert ring.unlock(yubikey(key_a)) == dek
    assert ring.unlock(PasswordFactor("pw")) == dek
    assert ring.unlock(yubikey(key_b)) == dek


def test_an_unregistered_key_never_unlocks(keyring_path):
    ring = Keyring(keyring_path)
    ring.add(new_dek(), yubikey(secrets.token_bytes(20)), "mine")
    with pytest.raises(UnlockFailed):
        ring.unlock(yubikey(secrets.token_bytes(20)))


def test_wrong_password_is_rejected(keyring_path):
    ring = Keyring(keyring_path)
    ring.add(new_dek(), PasswordFactor("hunter2"), "pw")
    with pytest.raises(UnlockFailed):
        ring.unlock(PasswordFactor("hunter3"))


def test_unlocking_with_an_unregistered_factor_type(keyring_path):
    """Password-only keyring, asked for a YubiKey: say so, do not just fail."""
    ring = Keyring(keyring_path)
    ring.add(new_dek(), PasswordFactor("pw"), "pw")
    with pytest.raises(UnlockFailed, match="No yubikey is registered"):
        ring.unlock(yubikey(secrets.token_bytes(20)))


# ── revocation ───────────────────────────────────────────────────────────────


def test_revoked_key_stops_working_others_survive(keyring_path):
    dek = new_dek()
    ring = Keyring(keyring_path)
    lost, kept = secrets.token_bytes(20), secrets.token_bytes(20)
    lost_wrapper = ring.add(dek, yubikey(lost), "lost on the train")
    ring.add(dek, yubikey(kept), "still have it")

    ring.revoke(lost_wrapper.id)

    with pytest.raises(UnlockFailed):
        ring.unlock(yubikey(lost))
    assert ring.unlock(yubikey(kept)) == dek


def test_cannot_revoke_the_last_way_in(keyring_path):
    """Guideline 2. Emptying the keyring would orphan every note, silently."""
    ring = Keyring(keyring_path)
    only = ring.add(new_dek(), PasswordFactor("pw"), "only")
    with pytest.raises(LastWrapperError, match="only way into your notes"):
        ring.revoke(only.id)
    assert len(ring) == 1


def test_revoking_an_unknown_id_is_an_error(keyring_path):
    ring = Keyring(keyring_path)
    ring.add(new_dek(), PasswordFactor("pw"), "pw")
    ring.add(new_dek(), PasswordFactor("pw2"), "pw2")
    with pytest.raises(KeyringError, match="No registered key"):
        ring.revoke("deadbeef")


# ── rotation: the honest answer to a key that may have been copied ───────────


def test_rotation_replaces_the_dek_and_keeps_everyone_working(keyring_path):
    old_dek = new_dek()
    ring = Keyring(keyring_path)
    key_a = secrets.token_bytes(20)
    ring.add(old_dek, yubikey(key_a), "a")
    ring.add(old_dek, PasswordFactor("pw"), "pw")

    rotated = new_dek()
    ring.rewrap_all(rotated, {"yubikey": yubikey(key_a), "password": PasswordFactor("pw")})

    assert ring.unlock(yubikey(key_a)) == rotated
    assert ring.unlock(PasswordFactor("pw")) == rotated
    assert ring.unlock(yubikey(key_a)) != old_dek


def test_rotation_refuses_when_a_registered_factor_is_absent(keyring_path):
    """Rotating without the backup key present would lock that key out."""
    dek = new_dek()
    ring = Keyring(keyring_path)
    ring.add(dek, yubikey(secrets.token_bytes(20)), "yubikey in a drawer")
    ring.add(dek, PasswordFactor("pw"), "pw")

    with pytest.raises(KeyringError, match="missing yubikey"):
        ring.rewrap_all(new_dek(), {"password": PasswordFactor("pw")})

    assert ring.unlock(PasswordFactor("pw")) == dek  # untouched


def test_failed_rotation_leaves_the_keyring_usable(keyring_path):
    """A factor that throws mid-rotation must not leave a half-rotated ring."""
    dek = new_dek()
    ring = Keyring(keyring_path)
    ring.add(dek, PasswordFactor("pw"), "pw")
    ring.add(dek, yubikey(secrets.token_bytes(20)), "yk")

    class Exploding:
        name = "yubikey"

        def new_params(self):
            raise FactorUnavailable("key yanked out mid-rotation")

        def derive_kek(self, params):  # pragma: no cover
            raise AssertionError("should not get here")

    with pytest.raises(FactorUnavailable):
        ring.rewrap_all(new_dek(), {"password": PasswordFactor("pw"), "yubikey": Exploding()})

    assert ring.unlock(PasswordFactor("pw")) == dek


# ── tamper resistance ────────────────────────────────────────────────────────


def test_swapping_ciphertext_between_entries_fails(keyring_path):
    """The AAD binds each wrapper to its own id and factor."""
    dek = new_dek()
    ring = Keyring(keyring_path)
    key_a, key_b = secrets.token_bytes(20), secrets.token_bytes(20)
    ring.add(dek, yubikey(key_a), "a")
    ring.add(dek, yubikey(key_b), "b")
    ring.save()

    raw = json.loads(keyring_path.read_text())
    raw["wrappers"][0]["ciphertext"] = raw["wrappers"][1]["ciphertext"]
    raw["wrappers"][0]["nonce"] = raw["wrappers"][1]["nonce"]
    keyring_path.write_text(json.dumps(raw))

    with pytest.raises(UnlockFailed):
        Keyring.load(keyring_path).unlock(yubikey(key_a))


def test_flipping_a_ciphertext_bit_is_detected(keyring_path):
    dek = new_dek()
    ring = Keyring(keyring_path)
    ring.add(dek, PasswordFactor("pw"), "pw")
    ring.save()

    raw = json.loads(keyring_path.read_text())
    ct = bytearray(base64.b64decode(raw["wrappers"][0]["ciphertext"]))
    ct[0] ^= 0x01
    raw["wrappers"][0]["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    keyring_path.write_text(json.dumps(raw))

    with pytest.raises(UnlockFailed):
        Keyring.load(keyring_path).unlock(PasswordFactor("pw"))


def test_absurd_scrypt_parameters_are_rejected(keyring_path):
    """The keyring sits outside the encrypted DB, so treat it as untrusted."""
    ring = Keyring(keyring_path)
    ring.add(new_dek(), PasswordFactor("pw"), "pw")
    ring.save()

    raw = json.loads(keyring_path.read_text())
    raw["wrappers"][0]["params"]["n"] = 2**30  # would try to allocate ~1 TB
    keyring_path.write_text(json.dumps(raw))

    with pytest.raises(UnlockFailed):
        Keyring.load(keyring_path).unlock(PasswordFactor("pw"))


# ── the keyring file ─────────────────────────────────────────────────────────


def test_keyring_round_trips_through_disk(keyring_path):
    dek = new_dek()
    ring = Keyring(keyring_path)
    key_a = secrets.token_bytes(20)
    ring.add(dek, yubikey(key_a), "primary")
    ring.add(dek, PasswordFactor("pw"), "fallback")
    ring.save()

    reloaded = Keyring.load(keyring_path)
    assert len(reloaded) == 2
    assert reloaded.unlock(yubikey(key_a)) == dek
    assert [w.label for w in reloaded.wrappers] == ["primary", "fallback"]


def test_keyring_file_holds_no_secrets(keyring_path):
    """Salts, challenges and ciphertext are safe to read. The DEK is not."""
    dek = new_dek()
    ring = Keyring(keyring_path)
    ring.add(dek, PasswordFactor("hunter2"), "pw")
    ring.save()

    text = keyring_path.read_text()
    assert dek.hex() not in text
    assert base64.b64encode(dek).decode() not in text
    assert "hunter2" not in text


def test_keyring_file_is_owner_only(keyring_path):
    ring = Keyring(keyring_path)
    ring.add(new_dek(), PasswordFactor("pw"), "pw")
    ring.save()
    assert oct(keyring_path.stat().st_mode & 0o777) == "0o600"


def test_save_is_atomic_and_leaves_no_debris(keyring_path):
    ring = Keyring(keyring_path)
    ring.add(new_dek(), PasswordFactor("pw"), "pw")
    ring.save()
    ring.save()
    leftovers = [p.name for p in keyring_path.parent.iterdir() if p.name.startswith(".keyring-")]
    assert leftovers == []


def test_missing_keyring_says_what_to_do(keyring_path):
    with pytest.raises(KeyringError, match="keys init"):
        Keyring.load(keyring_path)


def test_future_keyring_version_is_refused(keyring_path):
    keyring_path.write_text(json.dumps({"version": 99, "wrappers": []}))
    with pytest.raises(KeyringError, match="not supported"):
        Keyring.load(keyring_path)


def test_corrupt_keyring_is_reported_clearly(keyring_path):
    keyring_path.write_text("{not json")
    with pytest.raises(KeyringError, match="not valid JSON"):
        Keyring.load(keyring_path)


# ── factors ──────────────────────────────────────────────────────────────────


def test_password_is_nfc_normalised():
    """The same password typed two ways must derive the same KEK.

    'é' can be one code point or 'e' plus a combining accent. Without
    normalisation the second form would silently fail to unlock.
    """
    composed, decomposed = "café", "café"
    assert composed != decomposed
    params = PasswordFactor(composed).new_params()
    assert PasswordFactor(composed).derive_kek(params) == PasswordFactor(decomposed).derive_kek(params)


def test_empty_password_is_refused():
    with pytest.raises(FactorUnavailable):
        PasswordFactor("")


def test_each_registration_gets_a_fresh_challenge():
    """Two registrations of the same physical key must not share a challenge."""
    factor = yubikey(secrets.token_bytes(20))
    assert factor.new_params()["challenge"] != factor.new_params()["challenge"]


def test_yubikey_rejects_a_bad_slot():
    with pytest.raises(FactorError):
        YubiKeyFactor(slot=3)


def test_yubikey_rejects_a_truncated_challenge():
    factor = yubikey(secrets.token_bytes(20))
    params = factor.new_params()
    params["challenge"] = base64.b64encode(b"too short").decode()
    with pytest.raises(FactorError, match="wrong length"):
        factor.derive_kek(params)


def test_missing_hardware_is_distinguished_from_a_wrong_key(keyring_path):
    """'Plug in your key' and 'that is the wrong key' are different messages."""

    def absent(challenge, slot):
        raise FactorUnavailable("No YubiKey found. Plug one in and try again.")

    ring = Keyring(keyring_path)
    ring.add(new_dek(), yubikey(secrets.token_bytes(20)), "yk")
    with pytest.raises(UnlockFailed, match="Plug one in"):
        ring.unlock(YubiKeyFactor(responder=absent))


# ── session custody ──────────────────────────────────────────────────────────


def test_session_hands_back_the_key_then_forgets_it():
    dek = new_dek()
    session = DekSession(dek, ttl_seconds=60)
    assert session.dek == dek
    session.close()
    with pytest.raises(SessionClosed):
        _ = session.dek


def test_expired_session_refuses_and_wipes():
    session = DekSession(new_dek(), ttl_seconds=0.05)
    time.sleep(0.1)
    with pytest.raises(SessionExpired):
        _ = session.dek


def test_renew_extends_but_cannot_resurrect():
    session = DekSession(new_dek(), ttl_seconds=0.05)
    session.renew()
    assert session.dek is not None
    time.sleep(0.1)
    with pytest.raises(SessionExpired):
        session.renew()


def test_session_context_manager_closes_on_exit():
    dek = new_dek()
    with DekSession(dek, ttl_seconds=60) as session:
        assert session.dek == dek
    with pytest.raises(SessionClosed):
        _ = session.dek


def test_closing_twice_is_safe():
    session = DekSession(new_dek(), ttl_seconds=60)
    session.close()
    session.close()


def test_repr_never_leaks_the_key():
    """A traceback or a debug log must not become a key disclosure."""
    dek = new_dek()
    session = DekSession(dek, ttl_seconds=60)
    assert dek.hex() not in repr(session)
    assert "DekSession" in repr(session)
