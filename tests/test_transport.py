"""Phase 3: certificates, the wire protocol, sessions, the mirror, the service.

The last group runs a real TLS server on an ephemeral port. Faking the handshake
would test our own mocks; the point of mutual TLS is that the socket layer turns
strangers away, and only a real socket proves it.
"""

import secrets
import ssl
import threading

import httpx
import pytest
from cryptography import x509
from werkzeug.serving import make_server

from core import chain, db, models, protocol
from core.certs import (
    CertificateError,
    CertPaths,
    client_context,
    create_ca,
    issue_client,
    issue_server,
    server_context,
)
from desktop import mirror
from desktop.__main__ import MutualTLSRequestHandler
from desktop.service import create_app
from desktop.sessions import NoSuchSession, SessionStore

DEVICE = "laptop"


@pytest.fixture
def certs(tmp_path):
    paths = CertPaths(tmp_path / "certs")
    create_ca(paths)
    issue_server(paths, ["desktop.example.ts.net"], ["100.64.1.2"])
    issue_client(paths, DEVICE)
    return paths


# ── certificates ─────────────────────────────────────────────────────────────


def test_server_certificate_covers_names_and_addresses(certs):
    """A cert issued for a name but dialled by address fails confusingly."""
    cert = x509.load_pem_x509_certificate(certs.cert("server").read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "desktop.example.ts.net" in san.get_values_for_type(x509.DNSName)
    assert "localhost" in san.get_values_for_type(x509.DNSName)  # loopback mode
    assert str(san.get_values_for_type(x509.IPAddress)[0]) == "100.64.1.2"


def test_client_certificate_names_the_device(certs):
    """The service identifies devices by this, so it must be present."""
    cert = x509.load_pem_x509_certificate(certs.cert(DEVICE).read_bytes())
    assert "CN=laptop" in cert.subject.rfc4514_string()


def test_private_keys_are_owner_only(certs):
    for name in ("ca", "server", DEVICE):
        assert oct(certs.key(name).stat().st_mode & 0o777) == "0o600"


def test_each_device_gets_its_own_certificate(certs):
    """Spec §10 extends capture to more devices; sharing one cert would mean
    revoking one device revokes them all."""
    issue_client(certs, "phone")
    laptop = x509.load_pem_x509_certificate(certs.cert(DEVICE).read_bytes())
    phone = x509.load_pem_x509_certificate(certs.cert("phone").read_bytes())
    assert laptop.serial_number != phone.serial_number
    assert laptop.public_key().public_numbers() != phone.public_key().public_numbers()


def test_the_server_demands_a_client_certificate(certs):
    assert server_context(certs).verify_mode == ssl.CERT_REQUIRED


def test_the_client_checks_the_server_name(certs):
    context = client_context(certs, DEVICE)
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname


def test_missing_certificates_say_what_to_run(tmp_path):
    with pytest.raises(CertificateError, match="certs init"):
        server_context(CertPaths(tmp_path / "nothing"))


def test_a_bad_address_is_rejected(certs):
    with pytest.raises(CertificateError, match="not a valid IP"):
        issue_server(certs, ["host"], ["not-an-ip"])


# ── protocol ─────────────────────────────────────────────────────────────────


def _payload(note_id=1, seq=1, text="hello", prev=None, tombstoned=None):
    prev = prev or chain.GENESIS_HASH
    body = chain.body_hash(note_id=note_id, captured_at="2026-08-30T00:00:00+00:00",
                           backdated_at=None, source_type="text_prompt",
                           source_trust="self_authored", raw_text=text)
    return protocol.NotePayload(
        note_id=note_id, captured_at="2026-08-30T00:00:00+00:00", backdated_at=None,
        source_type="text_prompt", source_trust="self_authored", raw_text=text,
        tombstoned_at=tombstoned, seq=seq, body_hash=body, prev_hash=prev,
        entry_hash=chain.link_hash(prev, body), hashed_at="2026-08-30T00:00:00+00:00",
    )


def test_a_valid_payload_round_trips():
    original = _payload()
    assert protocol.NotePayload.from_json(original.to_json()) == original


def test_a_note_that_does_not_match_its_chain_entry_is_refused():
    """The mirror must never store something that never existed."""
    tampered = protocol.NotePayload.from_json({**_payload().to_json(), "raw_text": "changed"})
    with pytest.raises(protocol.ProtocolError, match="does not match the chain entry"):
        tampered.verify_self_consistency()


def test_an_inconsistent_chain_entry_is_refused():
    broken = protocol.NotePayload.from_json({**_payload().to_json(), "entry_hash": "0" * 64})
    with pytest.raises(protocol.ProtocolError, match="not self-consistent"):
        broken.verify_self_consistency()


def test_a_tombstoned_note_skips_the_body_check_but_not_the_link():
    """Its text was destroyed on purpose and cannot be recomputed."""
    body = "a" * 64
    entry = protocol.NotePayload(
        note_id=1, captured_at="t", backdated_at=None, source_type="text_prompt",
        source_trust="self_authored", raw_text="", tombstoned_at="t", seq=1,
        body_hash=body, prev_hash=chain.GENESIS_HASH,
        entry_hash=chain.link_hash(chain.GENESIS_HASH, body), hashed_at="t",
    )
    entry.verify_self_consistency()


@pytest.mark.parametrize("field, value", [
    ("note_id", "one"), ("note_id", 0), ("note_id", True),
    ("source_type", "smuggled"), ("source_trust", "trusted"),
    ("body_hash", "nothex"), ("seq", -1),
])
def test_malformed_fields_are_refused(field, value):
    with pytest.raises(protocol.ProtocolError):
        protocol.NotePayload.from_json({**_payload().to_json(), field: value})


def test_out_of_order_batches_are_refused():
    second = _payload(note_id=2, seq=2)
    with pytest.raises(protocol.ProtocolError, match="chain order"):
        protocol.parse_batch([second.to_json(), _payload().to_json()])


def test_oversized_batches_are_refused():
    with pytest.raises(protocol.ProtocolError, match="Too many"):
        protocol.parse_batch([_payload().to_json()] * (protocol.MAX_BATCH + 1))


def test_a_bad_key_is_refused():
    for bad in (None, 123, "not base64!", protocol.encode_key(b"short")):
        with pytest.raises(protocol.ProtocolError):
            protocol.decode_key(bad)


# ── sessions ─────────────────────────────────────────────────────────────────


def test_a_session_returns_the_key_to_its_own_device():
    store = SessionStore()
    dek = secrets.token_bytes(32)
    assert store.key_for(store.open(DEVICE, dek, 60), DEVICE) == dek


def test_another_device_cannot_use_a_session():
    """A leaked session id must not work from a different enrolled device."""
    store = SessionStore()
    session_id = store.open(DEVICE, secrets.token_bytes(32), 60)
    with pytest.raises(NoSuchSession):
        store.key_for(session_id, "phone")


def test_closing_a_session_discards_the_key():
    store = SessionStore()
    session_id = store.open(DEVICE, secrets.token_bytes(32), 60)
    assert store.close(session_id, DEVICE)
    with pytest.raises(NoSuchSession):
        store.key_for(session_id, DEVICE)


def test_close_all_drops_everything():
    """What shutdown relies on to seal the mirror."""
    store = SessionStore()
    for _ in range(3):
        store.open(DEVICE, secrets.token_bytes(32), 60)
    store.close_all()
    assert len(store) == 0


# ── mirror ───────────────────────────────────────────────────────────────────


@pytest.fixture
def mirror_conn(tmp_path):
    conn = db.create(tmp_path / "mirror.db", secrets.token_bytes(32))
    yield conn
    conn.close()


def test_the_mirror_stores_a_batch(mirror_conn):
    first = _payload()
    second = _payload(note_id=2, seq=2, text="second", prev=first.entry_hash)
    result = mirror.store(mirror_conn, [first, second])
    assert result.stored == 2
    assert result.head_seq == 2
    assert mirror.verify(mirror_conn).ok


def test_syncing_the_same_notes_twice_is_harmless(mirror_conn):
    """An interrupted sync must be safe to simply run again."""
    payloads = [_payload()]
    mirror.store(mirror_conn, payloads)
    again = mirror.store(mirror_conn, payloads)
    assert again.stored == 0 and again.skipped == 1
    assert mirror.verify(mirror_conn).ok


def test_a_batch_that_would_leave_a_gap_is_refused(mirror_conn):
    """A hole in the chain is indistinguishable from tampering forever after."""
    with pytest.raises(protocol.ProtocolError, match="expects 1"):
        mirror.store(mirror_conn, [_payload(note_id=5, seq=5)])
    assert mirror.head_seq(mirror_conn) == 0


def test_the_mirror_reproduces_the_laptops_chain(tmp_path):
    """Both machines must derive the same hashes from the same notes."""
    laptop = db.create(tmp_path / "notes.db", secrets.token_bytes(32))
    for text in ("first", "second", "third"):
        models.add_note(laptop, text)
    payloads = mirror.to_payloads(laptop)

    copy = db.create(tmp_path / "mirror.db", secrets.token_bytes(32))
    mirror.store(copy, payloads)

    assert [e.entry_hash for e in models.chain_entries(copy)] == \
           [e.entry_hash for e in models.chain_entries(laptop)]
    assert mirror.verify(copy).ok
    laptop.close()
    copy.close()


def test_only_notes_after_a_position_are_sent(tmp_path):
    conn = db.create(tmp_path / "notes.db", secrets.token_bytes(32))
    for text in ("a", "b", "c"):
        models.add_note(conn, text)
    assert [p.seq for p in mirror.to_payloads(conn, after_seq=2)] == [3]
    conn.close()


# ── the service, over real mutual TLS ────────────────────────────────────────


@pytest.fixture
def live_server(certs, tmp_path, monkeypatch):
    """A real TLS server on an ephemeral port."""
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "desktop-data"))
    app = create_app(SessionStore())
    server = make_server("127.0.0.1", 0, app, threaded=True,
                         ssl_context=server_context(certs),
                         request_handler=MutualTLSRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"https://localhost:{server.server_port}", certs
    server.shutdown()
    thread.join(timeout=5)


def test_an_enrolled_device_is_recognised(live_server):
    url, certs = live_server
    with httpx.Client(verify=client_context(certs, DEVICE)) as client:
        health = client.get(f"{url}/health").json()
    assert health["status"] == "ok"
    assert health["device"] == DEVICE


def test_a_certificate_from_another_authority_is_refused(live_server, tmp_path):
    """The property that makes listening on a tailnet acceptable."""
    url, certs = live_server
    rogue = CertPaths(tmp_path / "rogue")
    create_ca(rogue)
    issue_client(rogue, "attacker")

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(rogue.cert("attacker"), rogue.key("attacker"))
    context.load_verify_locations(certs.ca_cert)

    with pytest.raises(httpx.TransportError):
        with httpx.Client(verify=context) as client:
            client.get(f"{url}/health")


def test_no_certificate_at_all_is_refused(live_server):
    url, certs = live_server
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(certs.ca_cert)
    with pytest.raises(httpx.TransportError):
        with httpx.Client(verify=context) as client:
            client.get(f"{url}/health")


def test_notes_cannot_be_sent_without_a_session(live_server):
    url, certs = live_server
    with httpx.Client(verify=client_context(certs, DEVICE)) as client:
        response = client.post(f"{url}/sync", json={"notes": []})
    assert response.status_code == 401


def test_a_full_session_and_sync(live_server):
    """The whole handshake: lend the key, send notes, hand the key back."""
    url, certs = live_server
    dek = secrets.token_bytes(32)
    with httpx.Client(verify=client_context(certs, DEVICE), timeout=30) as client:
        session_id = client.post(f"{url}/session",
                                 json={"key": protocol.encode_key(dek)}).json()["session_id"]

        first = _payload()
        second = _payload(note_id=2, seq=2, text="second", prev=first.entry_hash)
        result = client.post(f"{url}/sync", json={
            "session_id": session_id,
            "notes": [first.to_json(), second.to_json()],
        }).json()
        assert result["stored"] == 2

        status = client.post(f"{url}/mirror/status", json={"session_id": session_id}).json()
        assert status["head_seq"] == 2 and status["verified"]

        assert client.request("DELETE", f"{url}/session/{session_id}").json()["closed"]
        # The key is gone; the mirror is sealed again.
        assert client.post(f"{url}/mirror/status",
                           json={"session_id": session_id}).status_code == 401


def test_the_service_refuses_a_tampered_note(live_server):
    """End to end: a note whose text does not match its chain entry."""
    url, certs = live_server
    with httpx.Client(verify=client_context(certs, DEVICE), timeout=30) as client:
        session_id = client.post(
            f"{url}/session", json={"key": protocol.encode_key(secrets.token_bytes(32))}
        ).json()["session_id"]
        bad = {**_payload().to_json(), "raw_text": "quietly changed in transit"}
        response = client.post(f"{url}/sync", json={"session_id": session_id, "notes": [bad]})
    assert response.status_code == 400
    assert "does not match" in response.json()["error"]
