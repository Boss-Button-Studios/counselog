"""Phase 4: the /people and /tag endpoints, over real mutual TLS.

The model itself is stubbed — it is benchmarked separately and takes minutes per
note. What is tested here is everything around it: what the desktop will accept,
what it refuses, and what happens when the model is unavailable.
"""

import secrets
import threading

import httpx
import pytest
from werkzeug.serving import make_server

from core import protocol
from core.certs import CertPaths, client_context, create_ca, issue_client, issue_server, server_context
from desktop import tagger
from desktop.__main__ import MutualTLSRequestHandler
from desktop.service import create_app
from desktop.sessions import SessionStore
from desktop.tagger import Tag

DEVICE = "laptop"


@pytest.fixture(autouse=True)
def never_call_a_real_model(monkeypatch):
    """No test in this file may reach the live model.

    A single accidental call costs a minute and a half and makes the suite
    unusable. Tests that want a specific answer override this afterwards.
    """
    def refuse(*args, **kwargs):
        raise AssertionError(
            "A test tried to call the real language model. Stub "
            "tagger.judge_self_team in the test instead."
        )
    monkeypatch.setattr(tagger, "judge_self_team", refuse)


@pytest.fixture
def certs(tmp_path):
    paths = CertPaths(tmp_path / "certs")
    create_ca(paths)
    issue_server(paths, ["localhost"], [])
    issue_client(paths, DEVICE)
    return paths


@pytest.fixture
def server(certs, tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "desktop"))
    srv = make_server("127.0.0.1", 0, create_app(SessionStore()), threaded=True,
                      ssl_context=server_context(certs),
                      request_handler=MutualTLSRequestHandler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"https://localhost:{srv.server_port}"
    srv.shutdown()
    thread.join(timeout=5)


@pytest.fixture
def client(certs):
    with httpx.Client(verify=client_context(certs, DEVICE), timeout=30) as c:
        yield c


@pytest.fixture
def session(server, client):
    dek = secrets.token_bytes(32)
    return client.post(f"{server}/session",
                       json={"key": protocol.encode_key(dek)}).json()["session_id"]


def _note(seq=1, note_id=1, text="Sarah pushed back on the timeline.", prev=None):
    from core import chain
    prev = prev or chain.GENESIS_HASH
    body = chain.body_hash(note_id=note_id, captured_at="2026-08-30T00:00:00+00:00",
                           backdated_at=None, source_type="text_prompt",
                           source_trust="self_authored", raw_text=text,
                           supersedes=None, version=chain.CANON_VERSION)
    return {
        "note_id": note_id, "captured_at": "2026-08-30T00:00:00+00:00",
        "backdated_at": None, "source_type": "text_prompt",
        "source_trust": "self_authored", "raw_text": text, "tombstoned_at": None,
        "supersedes": None, "canon_version": chain.CANON_VERSION,
        "seq": seq, "body_hash": body, "prev_hash": prev,
        "entry_hash": chain.link_hash(prev, body), "hashed_at": "2026-08-30T00:00:00+00:00",
    }


def _load(client, server, session, notes=None, people=None):
    client.post(f"{server}/people", json={
        "session_id": session,
        "people": people or [{"person_id": 1, "display_name": "Sarah K.",
                              "aliases": ["Sarah", "SK"], "active": True,
                              "created_at": "2026-08-30T00:00:00+00:00"}],
    })
    client.post(f"{server}/sync", json={"session_id": session, "notes": notes or [_note()]})


# ── people ───────────────────────────────────────────────────────────────────


def test_people_are_received(server, client, session):
    response = client.post(f"{server}/people", json={
        "session_id": session,
        "people": [{"person_id": 1, "display_name": "Sarah K.", "aliases": ["Sarah"],
                    "active": True, "created_at": "2026-08-30T00:00:00+00:00"}],
    })
    assert response.status_code == 200
    assert response.json()["stored"] == 1


def test_people_can_be_updated(server, client, session, monkeypatch):
    """Adding an alias on the laptop must reach the desktop, not duplicate.

    The model is stubbed: without this the test calls the real one, which takes
    minutes per note and would make the suite unrunnable.
    """
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    for aliases in (["Sarah"], ["Sarah", "SK"]):
        client.post(f"{server}/people", json={
            "session_id": session,
            "people": [{"person_id": 1, "display_name": "Sarah K.", "aliases": aliases,
                        "active": True, "created_at": "2026-08-30T00:00:00+00:00"}],
        })
    _load(client, server, session)
    tagged = client.post(f"{server}/tag", json={"session_id": session, "note_ids": [1]}).json()
    assert tagged["tags"]["1"]


def test_people_needs_a_session(server, client):
    assert client.post(f"{server}/people", json={"people": []}).status_code == 401


@pytest.mark.parametrize("bad", [
    {"person_id": 0, "display_name": "x", "aliases": [], "active": True, "created_at": "t"},
    {"person_id": 1, "display_name": "x", "aliases": "notalist", "active": True, "created_at": "t"},
    {"person_id": 1, "display_name": "x", "aliases": [], "active": "yes", "created_at": "t"},
    {"person_id": 1, "aliases": [], "active": True, "created_at": "t"},
])
def test_malformed_people_are_refused(server, client, session, bad):
    response = client.post(f"{server}/people", json={"session_id": session, "people": [bad]})
    assert response.status_code == 400


# ── tagging ──────────────────────────────────────────────────────────────────


def test_a_named_person_is_tagged_without_the_model(server, client, session, monkeypatch):
    """Alias matching alone should resolve this, so a dead model is irrelevant."""
    def refuse(*args, **kwargs):
        raise tagger.TaggingUnavailable("model is down")
    monkeypatch.setattr(tagger, "judge_self_team", refuse)

    _load(client, server, session)
    result = client.post(f"{server}/tag", json={"session_id": session, "note_ids": [1]}).json()
    # The model failing stops the run, but nothing was guessed wrongly.
    assert result["failed"]


def test_alias_and_model_tags_are_combined(server, client, session, monkeypatch):
    monkeypatch.setattr(tagger, "judge_self_team",
                        lambda text, **kw: [Tag("team", 0.85, "model")])
    _load(client, server, session)
    tags = client.post(f"{server}/tag",
                       json={"session_id": session, "note_ids": [1]}).json()["tags"]["1"]
    assert {t["bin"] for t in tags} == {"person:1", "team"}
    by_bin = {t["bin"]: t["confidence"] for t in tags}
    assert by_bin["person:1"] is None       # exact match, nothing to quantify
    assert by_bin["team"] == 0.85


def test_a_tombstoned_note_is_skipped(server, client, session, monkeypatch):
    """There is no text left to sort."""
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    from core import chain
    body = "a" * 64
    note = {**_note(), "raw_text": "", "tombstoned_at": "2026-08-30T00:00:00+00:00",
            "body_hash": body, "prev_hash": chain.GENESIS_HASH,
            "entry_hash": chain.link_hash(chain.GENESIS_HASH, body)}
    _load(client, server, session, notes=[note])
    result = client.post(f"{server}/tag", json={"session_id": session, "note_ids": [1]}).json()
    assert result["tags"] == {}


def test_an_unknown_note_is_skipped_not_an_error(server, client, session, monkeypatch):
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    _load(client, server, session)
    result = client.post(f"{server}/tag", json={"session_id": session, "note_ids": [999]}).json()
    assert result["tags"] == {}


def test_a_failing_model_stops_but_keeps_earlier_work(server, client, session, monkeypatch):
    """Every remaining note would fail the same way, and the laptop keeps what
    already succeeded."""
    calls = {"n": 0}

    def flaky(text, **kwargs):
        calls["n"] += 1
        if calls["n"] > 1:
            raise tagger.TaggingUnavailable("model went away")
        return [Tag("team", 0.9, "model")]

    monkeypatch.setattr(tagger, "judge_self_team", flaky)
    first = _note()
    second = _note(seq=2, note_id=2, text="another note", prev=first["entry_hash"])
    _load(client, server, session, notes=[first, second])

    result = client.post(f"{server}/tag",
                         json={"session_id": session, "note_ids": [1, 2]}).json()
    assert "1" in result["tags"]
    assert "2" in result["failed"]


def test_tag_needs_a_session(server, client):
    assert client.post(f"{server}/tag", json={"note_ids": [1]}).status_code == 401


@pytest.mark.parametrize("payload", [
    {"note_ids": "all"},
    {"note_ids": list(range(200))},
    {"note_ids": [1], "model": {"not": "a name"}},
])
def test_malformed_tag_requests_are_refused(server, client, session, payload):
    response = client.post(f"{server}/tag", json={"session_id": session, **payload})
    assert response.status_code == 400


def test_a_non_integer_note_id_is_refused(server, client, session):
    response = client.post(f"{server}/tag",
                           json={"session_id": session, "note_ids": ["1; DROP TABLE notes"]})
    assert response.status_code == 400


def test_a_long_run_does_not_expire_its_own_session(server, client, session, monkeypatch):
    """Tagging can outlast the idle timeout; a session doing work stays alive."""
    monkeypatch.setattr(tagger, "judge_self_team", lambda text, **kw: [])
    _load(client, server, session)
    for _ in range(3):
        assert client.post(f"{server}/tag",
                           json={"session_id": session, "note_ids": [1]}).status_code == 200
