"""Phase 5: identity, sign-in, sessions, rate limiting, CSRF.

The web app widens the exposure window from seconds to a session, so these test
the things that keep that window narrow and the door guarded.
"""

import time

import pytest
from click.testing import CliRunner

from core.crypto.memory import LockedBuffer
from laptop.cli import cli
from web.app import create_app
from web.identity import identify
from web.ratelimit import SignInLimiter, TooManyAttempts
from web.sessions import BrowserSessions, NotSignedIn

PASSPHRASE = "correct horse battery staple"
TAILSCALE = {"REMOTE_ADDR": "127.0.0.1", "HTTP_TAILSCALE_USER_LOGIN": "you@example.com"}


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("COUNSELOG_ENV_FILE", str(tmp_path / "absent.env"))
    monkeypatch.setenv("COUNSELOG_HOME", str(tmp_path / "data"))
    CliRunner().invoke(cli, ["keys", "init", "--factor", "password", "--label", "web"],
                       input=f"{PASSPHRASE}\n{PASSPHRASE}\n", catch_exceptions=False)
    CliRunner().invoke(cli, ["init", "--unlock-with", "password"],
                       input=f"{PASSPHRASE}\n", catch_exceptions=False)
    return tmp_path


@pytest.fixture
def client(home):
    app = create_app()
    app.testing = True
    return app.test_client()


def _signin(client, passphrase=PASSPHRASE, **extra):
    page = client.get("/signin", environ_overrides=TAILSCALE)
    token = _csrf(page.get_data(as_text=True))
    return client.post("/signin", data={"passphrase": passphrase, "_csrf": token, **extra},
                       environ_overrides=TAILSCALE, follow_redirects=False)


def _csrf(html: str) -> str:
    marker = 'name="_csrf" value="'
    start = html.index(marker) + len(marker)
    return html[start:html.index('"', start)]


# ── identity: the header is only meaningful from the proxy ───────────────────


def test_a_request_through_tailscale_is_identified():
    caller = identify(TAILSCALE)
    assert caller.known and caller.login == "you@example.com"


@pytest.mark.parametrize("environ, why", [
    ({"REMOTE_ADDR": "127.0.0.1"}, "loopback but no header"),
    ({"REMOTE_ADDR": "100.64.1.5", "HTTP_TAILSCALE_USER_LOGIN": "attacker@evil"},
     "off-machine with a forged header"),
    ({"REMOTE_ADDR": "192.168.1.20", "HTTP_TAILSCALE_USER_LOGIN": "you@example.com"},
     "LAN with a forged header"),
    ({}, "nothing at all"),
])
def test_forged_or_absent_identity_is_refused(environ, why):
    assert not identify(environ).known, why


def test_the_app_refuses_a_request_that_did_not_come_through_tailscale(client):
    """Binding to loopback keeps the network out; this keeps everything else out."""
    assert client.get("/", environ_overrides={"REMOTE_ADDR": "192.168.1.9"}).status_code == 403


def test_the_app_serves_a_request_that_did(client):
    assert client.get("/", environ_overrides=TAILSCALE).status_code == 200


# ── sign-in ──────────────────────────────────────────────────────────────────


def test_the_right_passphrase_unlocks(client):
    response = _signin(client)
    assert response.status_code == 302
    assert client.get("/status", environ_overrides=TAILSCALE).json["signed_in"]


def test_a_wrong_passphrase_does_not(client):
    response = _signin(client, "wrong")
    assert response.status_code == 401
    assert "did not unlock" in response.get_data(as_text=True)
    assert not client.get("/status", environ_overrides=TAILSCALE).json["signed_in"]


def test_the_failure_message_does_not_say_which_part_was_wrong(client):
    """'No such user' versus 'wrong password' is free information."""
    body = _signin(client, "wrong").get_data(as_text=True)
    assert "keyring" not in body.lower()
    assert "no such" not in body.lower()


def test_the_session_id_changes_on_sign_in(client):
    """A session id observed before authentication must not become an
    authenticated one."""
    client.get("/signin", environ_overrides=TAILSCALE)
    before = client.get_cookie("counselog_session")
    _signin(client)
    after = client.get_cookie("counselog_session")
    assert before is None or before.value != after.value


def test_the_cookie_is_defended(client):
    _signin(client)
    cookie = client.get_cookie("counselog_session")
    assert cookie.http_only
    assert cookie.secure
    assert (cookie.same_site or "").lower() == "strict"


# ── locking ──────────────────────────────────────────────────────────────────


def test_lock_seals_the_database(client):
    _signin(client)
    page = client.get("/", environ_overrides=TAILSCALE).get_data(as_text=True)
    client.post("/lock", data={"_csrf": _csrf(page)}, environ_overrides=TAILSCALE)
    assert not client.get("/status", environ_overrides=TAILSCALE).json["signed_in"]


def test_lock_ends_every_session_not_just_this_one():
    """Pressing Lock means close the notes; leaving another browser holding the
    key would not be that."""
    sessions = BrowserSessions()
    a = sessions.sign_in("phone", b"k" * 32)
    b = sessions.sign_in("laptop", b"k" * 32)
    assert sessions.lock_all() == 2
    for sid in (a, b):
        with pytest.raises(NotSignedIn):
            sessions.key(sid)


# ── session lifetime ─────────────────────────────────────────────────────────


def test_an_idle_session_expires():
    sessions = BrowserSessions(idle_seconds=0.05, absolute_seconds=10)
    sid = sessions.sign_in("phone", b"k" * 32)
    time.sleep(0.1)
    with pytest.raises(NotSignedIn):
        sessions.key(sid)


def test_use_refreshes_the_idle_timer_but_not_the_absolute_cap():
    """Reading for a while should not require signing in every five minutes;
    reading all day should."""
    sessions = BrowserSessions(idle_seconds=0.2, absolute_seconds=0.35)
    sid = sessions.sign_in("phone", b"k" * 32)
    for _ in range(2):
        time.sleep(0.12)
        sessions.key(sid)          # still alive: each use renews
    time.sleep(0.2)
    with pytest.raises(NotSignedIn):
        sessions.key(sid)          # absolute cap reached regardless


def test_signing_out_drops_the_key():
    sessions = BrowserSessions()
    sid = sessions.sign_in("phone", b"k" * 32)
    assert sessions.sign_out(sid)
    with pytest.raises(NotSignedIn):
        sessions.key(sid)


def test_no_sessions_means_no_key_is_held():
    sessions = BrowserSessions()
    sid = sessions.sign_in("phone", b"k" * 32)
    sessions.sign_out(sid)
    assert not sessions.any_open()


def test_an_unknown_session_id_is_refused():
    with pytest.raises(NotSignedIn):
        BrowserSessions().key("not-a-real-session")


# ── the key stays out of swap ────────────────────────────────────────────────


def test_the_key_is_held_in_locked_memory():
    """This machine's swap is unencrypted, so an unpinned key can reach a disk
    that outlives the process."""
    buffer = LockedBuffer(b"k" * 32)
    try:
        assert buffer.locked, buffer.lock_error
        assert buffer.bytes() == b"k" * 32
    finally:
        buffer.clear()


def test_clearing_a_buffer_is_idempotent():
    buffer = LockedBuffer(b"k" * 32)
    buffer.clear()
    buffer.clear()
    with pytest.raises(ValueError):
        buffer.bytes()


def test_the_buffer_never_shows_the_key(client):
    buffer = LockedBuffer(bytes(range(32)))
    try:
        assert bytes(range(32)).hex() not in repr(buffer)
    finally:
        buffer.clear()


def test_a_live_session_reports_its_memory_as_locked(client):
    _signin(client)
    assert client.get("/status", environ_overrides=TAILSCALE).json["memory_locked"]


# ── rate limiting ────────────────────────────────────────────────────────────


def test_a_burst_is_refused_before_any_derivation():
    """scrypt costs 128 MB per attempt; refusing afterwards would still let an
    attacker spend it."""
    limiter = SignInLimiter(max_attempts=3, lockout=30)
    for _ in range(3):
        limiter.check("phone")
    with pytest.raises(TooManyAttempts):
        limiter.check("phone")


def test_one_caller_being_limited_does_not_lock_out_another():
    limiter = SignInLimiter(max_attempts=2, lockout=30)
    for _ in range(2):
        limiter.check("phone")
    with pytest.raises(TooManyAttempts):
        limiter.check("phone")
    limiter.check("laptop")


def test_a_correct_passphrase_clears_the_record():
    limiter = SignInLimiter(max_attempts=3, lockout=30)
    limiter.check("phone")
    limiter.check("phone")
    limiter.succeeded("phone")
    for _ in range(3):
        limiter.check("phone")


def test_repeated_wrong_passphrases_are_eventually_refused(client):
    codes = [_signin(client, "wrong").status_code for _ in range(7)]
    assert 429 in codes, codes


# ── CSRF ─────────────────────────────────────────────────────────────────────


def test_a_post_without_a_token_is_refused(client):
    _signin(client)
    assert client.post("/lock", data={}, environ_overrides=TAILSCALE).status_code == 400


def test_a_post_with_a_wrong_token_is_refused(client):
    _signin(client)
    response = client.post("/lock", data={"_csrf": "not-the-token"},
                           environ_overrides=TAILSCALE)
    assert response.status_code == 400


def test_reads_do_not_need_a_token(client):
    assert client.get("/", environ_overrides=TAILSCALE).status_code == 200


# ── headers ──────────────────────────────────────────────────────────────────


def test_the_page_may_not_load_anything_off_machine(client):
    """No fonts, no CDNs, no analytics. Notes about people do not leave here."""
    policy = client.get("/", environ_overrides=TAILSCALE).headers["Content-Security-Policy"]
    assert "default-src 'none'" in policy
    assert "frame-ancestors 'none'" in policy
    assert "form-action 'self'" in policy


def test_pages_are_not_cached(client):
    """A shared or borrowed device should not keep note text in its cache."""
    assert client.get("/", environ_overrides=TAILSCALE).headers["Cache-Control"] == "no-store"


def test_no_referrer_leaks(client):
    assert client.get("/", environ_overrides=TAILSCALE).headers["Referrer-Policy"] == "no-referrer"
