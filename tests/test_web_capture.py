"""Phase 6: capture in the browser, and what happens to it at the next sign-in.

The spool's own tests (`test_spool.py`) attack the file. These test the path a
real note takes: typed into a page with no key available, sealed, and then
judged when someone signs in.

Two things get particular attention. First, that a note is never lost — an
unenrolled browser, a browser with scripting off, a forged entry next to a
genuine one: in every case the genuine note survives and the writer is told what
happened. Second, that the browser and Python agree byte for byte about what is
stamped, because a disagreement there would hold real notes for review and look
exactly like tampering.
"""

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from core import db, devices, intake, models, spool
from core.crypto import Keyring, PasswordFactor
from core.paths import (
    keyring_path,
    notes_db_path,
    spool_db_path,
    spool_public_key_path,
)
from core.sanitize import normalize_newlines
from laptop.cli import cli
from web.app import create_app

PASSPHRASE = "correct horse battery staple"
TAILSCALE = {"REMOTE_ADDR": "127.0.0.1", "HTTP_TAILSCALE_USER_LOGIN": "you@example.com"}

STATIC = Path(__file__).resolve().parent.parent / "web" / "static"
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")


# ── fixtures ─────────────────────────────────────────────────────────────────


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


@pytest.fixture
def dek(home):
    """The database key, derived once — scrypt is expensive on purpose."""
    return Keyring.load(keyring_path()).unlock(PasswordFactor(PASSPHRASE))


# ── acting like a browser ────────────────────────────────────────────────────


def _csrf(html: str) -> str:
    match = re.search(r'name="_csrf" value="([^"]+)"', html)
    assert match, "no form token on the page"
    return match.group(1)


def _token(client, path: str = "/") -> str:
    page = client.get(path, environ_overrides=TAILSCALE)
    return _csrf(page.get_data(as_text=True))


def sign_in(client):
    token = _token(client, "/signin")
    return client.post("/signin", data={"passphrase": PASSPHRASE, "_csrf": token},
                       environ_overrides=TAILSCALE)


def lock(client):
    return client.post("/lock", data={"_csrf": _token(client)},
                       environ_overrides=TAILSCALE)


def enroll(client, label="Phone") -> tuple[str, bytes]:
    """Enrol the browser the way the page does, and keep what it was handed."""
    page = client.post("/devices", data={"_csrf": _token(client, "/devices"),
                                         "label": label},
                       environ_overrides=TAILSCALE)
    html = page.get_data(as_text=True)
    device_id = re.search(r'data-device-id="([^"]+)"', html).group(1)
    secret = re.search(r'data-device-secret="([0-9a-f]+)"', html).group(1)
    return device_id, bytes.fromhex(secret)


def write(client, text, *, device=None, captured_at=None, mac=None, wire_text=None):
    """Post a note the way the capture form does.

    `wire_text` is what actually goes over the wire when it differs from what
    the browser stamped — which is the normal case for a multi-line note, since
    form submission rewrites newlines as CRLF in transit.
    """
    data = {"text": wire_text if wire_text is not None else text,
            "_csrf": _token(client)}
    if device is not None:
        device_id, secret = device
        captured_at = captured_at or spool.utc_now()
        data["device"] = device_id
        data["captured_at"] = captured_at
        data["mac"] = mac or spool.device_mac(
            secret, normalize_newlines(text), captured_at, device_id).hex()
    return client.post("/write", data=data, environ_overrides=TAILSCALE,
                       follow_redirects=True)


def page_text(response) -> str:
    """The page as words, with runs of whitespace collapsed.

    An assertion should be about what the page says, not about where the
    template happened to wrap a line.
    """
    return " ".join(response.get_data(as_text=True).split())


def notes_in(dek):
    conn = db.connect(notes_db_path(), dek)
    try:
        return models.list_notes(conn)
    finally:
        conn.close()


def spool_entries():
    conn = spool.connect(spool_db_path())
    try:
        return spool.entries_after(conn, 0)
    finally:
        conn.close()


# ── writing with no key available ────────────────────────────────────────────


def test_a_note_can_be_written_with_no_session(client, dek):
    """The whole reason the spool exists."""
    response = write(client, "Ada pushed back on the timeline.")
    assert response.status_code == 200
    assert len(spool_entries()) == 1
    assert notes_in(dek) == []


def test_a_note_written_while_locked_is_not_readable_in_the_file(client):
    write(client, "Ada pushed back on the timeline.")
    raw = spool_db_path().read_bytes()
    assert b"Ada pushed back" not in raw


def test_writing_still_needs_the_form_token(client):
    """No session is required. That is not the same as no protection."""
    response = client.post("/write", data={"text": "no token"},
                           environ_overrides=TAILSCALE)
    assert response.status_code == 400
    assert spool_entries() == []


@pytest.mark.parametrize("text, why", [
    ("", "nothing at all"),
    ("   \n  ", "only whitespace"),
])
def test_an_empty_note_is_refused(client, text, why):
    response = write(client, text)
    assert response.status_code == 400, why
    assert spool_entries() == []


def test_a_note_longer_than_the_limit_is_refused_with_the_text_kept(client):
    """Refusing is only acceptable because the text stays in the box."""
    response = write(client, "x" * (spool.MAX_NOTE_CHARS + 1))
    assert response.status_code == 400
    assert "Split it into a few notes" in page_text(response)
    assert spool_entries() == []


def test_the_page_says_so_when_this_machine_cannot_seal_yet(client):
    """A fresh install, before anyone has signed in or run init."""
    spool_public_key_path().unlink()
    page = client.get("/", environ_overrides=TAILSCALE)
    assert "not set up on this machine yet" in page_text(page)
    assert write(client, "held up").status_code == 503


# ── the note becomes a real note ─────────────────────────────────────────────


def test_an_enrolled_browser_s_note_is_filed_at_the_next_signin(client, dek):
    sign_in(client)
    device = enroll(client)
    lock(client)

    write(client, "Ada pushed back on the timeline.", device=device)
    assert notes_in(dek) == []

    sign_in(client)
    stored = notes_in(dek)
    assert len(stored) == 1
    assert stored[0].raw_text == "Ada pushed back on the timeline."


def test_a_filed_note_extends_the_chain_and_still_verifies(client, dek):
    sign_in(client)
    device = enroll(client)
    lock(client)
    write(client, "Tom asked for Friday off.", device=device)
    sign_in(client)

    conn = db.connect(notes_db_path(), dek)
    try:
        result = models.verify(conn)
    finally:
        conn.close()
    assert result.ok, result.problems


def test_a_multiline_note_survives_the_browser_s_line_endings(client, dek):
    """A form submission rewrites newlines as CRLF in transit.

    The browser stamps the text it holds, which uses plain newlines. Without
    normalising on both sides, every note with a line break in it would fail its
    check and be held for review — so this is the shape of a bug that would have
    made the feature useless for real notes.
    """
    sign_in(client)
    device = enroll(client)
    lock(client)

    typed = "Two things:\n- the timeline\n- the handover"
    write(client, typed, device=device, wire_text=typed.replace("\n", "\r\n"))
    sign_in(client)

    stored = notes_in(dek)
    assert len(stored) == 1
    assert stored[0].raw_text == typed


def test_the_note_is_filed_under_this_machine_s_clock(client, dek):
    """A device's claimed time is stamped, but it is still a phone's clock.

    `captured_at` is what has to mean something in an HR conversation, so it
    comes from one clock: ours.
    """
    sign_in(client)
    device = enroll(client)
    lock(client)

    write(client, "written long ago, supposedly", device=device,
          captured_at="2020-01-01T00:00:00+00:00")
    sign_in(client)

    stored = notes_in(dek)
    assert len(stored) == 1
    assert not stored[0].captured_at.startswith("2020")


def test_a_device_whose_clock_disagrees_is_reported(client, dek):
    sign_in(client)
    device = enroll(client)
    lock(client)
    write(client, "written long ago, supposedly", device=device,
          captured_at="2020-01-01T00:00:00+00:00")

    page = sign_in(client)
    assert page.status_code == 302
    assert "clock disagrees" in page_text(client.get("/", environ_overrides=TAILSCALE))


def test_a_second_signin_does_not_file_the_same_note_twice(client, dek):
    sign_in(client)
    device = enroll(client)
    lock(client)
    write(client, "Ada pushed back on the timeline.", device=device)

    sign_in(client)
    lock(client)
    sign_in(client)
    assert len(notes_in(dek)) == 1


def test_a_note_written_while_signed_in_skips_the_spool(client, dek):
    """With the key in hand there is nothing to gain by sealing it first."""
    sign_in(client)
    write(client, "Straight into the record.")

    assert spool_entries() == []
    stored = notes_in(dek)
    assert len(stored) == 1
    assert stored[0].raw_text == "Straight into the record."


# ── what does not get filed ──────────────────────────────────────────────────


def test_an_unenrolled_browser_s_note_is_held_not_filed(client, dek):
    """Scripting off, or a browser nobody enrolled. The note is kept either way."""
    write(client, "who wrote this?")
    sign_in(client)

    assert notes_in(dek) == []
    page = page_text(client.get("/held", environ_overrides=TAILSCALE))
    assert "not enrolled" in page
    assert devices.UNSTAMPED in page


def test_the_writer_is_told_at_the_time_that_it_will_be_held(client):
    """Told while they still remember writing it, not days later."""
    assert "held for review" in page_text(write(client, "who wrote this?"))


def test_a_forged_stamp_is_held_but_the_genuine_note_behind_it_is_not(client, dek):
    """One forgery must not deny the user their own notes."""
    sign_in(client)
    device = enroll(client)
    lock(client)

    write(client, "forged", device=(device[0], os.urandom(32)))
    write(client, "genuine", device=device)
    sign_in(client)

    stored = notes_in(dek)
    assert [note.raw_text for note in stored] == ["genuine"]
    held = page_text(client.get("/held", environ_overrides=TAILSCALE))
    assert "was not written by the device it claims to be from" in held


def test_a_revoked_browser_s_later_notes_are_held(client, dek):
    sign_in(client)
    device = enroll(client)
    lock(client)
    write(client, "before revoking", device=device)
    sign_in(client)

    client.post(f"/devices/{device[0]}/revoke",
                data={"_csrf": _token(client, "/devices")},
                environ_overrides=TAILSCALE)
    lock(client)
    write(client, "after revoking", device=device)
    sign_in(client)

    assert [note.raw_text for note in notes_in(dek)] == ["before revoking"]


def test_a_rewritten_spool_is_held_not_filed(client, dek):
    """An attacker who can write the file cannot continue the chain."""
    sign_in(client)
    device = enroll(client)
    lock(client)
    write(client, "genuine", device=device)
    sign_in(client)          # bookmark now points past the genuine note
    lock(client)

    # Start the file over with an entry of the attacker's own.
    spool_db_path().unlink()
    conn = spool.connect(spool_db_path())
    try:
        spool.append(conn, intake.published_key(), text="planted",
                     captured_at=spool.utc_now(), device_id=device[0],
                     mac=b"\x00" * 32)
    finally:
        conn.close()

    sign_in(client)
    assert [note.raw_text for note in notes_in(dek)] == ["genuine"]


def test_a_replaced_spool_is_reported_rather_than_passed_over(client, dek):
    """Deleting the file destroys notes. It must not do so quietly."""
    sign_in(client)
    device = enroll(client)
    lock(client)
    write(client, "genuine", device=device)
    sign_in(client)
    lock(client)

    spool_db_path().unlink()
    write(client, "written after the file was replaced", device=device)
    sign_in(client)

    home = page_text(client.get("/", environ_overrides=TAILSCALE))
    assert "was replaced" in home
    # The stamp still proves this one, so the user does not lose it.
    assert "written after the file was replaced" in [n.raw_text for n in notes_in(dek)]


def test_an_altered_spool_holds_what_follows_but_files_nothing_twice(client, dek):
    """The same file, edited in place after part of it was already taken in.

    Reading it from the start again would put the notes already filed into the
    record a second time, which in an HR record is its own kind of damage. So
    reading carries on from the bookmark instead, and the change is reported.

    A note written after the edit is genuine — its stamp is good — but it no
    longer follows the entry the record stopped at, so it is held rather than
    filed. That is the chain doing its job: an attacker who edits the file
    cannot make the edit invisible by writing over it. Reading catches up with
    the file again on the next drain, so the effect is bounded.
    """
    sign_in(client)
    device = enroll(client)
    lock(client)
    write(client, "genuine", device=device)
    sign_in(client)
    lock(client)

    conn = spool.connect(spool_db_path())
    try:
        conn.execute("UPDATE entries SET entry_hash = ? WHERE seq = 1", ("0" * 64,))
        conn.commit()
    finally:
        conn.close()

    write(client, "written straight after the change", device=device)
    sign_in(client)

    assert "was changed" in page_text(client.get("/", environ_overrides=TAILSCALE))
    assert [note.raw_text for note in notes_in(dek)] == ["genuine"]
    held = page_text(client.get("/held", environ_overrides=TAILSCALE))
    assert "the spool was altered" in held

    # And it recovers: the next note follows an entry the record has now seen.
    lock(client)
    write(client, "written later still", device=device)
    sign_in(client)
    assert [note.raw_text for note in notes_in(dek)] == ["genuine",
                                                         "written later still"]


def test_a_held_entry_can_be_marked_seen_but_the_record_of_it_stays(client, dek):
    write(client, "who wrote this?")
    sign_in(client)

    conn = db.connect(notes_db_path(), dek)
    try:
        seq = intake.held(conn)[0]["seq"]
    finally:
        conn.close()

    client.post(f"/held/{seq}/acknowledge", data={"_csrf": _token(client, "/held")},
                environ_overrides=TAILSCALE)

    conn = db.connect(notes_db_path(), dek)
    try:
        assert intake.held(conn) == []
        assert len(intake.held(conn, include_acknowledged=True)) == 1
    finally:
        conn.close()


def test_the_text_of_a_held_entry_is_not_kept(client, dek):
    """It failed its checks. It does not get a place in the record."""
    write(client, "unmistakeable phrasing")
    sign_in(client)

    page = client.get("/held", environ_overrides=TAILSCALE)
    assert b"unmistakeable phrasing" not in page.data
    assert b"unmistakeable phrasing" not in notes_db_path().read_bytes()


# ── what the spool keeps afterwards ──────────────────────────────────────────


def test_a_filed_note_leaves_no_sealed_copy_behind(client, dek):
    """The record is the only place a filed note lives.

    The spool holds a note between writing it and the next sign-in. Once it is
    inside the encrypted database there is no reason for that sealed copy to
    outlive it, and every reason for it not to — see the `forget` test below.
    """
    sign_in(client)
    device = enroll(client)
    lock(client)
    write(client, "Ada pushed back on the timeline.", device=device)
    sign_in(client)

    entries = spool_entries()
    assert len(entries) == 1, "the entry keeps its place in the chain"
    assert entries[0].ciphertext == b"", "but not its body"


def test_forgetting_a_note_written_while_locked_really_forgets_it(client, dek):
    """The gap this exists to close.

    `forget` clears a note's text from the record. Before the spool learned to
    drop drained bodies, a note written while locked kept a complete sealed copy
    in a second file that `forget` had never heard of — so honouring a deletion
    request left the text recoverable by anyone who could open the spool key.

    The test opens the leftovers with the real private key rather than grepping
    the file for the words. A sealed body is ciphertext, so a plaintext search
    finds nothing whether or not the copy is still there — which is exactly the
    sort of test that passes while the thing it claims to check is broken.
    """
    secret = "Tom disclosed something in confidence."
    sign_in(client)
    device = enroll(client)
    lock(client)
    write(client, secret, device=device)
    sign_in(client)

    conn = db.connect(notes_db_path(), dek)
    try:
        models.tombstone_note(conn, models.list_notes(conn)[0].id)
        private = intake.private_key(conn)
    finally:
        conn.close()

    recovered = []
    for entry in spool_entries():
        try:
            recovered.append(spool.unseal(private, entry.ciphertext))
        except Exception:
            pass  # nothing left to open, which is the point
    assert not any(secret.encode() in blob for blob in recovered), \
        "a forgotten note is still recoverable from the spool"
    assert secret.encode() not in notes_db_path().read_bytes()


def test_clearing_a_body_does_not_break_the_chain(client, dek):
    """The link has to survive the body, exactly as a tombstone does."""
    sign_in(client)
    device = enroll(client)
    lock(client)
    write(client, "first", device=device)
    sign_in(client)
    lock(client)
    write(client, "second", device=device)
    sign_in(client)

    assert [note.raw_text for note in notes_in(dek)] == ["first", "second"]
    assert all(entry.ciphertext == b"" for entry in spool_entries())


def test_a_held_entry_keeps_its_body(client, dek):
    """Its text is in no other place, and it may well be a genuine note."""
    write(client, "who wrote this?")
    sign_in(client)

    entries = spool_entries()
    assert len(entries) == 1
    assert entries[0].ciphertext != b"", "the only copy there is"


def test_a_body_left_by_an_interrupted_drain_is_cleared_next_time(client, dek):
    """The sweep heals the file rather than relying on nothing going wrong.

    Imitates a drain that filed a note and then died before clearing, and a
    build that never cleared at all — the same shape of leftover either way.
    """
    sign_in(client)
    device = enroll(client)
    lock(client)
    write(client, "left behind", device=device)
    sign_in(client)

    sealed = spool.seal(intake.published_key(), b"pretend this was never cleared")
    conn = spool.connect(spool_db_path())
    try:
        conn.execute("UPDATE entries SET ciphertext = ? WHERE seq = 1", (sealed,))
        conn.commit()
    finally:
        conn.close()

    lock(client)
    sign_in(client)          # nothing new to drain; the sweep still runs
    assert spool_entries()[0].ciphertext == b""


# ── the published key ────────────────────────────────────────────────────────


def test_the_published_key_is_the_public_half_and_owner_only(dek):
    published = spool_public_key_path()
    assert len(published.read_bytes()) == 32
    assert published.stat().st_mode & 0o777 == 0o600

    conn = db.connect(notes_db_path(), dek)
    try:
        assert published.read_bytes() == spool.public_of(intake.private_key(conn))
    finally:
        conn.close()


def test_a_swapped_public_key_is_put_back_at_the_next_signin(client, dek):
    """The one file an attacker could usefully replace.

    Swap in their own public key and the locked server would seal tomorrow's
    notes where they could read them. Republishing at every sign-in bounds that
    to a single reading session.
    """
    _, theirs = spool.new_identity()
    spool_public_key_path().write_bytes(theirs)

    sign_in(client)

    conn = db.connect(notes_db_path(), dek)
    try:
        ours = spool.public_of(intake.private_key(conn))
    finally:
        conn.close()
    assert spool_public_key_path().read_bytes() == ours


def test_notes_sealed_to_a_swapped_key_surface_rather_than_vanish(client, dek):
    sign_in(client)
    device = enroll(client)
    lock(client)

    _, theirs = spool.new_identity()
    spool_public_key_path().write_bytes(theirs)
    write(client, "sealed to the wrong key", device=device)
    sign_in(client)

    assert notes_in(dek) == []
    page = page_text(client.get("/held", environ_overrides=TAILSCALE))
    assert "could not be opened or read" in page


# ── who may do what ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("path", ["/devices", "/held"])
def test_reading_pages_send_a_locked_browser_to_sign_in(client, path):
    response = client.get(path, environ_overrides=TAILSCALE)
    assert response.status_code == 302
    assert "/signin" in response.headers["Location"]


def test_the_capture_page_is_reachable_while_locked(client):
    """It is the one page that must never ask for a passphrase."""
    response = client.get("/", environ_overrides=TAILSCALE)
    assert response.status_code == 200
    assert "Write a note" in page_text(response)


def test_enrolment_shows_the_key_once_and_never_again(client):
    sign_in(client)
    device_id, _ = enroll(client)
    later = client.get("/devices", environ_overrides=TAILSCALE).get_data(as_text=True)
    assert device_id in later
    assert "data-device-secret" not in later


# ── the browser and Python have to agree ─────────────────────────────────────


def _in_node(script: str) -> str:
    """Run a snippet with stamp.js loaded, the way a browser would have it."""
    harness = f"""
      globalThis.window = undefined;
      require({str(STATIC / "stamp.js")!r});
      const stamping = globalThis.counselogStamp;
      {script}
    """
    result = subprocess.run([NODE, "-e", harness], capture_output=True, text=True,
                            timeout=30)
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


# Awkward on purpose: a newline, a tab, an accent, a non-Latin script, an emoji,
# a quote and a backslash. These are where two languages stop agreeing, and the
# reason the stamped bytes are length-prefixed rather than JSON.
TRICKY = [
    "plain text",
    "two\nlines",
    "a\ttab",
    "café",
    "naïve — em dash",
    "日本語のメモ",
    "🙂 emoji",
    'quotes "and" \\backslashes\\',
    "trailing space ",
]


@needs_node
@pytest.mark.parametrize("text", TRICKY)
def test_the_browser_stamps_the_bytes_python_expects(text):
    captured_at = "2026-09-02T10:11:12+00:00"
    device_id = "0123456789abcdef"
    from_node = _in_node(
        f"console.log(stamping.toHex(stamping.stampedBytes("
        f"{json.dumps(text)}, {json.dumps(captured_at)}, {json.dumps(device_id)})));")
    assert from_node == spool.stamped_bytes(text, captured_at, device_id).hex()


@needs_node
@pytest.mark.parametrize("text", TRICKY)
def test_the_browser_and_python_produce_the_same_stamp(text):
    secret = bytes(range(32))
    captured_at = "2026-09-02T10:11:12+00:00"
    device_id = "0123456789abcdef"
    from_node = _in_node(
        f"stamping.stamp({json.dumps(secret.hex())}, {json.dumps(text)}, "
        f"{json.dumps(captured_at)}, {json.dumps(device_id)})"
        f".then(mac => console.log(mac));")
    assert from_node == spool.device_mac(secret, text, captured_at, device_id).hex()


@needs_node
def test_the_browser_writes_the_one_timestamp_form_that_is_accepted():
    """Never the `Z` form: note times have to sort as text in one order."""
    stamped = _in_node(
        "console.log(stamping.nowStamp(new Date(Date.UTC(2026, 8, 2, 10, 11, 12))));")
    assert stamped == "2026-09-02T10:11:12+00:00"
    assert devices.is_captured_at(stamped)


@needs_node
def test_the_browser_normalises_newlines_the_way_python_does():
    mixed = "a\r\nb\rc\nd"
    from_node = _in_node(
        f"console.log(JSON.stringify(stamping.normalizeNewlines({json.dumps(mixed)})));")
    assert json.loads(from_node) == normalize_newlines(mixed)
