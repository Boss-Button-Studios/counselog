"""Phase 6 part 3, slice 2: the subject registry.

Aliases carry most of the weight. They are what matches a name exactly, and an
exact match is the one answer the model is never asked to second-guess — so a
missing alias is a note that gets guessed about or filed nowhere. Until this
slice they could only be set when a person was created.

Pronouns get their own attention because the column keeps three states, not two,
and collapsing them would mean recording a considered choice nobody made.
"""

import re

import pytest
from click.testing import CliRunner

from core import db, models
from core.crypto import Keyring, PasswordFactor
from core.paths import keyring_path, notes_db_path
from laptop.cli import cli
from web.app import create_app

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
def dek(home):
    return Keyring.load(keyring_path()).unlock(PasswordFactor(PASSPHRASE))


@pytest.fixture
def client(home):
    app = create_app()
    app.testing = True
    return app.test_client()


def sign_in(client):
    page = client.get("/signin", environ_overrides=TAILSCALE)
    token = re.search(r'name="_csrf" value="([^"]+)"',
                      page.get_data(as_text=True)).group(1)
    return client.post("/signin", data={"passphrase": PASSPHRASE, "_csrf": token},
                       environ_overrides=TAILSCALE)


def token_on(client, path):
    page = client.get(path, environ_overrides=TAILSCALE)
    return re.search(r'name="_csrf" value="([^"]+)"', page.get_data(as_text=True)).group(1)


def get(client, path):
    return client.get(path, environ_overrides=TAILSCALE)


def text_of(response) -> str:
    return " ".join(response.get_data(as_text=True).split())


def post(client, path, **fields):
    return client.post(path, data={"_csrf": token_on(client, "/people"), **fields},
                       environ_overrides=TAILSCALE, follow_redirects=True)


def person_in(dek, person_id: int) -> models.Person:
    conn = db.connect(notes_db_path(), dek)
    try:
        return models.get_person(conn, person_id)
    finally:
        conn.close()


@pytest.fixture
def ada(client, dek):
    sign_in(client)
    post(client, "/people", name="Ada L.", aliases="Ada")
    conn = db.connect(notes_db_path(), dek)
    try:
        return models.list_people(conn)[0]
    finally:
        conn.close()


# ── adding ───────────────────────────────────────────────────────────────────


def test_someone_can_be_added_with_the_names_actually_used_for_them(client, dek):
    sign_in(client)
    post(client, "/people", name="Sarah K.", aliases="Sarah, SK")
    person = person_in(dek, 1)
    assert person.display_name == "Sarah K."
    assert set(person.aliases) == {"Sarah K.", "Sarah", "SK"}


def test_the_display_name_is_always_a_name_that_matches(client, dek):
    """Matching must not depend on remembering to repeat the name."""
    sign_in(client)
    post(client, "/people", name="Sarah K.", aliases="")
    assert person_in(dek, 1).aliases == ("Sarah K.",)


def test_adding_someone_twice_says_so_rather_than_failing_obscurely(client):
    sign_in(client)
    post(client, "/people", name="Sarah K.")
    page = post(client, "/people", name="Sarah K.")
    assert "already on the list" in text_of(page)


def test_a_person_gets_a_bin_so_notes_can_be_sorted_to_them(client, dek):
    """A person without a bin cannot be tagged at all."""
    sign_in(client)
    post(client, "/people", name="Sarah K.")
    conn = db.connect(notes_db_path(), dek)
    try:
        assert models.bin_for_person(conn, 1)
    finally:
        conn.close()


def test_an_empty_list_says_only_self_and_team_can_match(client):
    sign_in(client)
    assert "only “self” and “team” can be matched" in text_of(get(client, "/people"))


# ── editing, which is the point of the slice ─────────────────────────────────


def test_an_alias_can_be_added_after_the_fact(client, dek, ada):
    """The gap this slice exists to close."""
    post(client, f"/people/{ada.id}", name="Ada L.", aliases="Ada, Ada Lovelace, AL",
         pronoun_state="unasked")
    assert set(person_in(dek, ada.id).aliases) == {"Ada L.", "Ada", "Ada Lovelace", "AL"}


def test_a_misspelled_alias_can_be_corrected(client, dek, ada):
    post(client, f"/people/{ada.id}", name="Ada L.", aliases="Adah",
         pronoun_state="unasked")
    aliases = set(person_in(dek, ada.id).aliases)
    assert "Adah" in aliases
    assert "Ada" not in aliases, "the wrong one is gone, not merely joined"


def test_someone_can_be_renamed(client, dek, ada):
    post(client, f"/people/{ada.id}", name="Ada Lovelace", aliases="Ada",
         pronoun_state="unasked")
    person = person_in(dek, ada.id)
    assert person.display_name == "Ada Lovelace"
    assert "Ada Lovelace" in person.aliases, "the new name matches too"


def test_renaming_onto_someone_else_is_refused(client, dek, ada):
    post(client, "/people", name="Tom R.")
    page = post(client, f"/people/{ada.id}", name="Tom R.", aliases="",
                pronoun_state="unasked")
    assert "already on the list" in text_of(page)
    assert person_in(dek, ada.id).display_name == "Ada L.", "unchanged"


def test_a_person_who_does_not_exist_says_so(client):
    sign_in(client)
    assert get(client, "/people/999").status_code == 404


# ── pronouns, three states ───────────────────────────────────────────────────


def test_a_new_person_has_not_been_asked(client, dek, ada):
    """Not 'not stated'. Nobody has been asked yet, and that is different."""
    assert person_in(dek, ada.id).pronouns is None


def test_pronouns_can_be_recorded_as_given(client, dek, ada):
    post(client, f"/people/{ada.id}", name="Ada L.", aliases="Ada",
         pronoun_state="stated", pronouns="she/her")
    person = person_in(dek, ada.id)
    assert person.pronouns == "she/her"
    assert person.pronouns_known and not person.pronouns_withheld


def test_preferring_not_to_say_is_recorded_as_a_real_answer(client, dek, ada):
    """'' is a considered choice; None is the absence of one."""
    post(client, f"/people/{ada.id}", name="Ada L.", aliases="Ada",
         pronoun_state="withheld")
    person = person_in(dek, ada.id)
    assert person.pronouns == ""
    assert person.pronouns_withheld and not person.pronouns_known


def test_the_two_kinds_of_no_answer_are_not_collapsed(client, dek, ada):
    post(client, f"/people/{ada.id}", name="Ada L.", aliases="Ada",
         pronoun_state="withheld")
    withheld = person_in(dek, ada.id).pronouns
    post(client, f"/people/{ada.id}", name="Ada L.", aliases="Ada",
         pronoun_state="unasked")
    unasked = person_in(dek, ada.id).pronouns
    assert withheld == "" and unasked is None
    assert withheld != unasked


def test_saying_they_use_something_but_typing_nothing_is_refused(client, dek, ada):
    """Silently filing it as 'never asked' would lose the answer given."""
    page = post(client, f"/people/{ada.id}", name="Ada L.", aliases="Ada",
                pronoun_state="stated", pronouns="   ")
    assert "Type the pronouns they use" in text_of(page)
    assert person_in(dek, ada.id).pronouns is None, "nothing was recorded"


def test_editing_a_name_does_not_disturb_recorded_pronouns(client, dek, ada):
    post(client, f"/people/{ada.id}", name="Ada L.", aliases="Ada",
         pronoun_state="stated", pronouns="they/them")
    post(client, f"/people/{ada.id}", name="Ada Lovelace", aliases="Ada",
         pronoun_state="stated", pronouns="they/them")
    assert person_in(dek, ada.id).pronouns == "they/them"


def test_update_person_leaves_pronouns_alone_unless_asked(dek, home):
    """The sentinel exists because None is itself a meaningful value."""
    conn = db.connect(notes_db_path(), dek)
    try:
        person = models.add_person(conn, "Ada L.", aliases=["Ada"], pronouns="she/her")
        models.update_person(conn, person.id, display_name="Ada Lovelace")
        assert models.get_person(conn, person.id).pronouns == "she/her"

        models.update_person(conn, person.id, pronouns=None)
        assert models.get_person(conn, person.id).pronouns is None
    finally:
        conn.close()


# ── leaving the team ─────────────────────────────────────────────────────────


def test_marking_someone_as_left_does_not_remove_them(client, dek, ada):
    post(client, f"/people/{ada.id}/status", active="0")
    person = person_in(dek, ada.id)
    assert not person.active
    assert person.aliases, "their names are untouched"


def test_a_former_colleague_still_sorts_new_notes(client, dek, ada):
    """`tag` sends everyone, so a note mentioning them next year still lands."""
    post(client, f"/people/{ada.id}/status", active="0")
    conn = db.connect(notes_db_path(), dek)
    try:
        everyone = models.list_people(conn, include_inactive=True)
        assert [p.display_name for p in everyone] == ["Ada L."]
        assert models.bin_for_person(conn, ada.id), "their bin survives"
    finally:
        conn.close()


def test_their_old_notes_stay_readable(client, dek, ada):
    conn = db.connect(notes_db_path(), dek)
    try:
        note = models.add_note(conn, "Ada pushed back on the timeline.")
        models.set_tags(conn, note.id, [(f"person:{ada.id}", None)])
    finally:
        conn.close()

    post(client, f"/people/{ada.id}/status", active="0")

    conn = db.connect(notes_db_path(), dek)
    try:
        assert len(models.notes_for_bin(conn, f"person:{ada.id}")) == 1
    finally:
        conn.close()


def test_someone_can_come_back(client, dek, ada):
    post(client, f"/people/{ada.id}/status", active="0")
    post(client, f"/people/{ada.id}/status", active="1")
    assert person_in(dek, ada.id).active


def test_the_page_says_what_leaving_does_and_does_not_do(client, ada):
    page = text_of(get(client, f"/people/{ada.id}"))
    assert "Their notes stay readable" in page
    assert "names keep sorting new notes" in page


# ── who may do this ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("path", ["/people", "/people/1"])
def test_the_registry_needs_a_session(client, path):
    response = get(client, path)
    assert response.status_code == 302
    assert "/signin" in response.headers["Location"]


def test_changing_someone_needs_the_form_token(client, dek, ada):
    response = client.post(f"/people/{ada.id}", data={"name": "Hijacked"},
                           environ_overrides=TAILSCALE)
    assert response.status_code == 400
    assert person_in(dek, ada.id).display_name == "Ada L."
