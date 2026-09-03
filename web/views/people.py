"""The people you write notes about.

Aliases are the load-bearing part. They are what resolves a name *exactly*, and
an exact match is the one answer the model is never asked to second-guess — so a
missing or misspelled alias quietly costs accuracy, sending a note off to be
guessed about or into no bin at all. Until now they could only be set when a
person was created, with no way to add one later.

Pronouns are recorded because writing about someone for months and getting them
wrong is a real way to do harm with a tool like this. Three states, not two:
nobody has been asked, they told you, or they were asked and preferred not to
say. Recording "not stated" for someone nobody ever asked about would be
inventing a considered choice that was never made.
"""

from __future__ import annotations

from flask import g, redirect, render_template, request, url_for

from core import models
from web.access import open_database, requires_unlock

# What the pronoun radio group can say, and what each means in storage.
NOT_ASKED = "unasked"
STATED = "stated"
WITHHELD = "withheld"


def register(app) -> None:

    @app.get("/people")
    @requires_unlock
    def people_list():
        conn = open_database()
        try:
            everyone = models.list_people(conn, include_inactive=True)
            return render_template(
                "people.html", caller=g.caller,
                here=[p for p in everyone if p.active],
                gone=[p for p in everyone if not p.active],
                error=None, name="",
            )
        finally:
            conn.close()

    @app.post("/people")
    @requires_unlock
    def add_person():
        name = request.form.get("name") or ""
        conn = open_database()
        try:
            try:
                person = models.add_person(
                    conn, name,
                    aliases=_split_aliases(request.form.get("aliases")),
                )
            except models.ModelError as exc:
                everyone = models.list_people(conn, include_inactive=True)
                return render_template(
                    "people.html", caller=g.caller,
                    here=[p for p in everyone if p.active],
                    gone=[p for p in everyone if not p.active],
                    error=str(exc), name=name,
                ), 400
        finally:
            conn.close()
        # Straight to their page: someone just added is someone about to have
        # their aliases and pronouns filled in.
        return redirect(url_for("person_detail", person_id=person.id))

    @app.get("/people/<int:person_id>")
    @requires_unlock
    def person_detail(person_id: int):
        conn = open_database()
        try:
            person = _find(conn, person_id)
            if person is None:
                return _no_such_person()
            return render_template("person.html", caller=g.caller, person=person,
                                   note_count=_note_count(conn, person_id), error=None)
        finally:
            conn.close()

    @app.post("/people/<int:person_id>")
    @requires_unlock
    def save_person(person_id: int):
        conn = open_database()
        try:
            person = _find(conn, person_id)
            if person is None:
                return _no_such_person()

            state = request.form.get("pronoun_state") or NOT_ASKED
            typed = (request.form.get("pronouns") or "").strip()
            if state == STATED and not typed:
                return render_template(
                    "person.html", caller=g.caller, person=person,
                    note_count=_note_count(conn, person_id),
                    error="Type the pronouns they use, or choose one of the "
                          "other two answers.",
                ), 400

            try:
                models.update_person(
                    conn, person_id,
                    display_name=request.form.get("name"),
                    aliases=_split_aliases(request.form.get("aliases")),
                    pronouns=_pronouns_from(state, typed),
                )
            except models.ModelError as exc:
                return render_template(
                    "person.html", caller=g.caller, person=person,
                    note_count=_note_count(conn, person_id), error=str(exc),
                ), 400
        finally:
            conn.close()
        return redirect(url_for("person_detail", person_id=person_id))

    @app.post("/people/<int:person_id>/status")
    @requires_unlock
    def set_status(person_id: int):
        """Mark someone as having left the team, or as back.

        Not a deletion and not a filter on the past. Their notes stay readable
        and their aliases keep resolving — `tag` sends everyone, former people
        included — so a note mentioning them next year still finds the right
        bin. All this changes is whether they are offered as current.
        """
        conn = open_database()
        try:
            if _find(conn, person_id) is None:
                return _no_such_person()
            models.set_person_active(conn, person_id,
                                     request.form.get("active") == "1")
        finally:
            conn.close()
        return redirect(url_for("person_detail", person_id=person_id))


def _split_aliases(raw: str | None) -> list[str]:
    """Commas, because a phone keyboard has one and no good way to add a row."""
    return [part.strip() for part in (raw or "").split(",") if part.strip()]


def _pronouns_from(state: str, typed: str) -> str | None:
    """The radio group as the three values the column actually holds."""
    if state == STATED:
        return typed
    if state == WITHHELD:
        return ""       # asked, and they preferred not to say
    return None         # nobody has been asked


def _find(conn, person_id: int) -> models.Person | None:
    try:
        return models.get_person(conn, person_id)
    except models.ModelError:
        return None


def _no_such_person():
    return render_template("error.html", title="No such person",
                           message="Nobody by that id is on your list."), 404


def _note_count(conn, person_id: int) -> int:
    """How much has been written about them, so a status change is informed."""
    try:
        return len(models.notes_for_bin(conn, f"person:{person_id}"))
    except models.ModelError:
        return 0


__all__ = ["register"]
