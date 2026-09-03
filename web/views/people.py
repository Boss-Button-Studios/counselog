"""The people you write notes about.

Aliases are the load-bearing part. They are what resolves a name *exactly*, and
an exact match is the one answer the model is never asked to second-guess — so a
missing or misspelled alias quietly costs accuracy, sending a note off to be
guessed about or into no bin at all. Until now they could only be set when a
person was created, with no way to add one later.

Pronouns are recorded because writing about someone for months and getting them
wrong is a real way to do harm with a tool like this. One field, and an empty
one is a real answer: nobody has said. It deliberately does not claim that
anybody was *asked* — the column can still hold "asked, and preferred not to
say" (`''`), but nothing here writes it, because a three-way control asks the
user to file someone's refusal and buys only a reminder not to ask again.
"""

from __future__ import annotations

from flask import g, redirect, render_template, request, url_for

from core import models, tags
from web.access import open_database, requires_unlock

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
            return _person_page(conn, person)
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

            try:
                models.update_person(
                    conn, person_id,
                    display_name=request.form.get("name"),
                    aliases=_split_aliases(request.form.get("aliases")),
                    pronouns=_pronouns(request.form.get("pronouns")),
                )
            except models.ModelError as exc:
                return _person_page(conn, person, error=str(exc),
                                    typed=request.form.get("pronouns")), 400
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


def _person_page(conn, person: models.Person, *, error: str | None = None,
                 typed: str | None = None):
    """One place that renders a person, so a refusal looks like the page did.

    A form that comes back empty after complaining has thrown away the work it
    is complaining about. So what was submitted is what is shown, and only what
    was never submitted falls back to what is stored.
    """
    return render_template(
        "person.html", caller=g.caller, person=person,
        note_count=_note_count(conn, person.id), error=error,
        typed=typed if typed is not None else (person.pronouns or ""),
    )


def _split_aliases(raw: str | None) -> list[str]:
    """Commas, because a phone keyboard has one and no good way to add a row."""
    return [part.strip() for part in (raw or "").split(",") if part.strip()]


def _pronouns(raw: str | None) -> str | None:
    """What was typed, or None for "nobody has said".

    None rather than '': the empty string means someone was asked and declined,
    which is a claim about a conversation that may never have happened.
    """
    return (raw or "").strip() or None


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
        return len(tags.notes_for_bin(conn, f"person:{person_id}"))
    except models.ModelError:
        return 0


__all__ = ["register"]
