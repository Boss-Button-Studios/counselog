"""Fill a throwaway record with fictitious notes, to look at the reading pages.

There is no way to see a digest, a correction, a cleared note and a backdated
one without a record that contains all four, and a real record acquires them
over months. So this builds one in a few seconds.

    COUNSELOG_HOME=/tmp/counselog-demo .venv/bin/python bench/seed_record.py

**It will not write into your real record**, and that guard is why this lives in
the repo instead of being retyped whenever someone needs it. A script that
fabricates notes must never be able to fabricate them in the record that is
meant to be evidence — the value of the whole design rests on every note in
there having been written by the person whose record it is.

Three conditions, all required:

  * COUNSELOG_HOME must be set explicitly, so seeding is never something that
    happens because a command was run in the wrong terminal;
  * it must not be the default location, checked by path rather than by asking;
  * the database must be one this script seeded before, marked by a file it
    leaves behind — so a home that was set explicitly but reused for something
    real is still refused.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from core import db, models, revisions, tags
from core.crypto import Keyring, PasswordFactor, new_dek
from core.paths import ENV_HOME, keyring_path, notes_db_path
from bench.notes import PEOPLE, REVISION, SEEDED

# Not a secret and not pretending to be one. The record it opens contains
# nothing but inventions, and a password prompt here would only train someone to
# type a real passphrase into a script that writes fabricated notes.
PASSPHRASE = "bench record, fictitious notes only"

MARKER = ".seeded-by-bench"


class Refused(Exception):
    """The seeder will not write here, and says exactly why."""


def check_home() -> Path:
    """Decide whether this home may be seeded. Refuse in every unclear case."""
    override = os.environ.get(ENV_HOME)
    if not override:
        raise Refused(
            f"Set {ENV_HOME} to a throwaway directory first, for example:\n"
            f"    {ENV_HOME}=/tmp/counselog-demo .venv/bin/python bench/seed_record.py")

    home = Path(override).expanduser()
    default = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share") / "counselog"
    if home.resolve() == default.resolve():
        raise Refused(
            f"{ENV_HOME} points at the real record ({home}). This script writes "
            "invented notes and will not put them in a record that is supposed "
            "to be evidence.")

    if notes_db_path().exists() and not (home / MARKER).exists():
        raise Refused(
            f"{home} already holds a database this script did not seed. Point "
            f"{ENV_HOME} somewhere else, or delete that directory if it really "
            "is disposable.")
    return home


def build(home: Path) -> None:
    """Create the keyring, the database, the people, and the notes."""
    if not keyring_path().exists():
        ring = Keyring(keyring_path())
        ring.add(new_dek(), PasswordFactor(PASSPHRASE), "bench")
        ring.save()
    dek = Keyring.load(keyring_path()).unlock(PasswordFactor(PASSPHRASE))

    if not notes_db_path().exists():
        db.create(notes_db_path(), dek).close()
    (home / MARKER).write_text(
        "Seeded by bench/seed_record.py. Everything in this directory is "
        "invented.\n", encoding="utf-8")

    conn = db.connect(notes_db_path(), dek)
    try:
        for name, alias in PEOPLE:
            try:
                models.add_person(conn, name, aliases=[alias])
            except models.ModelError:
                pass  # already added: seeding twice should not fail

        for text, at, person, confidence, backdated, then in SEEDED:
            note = models.add_note(conn, text, captured_at=at, backdated_at=backdated)
            key = f"person:{person}"
            tags.set_tags(conn, note.id, [(key, confidence)])
            if then == "confirm":
                tags.confirm_tag(conn, note.id, key)
            elif then == "revise":
                revisions.revise(conn, note.id, REVISION)
            elif then == "clear":
                models.tombstone_note(conn, note.id)

        # The total, not what this run added: seeding twice is allowed, and
        # "seeded 9" after a second run would be a lie about what is in there.
        print(f"{home} now holds {len(models.list_notes(conn))} notes about "
              f"{len(models.list_people(conn))} people.")
    finally:
        conn.close()

    print(f'\nRead them with:\n    COUNSELOG_HOME={home} ./counselogweb '
          f'--allow-direct --port 8899\nand sign in with: {PASSPHRASE}')


def main() -> int:
    try:
        build(check_home())
    except Refused as exc:
        print(f"Refused: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
