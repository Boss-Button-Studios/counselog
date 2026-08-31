"""The desktop's service: bin tagging, report generation, and the mirror.

Reachable only over mutual TLS. An unenrolled machine on the tailnet is refused
at the handshake, before it sends a byte of a request.

What this process deliberately does not have: any way to open the mirror on its
own. The key arrives per session from the laptop and lives in memory only, so
this service is useful exactly as long as the laptop is talking to it, and inert
the rest of the time.
"""

from __future__ import annotations

import functools
import logging
from typing import Callable

import sqlcipher3
from flask import Flask, g, jsonify, request

from core import config, db, models, protocol
from core.certs import peer_name
from core.paths import mirror_db_path
from desktop import mirror, tagger
from desktop.sessions import NoSuchSession, SessionStore

log = logging.getLogger("counselogd")

SERVICE_VERSION = 1


def _device() -> str:
    """Which enrolled device is calling, per its verified client certificate."""
    return peer_name(request.environ.get("SSL_CLIENT_CERT_DICT"))


def requires_session(view: Callable) -> Callable:
    """Resolve the caller's session key, or refuse.

    Every endpoint that touches notes goes through here, so there is exactly one
    place where a missing or expired session is turned into an answer.
    """
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        payload = request.get_json(silent=True) or {}
        session_id = payload.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            return jsonify(error="This request needs a session."), 401
        try:
            g.dek = current_app_sessions().key_for(session_id, _device())
        except NoSuchSession as exc:
            return jsonify(error=str(exc)), 401
        g.payload = payload
        return view(*args, **kwargs)

    return wrapper


def current_app_sessions() -> SessionStore:
    from flask import current_app
    return current_app.config["SESSIONS"]


def open_mirror() -> "sqlcipher3.Connection":
    """Open the mirror with the borrowed key, creating it on first use."""
    path = mirror_db_path()
    if not path.exists():
        return db.create(path, g.dek)
    return db.connect(path, g.dek)


def create_app(sessions: SessionStore | None = None) -> Flask:
    app = Flask(__name__)
    app.config["SESSIONS"] = sessions or SessionStore()

    @app.get("/health")
    def health():
        """Liveness, and what this build can do. Needs no session.

        Deliberately says nothing about whether any notes exist or how many —
        an enrolled but idle device learns only that the service is up.
        """
        return jsonify(
            status="ok",
            service_version=SERVICE_VERSION,
            protocol_version=protocol.PROTOCOL_VERSION,
            sessions=len(current_app_sessions()),
            device=_device(),
        )

    @app.post("/session")
    def open_session():
        """Take custody of the database key for a bounded time."""
        body = request.get_json(silent=True) or {}
        try:
            dek = protocol.decode_key(body.get("key"))
        except protocol.ProtocolError as exc:
            return jsonify(error=str(exc)), 400

        ttl = config.session_ttl()
        device = _device()
        session_id = current_app_sessions().open(device, dek, ttl)
        log.info("session opened for %s, expires in %ss", device, ttl)
        return jsonify(session_id=session_id, expires_in=ttl)

    @app.delete("/session/<session_id>")
    def close_session(session_id: str):
        """Hand the key back early, rather than waiting for it to expire."""
        closed = current_app_sessions().close(session_id, _device())
        return jsonify(closed=closed)

    @app.post("/sync")
    @requires_session
    def sync():
        """Receive notes into the mirror.

        The batch is validated before anything is written: every note must match
        the chain entry sent with it, and the batch must continue this mirror's
        chain without a gap.
        """
        try:
            payloads = protocol.parse_batch(g.payload.get("notes"))
        except protocol.ProtocolError as exc:
            return jsonify(error=str(exc)), 400

        conn = open_mirror()
        try:
            result = mirror.store(conn, payloads)
        except protocol.ProtocolError as exc:
            return jsonify(error=str(exc)), 409
        except sqlcipher3.IntegrityError as exc:
            return jsonify(error=f"The mirror refused this batch: {exc}"), 409
        finally:
            conn.close()

        log.info("stored %s notes from %s", result.stored, _device())
        return jsonify(stored=result.stored, skipped=result.skipped, head_seq=result.head_seq)

    @app.post("/mirror/status")
    @requires_session
    def mirror_status():
        """What the mirror already holds, so the laptop only sends the rest."""
        path = mirror_db_path()
        if not path.exists():
            return jsonify(head_seq=0, notes=0, verified=True)
        conn = open_mirror()
        try:
            result = mirror.verify(conn)
            notes = conn.execute("SELECT count(*) AS n FROM notes").fetchone()["n"]
            return jsonify(head_seq=mirror.head_seq(conn), notes=notes, verified=result.ok)
        finally:
            conn.close()

    @app.post("/people")
    @requires_session
    def receive_people():
        """Take the laptop's list of people, so tagging can match names.

        The mirror never invents people; it only ever receives them, keeping the
        laptop the single source of truth for who is on the team.
        """
        try:
            people = protocol.parse_people(g.payload.get("people"))
        except protocol.ProtocolError as exc:
            return jsonify(error=str(exc)), 400

        conn = open_mirror()
        try:
            for person in people:
                models.upsert_person(conn, person.person_id, person.display_name,
                                     person.aliases, person.active, person.created_at)
        finally:
            conn.close()
        return jsonify(stored=len(people))

    @app.post("/tag")
    @requires_session
    def tag():
        """Work out which bins some notes belong to.

        Deliberately takes a list of note ids rather than a batch of text: the
        notes are already here, and re-sending their content would put it on the
        wire a second time for no reason.

        One note at a time, because the model is slow enough that a failure part
        way through a batch should not discard the work already done.
        """
        note_ids = g.payload.get("note_ids")
        if not isinstance(note_ids, list) or len(note_ids) > 100:
            return jsonify(error="'note_ids' must be a list of at most 100 ids."), 400
        model = g.payload.get("model") or tagger.DEFAULT_MODEL
        if not isinstance(model, str) or len(model) > 128:
            return jsonify(error="'model' must be a model name."), 400

        conn = open_mirror()
        try:
            people = tagger.people_from_rows(
                conn.execute("SELECT id, display_name, aliases FROM people WHERE active = 1")
            )
            results: dict[str, list[dict]] = {}
            failed: dict[str, str] = {}
            for raw_id in note_ids:
                if not isinstance(raw_id, int) or isinstance(raw_id, bool):
                    return jsonify(error="Note ids must be whole numbers."), 400
                row = conn.execute(
                    "SELECT raw_text, tombstoned_at FROM notes WHERE id = ?", (raw_id,)
                ).fetchone()
                if row is None or row["tombstoned_at"] is not None:
                    continue  # nothing to read
                try:
                    tags = tagger.tag_note(row["raw_text"], people, model=model)
                except tagger.TaggingUnavailable as exc:
                    # Report and stop: every remaining note would fail the same
                    # way, and the laptop keeps whatever already succeeded.
                    failed[str(raw_id)] = str(exc)
                    break
                results[str(raw_id)] = [
                    {"bin": tag.bin_key, "confidence": tag.confidence} for tag in tags
                ]
        finally:
            conn.close()

        log.info("tagged %s notes for %s", len(results), _device())
        return jsonify(tags=results, failed=failed, model=model)

    @app.errorhandler(404)
    def not_found(_):
        return jsonify(error="No such endpoint."), 404

    @app.errorhandler(500)
    def server_error(exc):
        # Never let an internal message reach the wire: it could carry a path,
        # a query, or a fragment of note text.
        log.exception("unhandled error", exc_info=exc)
        return jsonify(error="The service hit an internal error."), 500

    return app
