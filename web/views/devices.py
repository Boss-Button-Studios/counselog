"""Enrolling the browsers that are allowed to write while locked.

Enrolment can only happen with the database open, which is the point: the key a
browser is given has to be written somewhere only an unlocked server can read.
So this is the one part of capture that needs a passphrase, and it is needed
once per browser rather than once per note.

The key is shown to the browser exactly once, on the page that creates it, and
the script stores it. There is no page that displays it again — a browser that
lost it enrols afresh, which costs one tap and leaves a clear record.
"""

from __future__ import annotations

from flask import g, redirect, render_template, request, url_for

from core import devices as device_store
from web.access import open_database, requires_unlock


def register(app) -> None:

    @app.get("/devices")
    @requires_unlock
    def device_list():
        conn = open_database()
        try:
            return render_template("devices.html", caller=g.caller,
                                   devices=device_store.list_devices(conn),
                                   enrolled=None, message=None)
        finally:
            conn.close()

    @app.post("/devices")
    @requires_unlock
    def enroll_device():
        """Give this browser a key and hand it over, once."""
        conn = open_database()
        try:
            device, secret = device_store.enroll(conn, request.form.get("label"))
            return render_template(
                "devices.html", caller=g.caller,
                devices=device_store.list_devices(conn),
                # The only time this value is ever rendered. The script on the
                # page stores it and there is no route that will show it again.
                enrolled={"id": device.id, "secret": secret.hex(),
                          "label": device.label},
                message=None,
            )
        finally:
            conn.close()

    @app.post("/devices/<device_id>/revoke")
    @requires_unlock
    def revoke_device(device_id: str):
        """Stop believing a browser.

        Not retroactive. Notes it already wrote passed their checks when they
        were taken in and are part of the record; this only decides what happens
        to notes it writes from now on.
        """
        if not device_store.is_device_id(device_id):
            return redirect(url_for("device_list"))
        conn = open_database()
        try:
            device_store.revoke(conn, device_id)
        finally:
            conn.close()
        return redirect(url_for("device_list"))


__all__ = ["register"]
