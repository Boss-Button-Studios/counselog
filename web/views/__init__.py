"""The routes, grouped by what they are for.

Each module exposes `register(app)` and is called once by the application
factory. Plain functions rather than blueprints on purpose: there is one
application, the endpoint names stay short enough to read in a template, and a
blueprint would add a naming layer that buys nothing here (Law 9).
"""

from __future__ import annotations

from web.views import auth, capture, devices, held


def register_all(app) -> None:
    for module in (auth, capture, devices, held):
        module.register(app)
