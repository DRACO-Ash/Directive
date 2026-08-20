"""Bluestaq Compliance Operations Console.

The application is built by a factory so it can be mounted in-process by the tests
with injected fakes, and so the listener lives outside the app itself. Configuration
is read from the environment, never hard-coded and never from a committed file.
"""

from __future__ import annotations

import logging

from flask import Flask
from flask.json.provider import DefaultJSONProvider

from . import config, security_headers
from .version import __version__
from .views import health_bp
from .views.health import probe_storage

__all__ = ["__version__", "create_app"]


def create_app() -> Flask:
    """Build and return the application without listening."""
    # No static folder until a frontend needs one: Flask would otherwise register a
    # /static route over a directory that does not exist.
    app = Flask(__name__, static_folder=None)
    # Flask 3 reads app.json.sort_keys. The older JSON_SORT_KEYS config key is accepted
    # silently and does nothing, so setting it would have been dead configuration. A
    # test asserts the result, so a provider change cannot make this a silent no-op.
    if isinstance(app.json, DefaultJSONProvider):
        app.json.sort_keys = False
    # AMD-001 section 10.6: every response, including a probe and an error page.
    security_headers.register(app)

    app.register_blueprint(health_bp)

    _log_boot_verdict(app)
    return app


def _log_boot_verdict(app: Flask) -> None:
    """Emit one decisive line recording whether storage accepted a write.

    A pod the platform kills later still leaves a narrative, rather than a single
    "listening" line that says nothing about why it stopped serving.

    Nothing in here may prevent boot. The diagnostics read-out is the recovery channel
    for a misconfigured value, so a probe that fails while establishing the narrative
    must not take down the very endpoint that would explain it.
    """
    if not app.logger.handlers:
        logging.basicConfig(level=logging.INFO)

    try:
        settings = config.Settings.from_environment()
        verdict = probe_storage(settings.data_dir)
    except Exception:
        app.logger.exception("boot: the storage probe failed; continuing so /readyz can report")
        return

    if verdict.writable:
        app.logger.info("boot: %s", verdict.log_line())
    else:
        app.logger.warning("boot: %s", verdict.log_line())
