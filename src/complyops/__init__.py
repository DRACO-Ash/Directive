"""Bluestaq Compliance Operations Console.

The application is built by a factory so it can be mounted in-process by the tests
with injected fakes, and so the listener lives outside the app itself. Configuration
is read from the environment, never hard-coded and never from a committed file.
"""

from __future__ import annotations

import logging

from flask import Flask

from . import config
from .views import health_bp
from .views.health import probe_storage

__all__ = ["create_app"]


def create_app() -> Flask:
    """Build and return the application without listening."""
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    app.register_blueprint(health_bp)

    _log_boot_verdict(app)
    return app


def _log_boot_verdict(app: Flask) -> None:
    """Emit one decisive line recording whether storage accepted a write.

    A pod the platform kills later still leaves a narrative, rather than a single
    "listening" line that says nothing about why it stopped serving.
    """
    if not app.logger.handlers:
        logging.basicConfig(level=logging.INFO)

    settings = config.Settings.from_environment()
    verdict = probe_storage(settings.data_dir)
    if verdict.writable:
        app.logger.info("boot: %s", verdict.log_line())
    else:
        app.logger.warning("boot: %s", verdict.log_line())
