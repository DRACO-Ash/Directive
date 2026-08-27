"""Bluestaq Compliance Operations Console.

The application is built by a factory so it can be mounted in-process by the tests
with injected fakes, and so the listener lives outside the app itself. Configuration
is read from the environment, never hard-coded and never from a committed file.
"""

from __future__ import annotations

import logging

from flask import Flask
from flask.json.provider import DefaultJSONProvider

from . import auth, config, csrf, security_headers
from .audit import keys as audit_keys
from .audit.journal import JournalError, resume
from .version import __version__
from .views import health_bp
from .views.api import api_bp
from .views.auth_routes import auth_bp
from .views.console import console_bp
from .views.health import probe_storage

#: The largest request body any route accepts.
MAXIMUM_REQUEST_BYTES = 256 * 1024

__all__ = ["__version__", "create_app"]


def create_app() -> Flask:
    """Build and return the application without listening."""
    # No static folder until a frontend needs one: Flask would otherwise register a
    # /static route over a directory that does not exist.
    # The static folder is deliberately enabled now that the console exists and needs it.
    # It was disabled while the app served only health paths, on the principle that surface
    # you do not need is surface you do not defend. `send_from_directory` refuses traversal,
    # and the directory holds two authored files and nothing generated.
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    # A byte cap on every request body. Werkzeug refuses a larger one with 413 before any
    # handler sees it, so no route has to defend itself against an unbounded payload. Well
    # above the largest legitimate record, which is a 4000-character note.
    app.config["MAX_CONTENT_LENGTH"] = MAXIMUM_REQUEST_BYTES
    # Flask 3 reads app.json.sort_keys. The older JSON_SORT_KEYS config key is accepted
    # silently and does nothing, so setting it would have been dead configuration. A
    # test asserts the result, so a provider change cannot make this a silent no-op.
    if isinstance(app.json, DefaultJSONProvider):
        app.json.sort_keys = False
    # AMD-001 section 10.6: every response, including a probe and an error page.
    security_headers.register(app)

    _install_application(app)

    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(console_bp)
    app.register_blueprint(api_bp)

    _log_boot_verdict(app)
    return app


def _install_application(app: Flask) -> None:
    """Wire the session gate, the record store and the audit chain into an application.

    The chain is resumed from the log and the anchor on the volume, so a restart continues
    the same chain rather than starting a new one, and a volume whose state cannot be
    reconciled leaves the audit path unavailable rather than quietly starting again. Every
    register mutation then fails closed, which is the correct behaviour: a change that
    cannot be evidenced must not happen.
    """
    data_dir = config.data_dir()
    app.config["COMPLYOPS_DATA_DIR"] = data_dir

    auth.install(app)
    csrf.install(app)
    app.after_request(csrf.attach_to_response)

    try:
        key = audit_keys.signing_key()
        chain, verdict = resume(
            data_dir,
            key=key,
            key_id=audit_keys.key_id(),
            keys=audit_keys.verification_keys() or {audit_keys.key_id(): key},
        )
    except Exception as error:
        # Boot proceeds so the diagnostics read-out stays reachable, which is the documented
        # recovery channel for a bad configuration value and now also for an unreconcilable
        # volume. Every mutating route fails closed until an operator acts.
        app.logger.warning("audit chain unavailable: %s", type(error).__name__)
        app.extensions["complyops_chain"] = None
        app.extensions["complyops_audit_status"] = _audit_status(error)
        return

    app.extensions["complyops_chain"] = chain
    app.extensions["complyops_audit_status"] = verdict.summary()
    app.logger.info("boot: audit log resumed, %s", verdict.summary())


def _audit_status(error: BaseException) -> str:
    """Return a status line for the diagnostics read-out.

    A journal fault names what is wrong with the volume, because that is the operator's
    recovery instruction and it describes the volume rather than any secret. Anything else
    is reported by type only, because a key or configuration fault must not echo a value.
    """
    if isinstance(error, JournalError):
        return f"unavailable: {error}"
    return f"unavailable: {type(error).__name__}"


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

    _log_input_presence(app)


def _log_input_presence(app: Flask) -> None:
    """Write the credential presence map to the log, as booleans and length bands only.

    This is the recovery channel for an operator who cannot sign in. The same map is on
    `/api/diagnostics`, but that half is signed-in only, and `entra_is_configured` tests
    presence rather than correctness: a PRESENT BUT WRONG `CLIENT_SECRET` disables the
    self-asserted sign-in path while the real one cannot complete, so nobody can reach the
    read-out that would explain it. The pod log is readable from the App Store console
    without authenticating to this application, which is exactly what that case needs.

    Never a value and never an exact length, the same rule the route follows.
    """
    from .views.health import CRITICAL_INPUTS, input_report  # noqa: PLC0415 - avoids a cycle

    try:
        summary = ", ".join(
            f"{name}={'set' if report['present'] else 'MISSING'}({report['lengthBucket']})"
            for name, report in ((name, input_report(name)) for name in CRITICAL_INPUTS)
        )
    except Exception:
        app.logger.exception("boot: the input presence map could not be built")
        return
    app.logger.info("boot: inputs %s", summary)
