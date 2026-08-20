"""Liveness, readiness, and the secret-free diagnostics read-out.

The split matters. Liveness is trivial and dependency-free: a liveness probe that
checks a downstream restarts a healthy container during a transient outage of that
downstream. Readiness proves the things the app needs in order to serve, and returns
503 when it cannot, which de-registers the pod from traffic without killing it.

Storage readiness is proved by a real WRITE, never an existence check: ``mkdir`` on an
existing directory succeeds without write permission, so a root-owned or read-only
mount passes an existence check and then fails the first real write. The probe races a
hard timeout strictly shorter than the platform's, because a stalled mount that hangs
the probe is killed silently by the platform and leaves nothing to diagnose.
"""

from __future__ import annotations

import errno as errno_module
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from flask import Blueprint, Response, current_app, jsonify

from .. import config
from ..version import __version__

#: Strictly shorter than the platform's readiness probe timeout, so a stalled mount
#: fails the probe with a diagnosis instead of hanging until the pod is killed.
PROBE_TIMEOUT_SECONDS = 3.0

#: How long a storage verdict is reused by the diagnostics read-out. Readiness always
#: probes live; diagnostics is unauthenticated in this release, so it must not perform a
#: real filesystem write on every request.
DIAGNOSTICS_CACHE_SECONDS = 10.0

#: The environment variables the app cannot serve without. Reported as a boolean and a
#: bucketed length, never as a value, so a stale value and a correct value are
#: distinguishable without leaking either and without giving an exact length oracle.
#:
#: The `inputs` block moves behind the authorisation check when the auth module lands.
#: Until then this route must NOT be exempted from the platform sign-on gateway; only
#: the health paths are (`docs/DEPLOYMENT.md`).
CRITICAL_INPUTS: tuple[str, ...] = (
    "TENANT_ID",
    "CLIENT_ID",
    "CLIENT_SECRET",
    "SESSION_KEY",
    "SHAREPOINT_SITE_ID",
    "REDIRECT_URI",
)

health_bp = Blueprint("health", __name__)

_cache_lock = threading.Lock()
_cached: tuple[float, StorageVerdict] | None = None


#: The band boundaries the diagnostics read-out reports a configured value's length in.
SHORT_VALUE_LENGTH = 16
FULL_VALUE_LENGTH = 32


def length_bucket(length: int) -> str:
    """Return a coarse band for a configured value's length.

    A boolean says whether a value arrived; the band says whether it looks like the
    right SHAPE of value, which is what distinguishes a stale secret from a correct one.
    An exact length would be a precise oracle on a credential to any caller.
    """
    if length == 0:
        return "0"
    if length < SHORT_VALUE_LENGTH:
        return "1-15"
    if length < FULL_VALUE_LENGTH:
        return "16-31"
    return "32+"


def reset_diagnostics_cache() -> None:
    """Clear the cached verdict. For tests and for a deliberate re-probe."""
    global _cached  # noqa: PLW0603 - one process-wide cache, guarded by the lock below
    with _cache_lock:
        _cached = None


def cached_storage_verdict(path: str, now: float | None = None) -> StorageVerdict:
    """Return a storage verdict, reusing a recent one within the cache window."""
    global _cached  # noqa: PLW0603 - one process-wide cache, guarded by the lock below
    moment = time.monotonic() if now is None else now
    with _cache_lock:
        if _cached is not None:
            cached_at, verdict = _cached
            if verdict.path == path and moment - cached_at < DIAGNOSTICS_CACHE_SECONDS:
                return verdict
    fresh = probe_storage(path)
    with _cache_lock:
        _cached = (moment, fresh)
    return fresh


@dataclass(frozen=True)
class StorageVerdict:
    """The outcome of a real write against the resolved data directory."""

    writable: bool
    path: str
    errno: int | None = None
    detail: str | None = None

    def log_line(self) -> str:
        """Return the one decisive boot line, so a killed pod still leaves a narrative."""
        if self.writable:
            return f"storage accepted a write at {self.path}"
        return f"storage refused a write at {self.path}: errno={self.errno} {self.detail}"


def _write_probe(path: str) -> StorageVerdict:
    """Create the directory if needed, then write and remove one probe file.

    Only ``OSError`` is handled here, because only it carries the errno worth
    reporting. Anything else is contained at the thread boundary in
    :func:`probe_storage`, which is the single place a probe failure becomes a verdict.
    """
    directory = Path(path)
    probe = directory / f".readyz-{uuid.uuid4().hex}"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        with probe.open("w", encoding="utf-8") as handle:
            handle.write("ok")
        probe.unlink()
    except OSError as error:
        # errno only. The path is operational detail, the message is not a secret, and
        # neither carries any record content.
        return StorageVerdict(
            writable=False,
            path=path,
            errno=error.errno,
            detail=errno_module.errorcode.get(error.errno or 0, "unknown"),
        )
    return StorageVerdict(writable=True, path=path)


def probe_storage(path: str, timeout_seconds: float = PROBE_TIMEOUT_SECONDS) -> StorageVerdict:
    """Prove the data directory accepts a write, within a bounded wall-clock time.

    Every failure becomes a value rather than an exception, so the probe cannot raise
    into a handler, and the timeout is a real bound rather than a nominal one. The
    abandoned thread is the deliberate price: a pool that is joined on exit, or any
    construction that waits for the stalled write, returns the right verdict only after
    the stall has finished, which is the hang this control exists to prevent.
    """
    reason = config.validate_data_dir(path)
    if reason is not None:
        return StorageVerdict(writable=False, path=path, errno=None, detail=reason)

    def run() -> None:
        """Run the probe, converting ANY failure into a verdict.

        Containment sits at the thread boundary, not only inside the write. An exception
        escaping the worker would leave the result empty, and the caller would then
        report a timeout it never waited for, or wait the full timeout for a fault that
        had already happened.
        """
        try:
            result.append(_write_probe(path))
        except BaseException as error:
            result.append(
                StorageVerdict(writable=False, path=path, errno=None, detail=type(error).__name__)
            )

    result: list[StorageVerdict] = []
    worker = threading.Thread(target=run, daemon=True)
    started = time.monotonic()
    worker.start()
    worker.join(timeout=timeout_seconds)
    if result:
        return result[0]
    return StorageVerdict(
        writable=False,
        path=path,
        errno=errno_module.ETIMEDOUT,
        detail=(
            f"write did not complete within {timeout_seconds} seconds "
            f"(abandoned after {time.monotonic() - started:.2f})"
        ),
    )


@health_bp.get("/")
def root() -> Response:
    """Return 200 at the root.

    The platform router probes ``GET /`` and treats a redirect as unhealthy, so this
    never redirects to the sign-in route. It touches nothing and needs no session.
    """
    return Response("Bluestaq Compliance Operations Console\n", mimetype="text/plain")


@health_bp.get("/healthz")
@health_bp.get("/livez")
@health_bp.get("/ping")
@health_bp.get("/health")
def liveness() -> Response:
    """Return 200 unauthenticated, dependency-free, touching nothing."""
    return Response("ok\n", mimetype="text/plain")


@health_bp.get("/readyz")
def readiness() -> tuple[Response, int]:
    """Return 200 when the app can serve, else 503 with the resolved path and errno."""
    settings = config.Settings.from_environment()
    verdict = probe_storage(settings.data_dir)
    if verdict.writable:
        return jsonify({"ready": True, "dataDir": verdict.path}), 200
    current_app.logger.error("readiness failed: %s", verdict.log_line())
    return (
        jsonify(
            {
                "ready": False,
                "dataDir": verdict.path,
                "errno": verdict.errno,
                "detail": verdict.detail,
            }
        ),
        503,
    )


@health_bp.get("/api/diagnostics")
def diagnostics() -> Response:
    """Report booleans, counts, and lengths. Never a configured value.

    Present from the first backend commit and carrying every field a plausible failure
    would need, so a misbehaving deploy is diagnosed from one read rather than from a
    sequence of deploy cycles.
    """
    settings = config.Settings.from_environment()
    verdict = cached_storage_verdict(settings.data_dir)
    return jsonify(
        {
            "version": __version__,
            "buildId": settings.build_id,
            "port": settings.port,
            "dataDir": verdict.path,
            "storageWritable": verdict.writable,
            "storageErrno": verdict.errno,
            "logViewEvents": settings.log_view_events,
            "inputs": {
                name: {
                    "present": bool(config.env(name)),
                    "lengthBucket": length_bucket(len(config.env(name))),
                }
                for name in CRITICAL_INPUTS
            },
        }
    )
