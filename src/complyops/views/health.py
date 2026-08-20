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
import uuid
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from dataclasses import dataclass
from pathlib import Path

from flask import Blueprint, Response, current_app, jsonify

from .. import config

#: Strictly shorter than the platform's readiness probe timeout, so a stalled mount
#: fails the probe with a diagnosis instead of hanging until the pod is killed.
PROBE_TIMEOUT_SECONDS = 3.0

#: The environment variables the app cannot serve without. Reported as a boolean and a
#: length, never as a value, so a stale value and a correct value are distinguishable
#: without leaking either.
CRITICAL_INPUTS: tuple[str, ...] = (
    "TENANT_ID",
    "CLIENT_ID",
    "CLIENT_SECRET",
    "SESSION_KEY",
    "SHAREPOINT_SITE_ID",
    "REDIRECT_URI",
)

health_bp = Blueprint("health", __name__)


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
    """Create the directory if needed, then write and remove one probe file."""
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
    """Prove the data directory accepts a write, racing a hard timeout.

    Every failure becomes a value rather than an exception, so the probe cannot hang
    the request and cannot raise into the readiness handler.
    """
    reason = config.validate_data_dir(path)
    if reason is not None:
        return StorageVerdict(writable=False, path=path, errno=None, detail=reason)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_write_probe, path)
        try:
            return future.result(timeout=timeout_seconds)
        except FutureTimeout:
            return StorageVerdict(
                writable=False,
                path=path,
                errno=errno_module.ETIMEDOUT,
                detail=f"write did not complete within {timeout_seconds} seconds",
            )


@health_bp.get("/")
def root() -> Response:
    """Return 200 at the root.

    The platform router probes ``GET /`` and treats a redirect as unhealthy, so this
    never redirects to the sign-in route. It touches nothing and needs no session.
    """
    return Response("Bluestaq Compliance Operations Console\n", mimetype="text/plain")


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
    verdict = probe_storage(settings.data_dir)
    return jsonify(
        {
            "buildId": settings.build_id,
            "port": settings.port,
            "dataDir": verdict.path,
            "storageWritable": verdict.writable,
            "storageErrno": verdict.errno,
            "logViewEvents": settings.log_view_events,
            "inputs": {
                name: {"present": bool(config.env(name)), "length": len(config.env(name))}
                for name in CRITICAL_INPUTS
            },
        }
    )
