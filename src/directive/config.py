"""Runtime configuration for the compliance operations console.

Every value is read from the environment at call time, never at module import, so a
value the platform injects after the process starts is still seen (see the
``security-hardening`` and ``app-store-deployment`` skills). Nothing here is read from
a committed configuration file, and no secret value is ever returned to a caller.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

#: Fallback data directory when the platform injects nothing. Deliberately not baked
#: into the container image as an ``ENV`` line: an ``ENV`` default always beats a code
#: fallback chain and would silently defeat the platform's injected mount.
DEFAULT_DATA_DIR = "/data"

#: The platform contract. The container port is 8080 unless the platform injects PORT.
DEFAULT_PORT = 8080

#: The highest port a TCP listener can bind.
MAX_PORT = 65535

_CONTROL_CHARACTERS = "".join(chr(code) for code in range(32)) + chr(127)


def normalise(raw: str | None) -> str:
    r"""Return ``raw`` with operator-console noise removed.

    The operator console routinely smuggles invisible characters into a pasted value:
    a trailing newline, a stray tab, or a wrapping pair of quotes. A stray tab in a
    path has turned a save into ``mkdir "\\t"``, and a token with a trailing newline
    never matches. Never use such a value raw.
    """
    if raw is None:
        return ""
    value = raw.strip().strip("\"'").strip()
    return "".join(character for character in value if character not in _CONTROL_CHARACTERS)


def env(name: str, default: str = "") -> str:
    """Read one environment variable, normalised, with a non-secret default."""
    value = normalise(os.environ.get(name))
    return value if value else default


def port() -> int:
    """Return the port to listen on: the injected ``PORT``, else 8080.

    Fails closed to the platform default rather than crashing on a malformed value,
    because a container that cannot bind is indistinguishable from a broken probe.
    """
    raw = env("PORT")
    if not raw.isdigit():
        return DEFAULT_PORT
    candidate = int(raw)
    return candidate if 1 <= candidate <= MAX_PORT else DEFAULT_PORT


def data_dir() -> str:
    """Resolve the persistent data directory.

    Resolution order is explicit variable, then the platform-injected variable, then
    the default. Validation is the caller's job (see :func:`validate_data_dir`).
    """
    return env("DATA_DIR") or env("STORAGE_MOUNT_PATH") or DEFAULT_DATA_DIR


def validate_data_dir(path: str) -> str | None:
    """Return ``None`` when ``path`` is usable, else the reason it is not.

    Fails closed and loudly: an absolute path that is not the filesystem root. Whether
    it is writable is proved by a real write at readiness time, never by an existence
    check, because ``mkdir`` on an existing directory succeeds without write
    permission and a root-owned mount then fails the first real write.
    """
    if not path:
        return "no data directory resolved"
    if not Path(path).is_absolute():
        return f"data directory is not absolute: {path!r}"
    # Strip separators rather than comparing against os.sep: normpath("//") returns
    # "//" on POSIX, so a normpath comparison lets "//" through as a non-root path.
    if not os.path.normpath(path).strip(os.sep):
        return "data directory is the filesystem root"
    return None


@dataclass(frozen=True)
class Settings:
    """A snapshot of configuration, taken per request rather than at import."""

    data_dir: str
    port: int
    build_id: str
    log_view_events: bool

    @classmethod
    def from_environment(cls) -> Settings:
        """Build a snapshot from the current environment."""
        return cls(
            data_dir=data_dir(),
            port=port(),
            build_id=env("BUILD_ID", "unknown"),
            # Open question in the flight plan, defaulted to the data-minimisation
            # reading of UK GDPR Article 5(1)(c): View events go to telemetry only,
            # never to the audit log. TBC, re-verify with the ISM before auth lands.
            log_view_events=env("LOG_VIEW_EVENTS").lower() == "true",
        )
