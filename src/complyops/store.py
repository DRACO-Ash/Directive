"""The record store: local files on the persistent volume, written atomically.

This application does not integrate with SharePoint. It is the system of record on its own
volume and produces standalone files the Information Security Manager exports and uploads
by hand, so this module is where every register actually lives.

Three properties, each of which exists because losing a compliance register is worse than
refusing a write.

Atomic and durable. A record set is written to a uniquely named temporary file in the same
directory, flushed to disk, then renamed over the target, and the directory entry is
flushed after. A partial write leaves the previous file intact rather than a truncated one,
and a rename is only atomic within a filesystem, hence the same directory.

Serialised. One lock per register, held across the read, the change and the write, because
the container serves two threads per worker. Without it two concurrent edits silently drop
one of them.

Validated at the boundary. Every field is checked before it is written, never after it is
read, so a malformed record cannot enter the store at all.

Cross-process writes are the remaining gap: the lock is per process, so two processes
editing the same register concurrently can still lose an edit. The container runs a single
gunicorn worker for exactly this reason, which is a mitigation and not a fix: any second
process on the same volume, including a maintenance script, reopens the gap. Closing it
needs an inter-process lock on the volume, declared in the deferred table in
`docs/DEPLOYMENT.md`.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import Any

#: The subdirectory of DATA_DIR holding the registers.
RECORDS_DIRNAME = "records"

#: A register file larger than this is refused unread. A compliance register for a company
#: of this size is thousands of rows, not millions.
MAXIMUM_REGISTER_BYTES = 32 * 1024 * 1024

_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


class StoreError(RuntimeError):
    """Raised when a register cannot be read or written. Always fail closed."""


def _lock_for(name: str) -> threading.Lock:
    """Return the process-wide lock for one register."""
    with _locks_guard:
        return _locks.setdefault(name, threading.Lock())


def register_path(data_dir: str, name: str) -> Path:
    """Return the file backing one register.

    ``name`` is supplied by the application, never by a request, but it is validated
    anyway: a name that escaped this directory would write a compliance register over
    something else on the volume.
    """
    if not name or not name.replace("-", "").replace("_", "").isalnum():
        raise StoreError(f"{name!r} is not a usable register name")
    return Path(data_dir) / RECORDS_DIRNAME / f"{name}.json"


def read(data_dir: str, name: str) -> list[dict[str, Any]]:
    """Return every record in one register, or an empty list if it has none yet."""
    target = register_path(data_dir, name)
    try:
        if not target.exists():
            return []
        if target.stat().st_size > MAXIMUM_REGISTER_BYTES:
            raise StoreError(f"the {name!r} register is implausibly large")
        loaded = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise StoreError(f"the {name!r} register could not be read: {error}") from error
    if not isinstance(loaded, list) or any(not isinstance(row, dict) for row in loaded):
        raise StoreError(f"the {name!r} register is not a list of records")
    return loaded


def write(data_dir: str, name: str, records: list[dict[str, Any]]) -> None:
    """Replace one register atomically and durably."""
    target = register_path(data_dir, name)
    target.parent.mkdir(parents=True, exist_ok=True)
    document = json.dumps(records, indent=2, sort_keys=True)

    handle, temporary = tempfile.mkstemp(dir=str(target.parent), prefix=f".{name}-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(document)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    _fsync_directory(target.parent)


def _fsync_directory(directory: Path) -> None:
    """Flush the directory entry, so the rename survives a power loss."""
    descriptor = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


class register:  # noqa: N801 - a context manager reads better in lower case here
    """Hold one register open for a read-modify-write, under its lock.

    Usage::

        with register(data_dir, "tasks") as rows:
            rows.append(new_row)

    The write happens on a clean exit. An exception inside the block leaves the stored
    register exactly as it was, which is what makes a rejected audit entry safe: the record
    change and its audit entry either both happen or neither does.
    """

    def __init__(self, data_dir: str, name: str) -> None:
        """Prepare to hold one register open, without reading it yet."""
        self._data_dir = data_dir
        self._name = name
        self._lock = _lock_for(f"{os.path.realpath(data_dir)}::{name}")
        self._rows: list[dict[str, Any]] = []

    def __enter__(self) -> list[dict[str, Any]]:
        """Take the lock and return the register's rows for editing."""
        self._lock.acquire()
        try:
            self._rows = read(self._data_dir, self._name)
        except BaseException:
            self._lock.release()
            raise
        return self._rows

    def __exit__(self, kind: object, value: object, traceback: object) -> None:
        """Write the register back, unless the block raised."""
        try:
            if kind is None:
                write(self._data_dir, self._name, self._rows)
        finally:
            self._lock.release()


def find(rows: list[dict[str, Any]], record_id: str) -> dict[str, Any] | None:
    """Return the row with this identifier, or ``None``."""
    return next((row for row in rows if row.get("id") == record_id), None)


def iter_registers(data_dir: str) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    """Yield every register on the volume, for the evidence export."""
    directory = Path(data_dir) / RECORDS_DIRNAME
    if not directory.exists():
        return
    for path in sorted(directory.glob("*.json")):
        yield path.stem, read(data_dir, path.stem)
