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
the container serves several threads per worker. Without it two concurrent edits silently
drop one of them.

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
    """Raised when a register cannot be read or written. Always fail closed.

    Every filesystem failure in this module becomes one of these, so a caller has a single
    thing to handle and a full volume answers 503 rather than escaping as an unhandled 500.
    """


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


def stage(data_dir: str, name: str, records: list[dict[str, Any]]) -> Path:
    """Write a register's new contents to a temporary file beside it, and return its path.

    This is the half of a write that can realistically fail: the serialisation, the disk
    space, the permissions and the flush all happen here. Separating it from the rename
    lets a caller do it BEFORE writing the audit entry, so a full volume refuses the change
    with nothing recorded rather than leaving an immutable entry describing a change that
    never landed. See :meth:`register.stage`.
    """
    target = register_path(data_dir, name)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        document = json.dumps(records, indent=2, sort_keys=True)
        handle, temporary = tempfile.mkstemp(
            dir=str(target.parent), prefix=f".{name}-", suffix=".tmp"
        )
    except (OSError, ValueError) as error:
        raise StoreError(f"the {name!r} register could not be prepared: {error}") from error
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(document)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException as error:
        Path(temporary).unlink(missing_ok=True)
        if isinstance(error, OSError):
            raise StoreError(f"the {name!r} register could not be written: {error}") from error
        raise
    return Path(temporary)


def commit(data_dir: str, name: str, staged: Path) -> None:
    """Rename a staged file over its register and flush the directory entry.

    A rename within one filesystem, which is why :func:`stage` writes into the target's own
    directory. This is the narrow window that remains between the audit entry and the
    stored record; see the deferred table in ``docs/DEPLOYMENT.md``.
    """
    target = register_path(data_dir, name)
    try:
        staged.replace(target)
        _fsync_directory(target.parent)
    except OSError as error:
        staged.unlink(missing_ok=True)
        raise StoreError(f"the {name!r} register could not be replaced: {error}") from error


def write(data_dir: str, name: str, records: list[dict[str, Any]]) -> None:
    """Replace one register atomically and durably, staging and committing in one step."""
    commit(data_dir, name, stage(data_dir, name, records))


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

        holder = register(data_dir, "tasks")
        with holder as rows:
            rows.append(new_row)
            holder.stage()          # optional, see below
            write_the_audit_entry()

    The write happens on a clean exit. An exception inside the block leaves the stored
    register exactly as it was, which is what makes a rejected audit entry safe: a change
    the log refuses does not reach the register.

    State the guarantee in the direction it actually holds, because the biconditional was
    claimed once and is false. A refused audit entry means no record change. The reverse is
    NOT guaranteed: a change whose entry was written and whose store write then failed
    leaves an immutable entry describing a change that did not land. :meth:`stage` narrows
    that window to a rename by doing the serialisation, the allocation and the flush before
    the entry is written, so the realistic failures happen with nothing yet recorded. It
    does not close it, and the residual case is declared in ``docs/DEPLOYMENT.md``.
    """

    def __init__(self, data_dir: str, name: str) -> None:
        """Prepare to hold one register open, without reading it yet."""
        self._data_dir = data_dir
        self._name = name
        self._lock = _lock_for(f"{os.path.realpath(data_dir)}::{name}")
        self._rows: list[dict[str, Any]] = []
        self._staged: Path | None = None

    def __enter__(self) -> list[dict[str, Any]]:
        """Take the lock and return the register's rows for editing."""
        self._lock.acquire()
        try:
            self._rows = read(self._data_dir, self._name)
        except BaseException:
            self._lock.release()
            raise
        return self._rows

    def stage(self) -> None:
        """Write the edited rows to a temporary file now, leaving only a rename for exit.

        Call this immediately before whatever else must succeed for the change to be
        legitimate. Raises :class:`StoreError`, which aborts the block with the stored
        register untouched.
        """
        if self._staged is not None:
            self._staged.unlink(missing_ok=True)
        self._staged = stage(self._data_dir, self._name, self._rows)

    def __exit__(self, kind: object, value: object, traceback: object) -> None:
        """Commit the staged file, or write the rows outright, unless the block raised."""
        try:
            if kind is not None:
                if self._staged is not None:
                    self._staged.unlink(missing_ok=True)
            elif self._staged is not None:
                commit(self._data_dir, self._name, self._staged)
            else:
                write(self._data_dir, self._name, self._rows)
        finally:
            self._staged = None
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
