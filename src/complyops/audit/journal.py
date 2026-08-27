"""The persistent audit log, and the resume that makes the anchor mean something.

Until this module the entries lived in memory and nothing wrote the anchor, so a restart
lost the log and started a fresh chain with no alarm. AUD-001 retains the log for 24
months; a log that does not survive a restart does not satisfy any part of that.

The file is append-only JSON Lines at ``DATA_DIR/audit/log.jsonl``: one entry per line,
flushed and fsynced before the call returns. Not a single JSON array, deliberately, because
rewriting a whole array to add a row makes every append a chance to lose the file.

Write order is journal, then anchor, and it is chosen rather than incidental. A crash
between the two leaves the log one entry LONGER than the anchor, which is the benign
direction: an anchor ahead of its log is indistinguishable from a truncation, and a false
truncation alarm on the evidence an assessor is shown is the one thing this control must
never raise. :func:`resume` repairs the lag at boot, and only for entries that verify under
the CURRENT signing key, so an actor with write access to the volume cannot use the repair
to graft history on.

A failure to persist wedges the chain for the life of the process. The head has already
advanced in memory at that point, so continuing would chain the next entry onto a
predecessor that is not on disk and fork the log. Refusing every later append is the
fail-closed answer: a change that cannot be evidenced does not happen, and after an
evidence write fails, nothing else happens either until an operator looks.

What this does NOT catch, stated here because the first version of this docstring claimed
the opposite. An actor with write access to the volume and NO KEY can keep a copy of a
genuine older anchor, truncate the log to match it, and restore both. `resume` then
verifies that shorter log as intact, because it IS intact: every entry in it is genuine and
it ends where the restored anchor says it should. The refusal to move backwards lives in
process memory and a restart clears it. Closing this needs a total the attacker cannot
reach, which is the last exported evidence pack, and it is the same control `re_anchor`
already demands an off-volume floor for. Recorded in `docs/DEPLOYMENT.md`.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import asdict, fields
from pathlib import Path

from .anchor import Anchor, read_anchor, write_anchor
from .chain import AuditChain, AuditEntry, ChainVerdict, verify_log

#: The subdirectory of DATA_DIR holding the log, and the file inside it.
LOG_DIRNAME = "audit"
LOG_FILENAME = "log.jsonl"

#: A log larger than this is refused unread rather than pulled into memory. Twenty-four
#: months of this company's compliance activity is thousands of entries, not millions.
MAXIMUM_LOG_BYTES = 64 * 1024 * 1024

_ENTRY_FIELDS = tuple(field.name for field in fields(AuditEntry))


class JournalError(RuntimeError):
    """Raised when the log cannot be read, written, or trusted. Always fail closed."""


def log_path(data_dir: str) -> Path:
    """Return the file holding the active audit log."""
    return Path(data_dir) / LOG_DIRNAME / LOG_FILENAME


def append_entry(data_dir: str, entry: AuditEntry) -> None:
    """Append one entry to the log, flushed to disk before returning.

    The line is written under one ``write`` call so a concurrent appender in another
    process cannot interleave inside it. That is a property of a small append to a file
    opened ``O_APPEND``, not a substitute for an inter-process lock. The container runs a
    single worker so that no second process appends at all; see the deferred table in
    ``docs/DEPLOYMENT.md``.
    """
    target = log_path(data_dir)
    fresh = not target.exists()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(asdict(entry), sort_keys=True, separators=(",", ":")) + "\n"
        descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(descriptor, line.encode("ascii"))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if fresh:
            _fsync_directory(target.parent)
    except OSError as error:
        raise JournalError(f"the audit log at {target} could not be written: {error}") from error


def _fsync_directory(directory: Path) -> None:
    """Flush the directory entry, so a newly created log survives a power loss."""
    descriptor = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_entries(data_dir: str) -> list[AuditEntry]:
    """Return every entry in the active log, oldest first.

    A malformed line raises rather than being skipped, including the last one. Skipping it
    would shorten the log silently, which is the exact effect an attacker truncating the
    file is after; the anchor would catch the shortened log, and it should never have to.
    """
    target = log_path(data_dir)
    if not target.exists():
        return []
    try:
        # `lstat` before opening, for the same reason the anchor does it: a FIFO in place of
        # the log would block this call forever, and `resume` runs from the app factory, so
        # the worker would never finish loading and the pod would restart-loop with no
        # diagnostics reachable. A symlink is refused as itself rather than followed.
        if not stat.S_ISREG(target.lstat().st_mode):
            raise JournalError(f"the audit log at {target} is not a regular file")
        if target.stat().st_size > MAXIMUM_LOG_BYTES:
            raise JournalError(f"the audit log at {target} is implausibly large")
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        # UnicodeDecodeError is a ValueError, not an OSError: one non-UTF-8 byte appended to
        # the log used to escape this module as a raw decode error, breaking the contract
        # that every fault here becomes a JournalError.
        raise JournalError(f"the audit log at {target} could not be read: {error}") from error

    entries: list[AuditEntry] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        entries.append(_parse_line(target, number, line))
    return entries


def _parse_line(target: Path, number: int, line: str) -> AuditEntry:
    """Return one entry from one line, or raise naming the line."""
    try:
        loaded = json.loads(line)
    except ValueError as error:
        raise JournalError(f"{target} line {number} is not readable JSON: {error}") from error
    if not isinstance(loaded, dict):
        raise JournalError(f"{target} line {number} is not an audit entry")
    missing = [name for name in _ENTRY_FIELDS if not isinstance(loaded.get(name), str)]
    if missing:
        raise JournalError(f"{target} line {number} is missing {', '.join(missing)}")
    return AuditEntry(**{name: loaded[name] for name in _ENTRY_FIELDS})


class JournalChain:
    """An :class:`AuditChain` that persists every entry and its anchor before returning.

    Wraps rather than subclasses, because the chain's own contract is that it holds a head
    and never the entries. Persistence is a separate job with separate failure modes, and
    keeping them apart is what lets the chain stay testable without a filesystem.
    """

    def __init__(
        self,
        chain: AuditChain,
        *,
        data_dir: str,
        key: bytes,
        entries: list[AuditEntry] | None = None,
    ) -> None:
        """Hold a chain, the volume it writes to, and the entries already on that volume."""
        self._chain = chain
        self._data_dir = data_dir
        self._key = key
        self._entries: list[AuditEntry] = list(entries or [])
        self._wedged: str | None = None

    @property
    def entries(self) -> list[AuditEntry]:
        """Return the active log, oldest first."""
        return self._entries

    @property
    def signing_key_id(self) -> str:
        """Return the identifier of the key this chain signs with."""
        return self._chain.key_id

    @property
    def signing_key(self) -> bytes:
        """Return the key this chain signs with, for an in-process verification run."""
        return self._key

    @property
    def wedged(self) -> str | None:
        """Return why the chain stopped accepting entries, or ``None`` while healthy."""
        return self._wedged

    def append(self, entry_fields: Mapping[str, object]) -> AuditEntry:
        """Sign one entry, persist it, then advance the stored anchor.

        Raises :class:`JournalError` if the entry cannot be persisted, and wedges the chain
        so no later append can fork the log by chaining onto an entry that is not on disk.
        """
        if self._wedged is not None:
            raise JournalError(
                f"the audit log stopped accepting entries earlier in this process, so no "
                f"further change can be recorded: {self._wedged}"
            )
        entry = self._chain.append(entry_fields)
        try:
            append_entry(self._data_dir, entry)
            write_anchor(self._data_dir, self._chain.anchor(), self._key)
        except Exception as error:
            self._wedged = f"{type(error).__name__}: {error}"
            raise JournalError(f"the audit entry could not be persisted: {error}") from error
        self._entries.append(entry)
        return entry

    def anchor(self) -> Anchor:
        """Return the chain's current anchor."""
        return self._chain.anchor()


def resume(
    data_dir: str, *, key: bytes, key_id: str, keys: Mapping[str, bytes]
) -> tuple[JournalChain, ChainVerdict]:
    """Reopen the log on this volume and return a chain that continues it.

    Raises :class:`JournalError` rather than starting a fresh chain whenever the volume's
    state cannot be reconciled, because silently starting again is how evidence disappears
    without an alarm. Three cases and each is deliberate.

    A log with no anchor is refused. This is the case AUD-001's delete control used to rest
    on SharePoint list versioning for, and it is the anchor's own blind spot named in
    ``docs/DEPLOYMENT.md``: entries present with no anchor beside them means the anchor was
    removed. It is now detectable from this side for the first time, though corroborating a
    volume that holds NEITHER still needs the last exported evidence pack.

    A log shorter than THE ANCHOR ON THIS VOLUME is refused. Be exact about the reach of
    that: it catches an actor who shortens the log and leaves the anchor, and it does NOT
    catch one who restores a genuine older anchor alongside a matching truncation, because
    that pair is internally consistent and the refusal to move backwards does not survive a
    restart. See the note at the top of this module.

    A log one or more entries LONGER than its anchor is repaired, and only when the extra
    entries chain cleanly and are signed under the CURRENT key. That is a crash between the
    two writes, the ordering above makes it the only benign direction, and requiring the
    current key stops a leaked retired key being used to graft invented history on.
    """
    anchor = read_anchor(data_dir, key)
    entries = read_entries(data_dir)

    if anchor is None:
        if entries:
            raise JournalError(
                f"the log at {log_path(data_dir)} holds {len(entries)} entries but this "
                f"volume holds no anchor, so the anchor was removed. Treat the log as "
                f"unverifiable until an operator re-anchors it from the evidence library."
            )
        chain = AuditChain(None, key=key, key_id=key_id)
        return JournalChain(chain, data_dir=data_dir, key=key), verify_log([], keys, chain.anchor())

    verdict = verify_log(entries, keys, anchor)
    if not verdict.ok:
        anchor = _repair_lag(data_dir, entries, keys, anchor, key=key, key_id=key_id)
        verdict = verify_log(entries, keys, anchor)
        if not verdict.ok:
            raise JournalError(
                f"the log on this volume does not verify against its anchor: {verdict.summary()}"
            )

    chain = AuditChain(anchor, key=key, key_id=key_id)
    return JournalChain(chain, data_dir=data_dir, key=key, entries=entries), verdict


def _repair_lag(
    data_dir: str,
    entries: Sequence[AuditEntry],
    keys: Mapping[str, bytes],
    anchor: Anchor,
    *,
    key: bytes,
    key_id: str,
) -> Anchor:
    """Advance the anchor over entries a crash left unanchored, or return it unchanged.

    Returns the stored anchor untouched whenever the log is not a clean extension of it, so
    the caller's second verification still fails and the boot still refuses.
    """
    extra = len(entries) - anchor.length
    if extra <= 0:
        return anchor
    if any(entry.key_id != key_id for entry in entries[anchor.length :]):
        return anchor

    # One verification, not two. A prefix check against the stored anchor was here as
    # defence in depth and is strictly redundant: the whole-log walk below starts from the
    # same archive boundary, so a corrupted prefix fails it too. No test could tell the two
    # apart, which is the signal that the second check was not a control.
    extended = Anchor(
        head=entries[-1].entry_hash,
        length=len(entries),
        key_id=entries[-1].key_id,
        total_length=anchor.total_length + extra,
        pruned_head=anchor.pruned_head,
    )
    if not verify_log(entries, keys, extended).ok:
        return anchor
    write_anchor(data_dir, extended, key)
    return extended
