"""The anchor: the record of where the audit log is supposed to end.

A hash chain is self-consistent by construction, so a chain rebuilt from the genesis
value verifies as intact however little of the original it contains. Chaining and keying
together stop an attacker editing or re-stamping a row, but nothing inside the log can
tell you that rows were deleted from the end, or that the whole log was replaced, because
the remaining run is internally perfect. The anchor is the outside reference for that: it
records the digest the log should end on, how many entries it should hold, and which key
signed the last of them.

WHAT THIS FILE DOES NOT DO, stated first because it was over-claimed twice.

It is not a trusted anchor against an attacker who can write this volume. It is a file on
the volume, so that attacker can delete it, and can delete anything else placed here to
notice the deletion. Two controls were added in successive rounds to close that: an
authentication tag, and a first-use marker so an absent anchor reads as a tamper alarm
rather than a fresh install. The tag holds and is worth having. The marker only raised the
cost from one deletion to two, in the same directory, which is no cost at all to an actor
who already holds write access to it. It is kept because raising cost is worth something,
and because it is now authenticated so an unkeyed actor can neither forge nor plant it,
but it does NOT close the attack and this file no longer says that it does.

What closes it is corroboration against a store the volume attacker does not control.
This application holds its records in local files and does not integrate with SharePoint,
so that store is the EXPORTED evidence pack the Information Security Manager uploads: a
pack carrying an anchor is a copy of the record held somewhere the volume attacker cannot
reach. "The last exported pack records entries but the volume holds no anchor" is the
tamper alarm, and "neither holds anything" is the only honest fresh install. That
comparison needs the export module, which is a later slice, so `read_anchor` returning
``None`` means only "this volume holds no anchor" and a caller MUST corroborate it before
treating it as an empty log. Between exports there is nothing to corroborate against,
which is why the export cadence is a security control and not housekeeping: see
`docs/DEPLOYMENT.md`. TBC, re-verify the cadence with the ISM.

WHAT IT DOES DO, against the attacker who holds list rights but not the volume and not
the key, which is the attacker the threat model actually names:

It is authenticated under the CURRENT signing key, and only that key. An actor without it
can neither write an anchor nor alter one. A retired key is deliberately NOT accepted here,
even though it IS accepted for stored entries: a key is retired because it may have leaked,
and an actor holding a leaked retired key plus write access to this volume would otherwise
re-sign the whole log, write a matching anchor and marker, and have wholly invented history
certified as intact. That was real, not hypothetical: it defeated the tail-key check in
`chain.verify_log` completely. A retired key exists so stored ENTRIES stay verifiable across
a rotation, which is a different job. Rotation therefore carries an explicit re-anchor step
rather than a wider trust rule.

Against the attacker the threat model names, somebody with write access to the log but not
the volume and not the key, this is sufficient: an edit, a re-stamp, a reorder, a deletion,
a truncation and a wholesale replacement are all caught.

It only moves forward. A write that would shorten the record is refused, and so is a read
of an anchor shorter than one already seen in this process. The first of those matters
most: one bad write used to destroy the durable head and length irrecoverably.

Writes are atomic and durable: a uniquely named temporary file in the target directory,
the file and the directory both flushed, then a rename over the target. A shared fixed
temporary name is not atomic across writers, and without the flushes a pod kill can leave
a stale or zero-length anchor. The marker is written AFTER the anchor rename, with the same
sequence, and an anchor found without a valid marker has the marker repaired on read rather
than being read as evidence. Writing the marker first was worse in both directions: a
failed anchor write left a marker on a virgin volume and every later read raised "it was
deleted", and a non-durable marker write left a zero-length marker beside a good anchor, so
deleting the anchor read as a fresh install.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import stat
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import TypeGuard

from .hashing import GENESIS_HASH, is_hash
from .validation import AuditFieldError, check_key_id

#: The anchor file, held on the persistent volume.
ANCHOR_FILENAME = "audit-anchor.json"

#: Written on first use, so a missing anchor afterwards is a tamper alarm. Authenticated,
#: so an actor without a key can neither forge nor plant it: planting one used to wedge
#: the whole audit path permanently, with no documented way back.
MARKER_FILENAME = "audit-initialised"

#: The stored shape's version. An unknown version fails closed rather than being read
#: with today's semantics, which matters during a rolling deploy where two image versions
#: share the volume. Version 2 added the archive boundary.
ANCHOR_SCHEMA_VERSION = 2

#: The anchor is a fixed, small document. Anything larger is refused unread.
MAXIMUM_ANCHOR_BYTES = 4096

#: Sentinel for "total_length not supplied", which means a log that has never been pruned.
UNSET_TOTAL = -1

#: The highest length seen in this process, per resolved data directory. Keyed on the
#: real path, so the same directory spelt two ways cannot bypass the refusal.
_high_water_lock = threading.Lock()
_high_water: dict[str, int] = {}


class AnchorError(RuntimeError):
    """Raised when the anchor cannot be read or is not trustworthy. Always fail closed."""


class AnchorTamperError(AnchorError):
    """Raised when the anchor's STATE indicates interference rather than a fault.

    Three classes of anchor problem, not two, and getting that wrong has now gone both ways
    in this build. Reporting them all as tampering showed a corrupt file to an assessor as
    an attack. Splitting off only the rollback then put an anchor signed by a key this
    server does not hold, and an anchor deleted beside a surviving marker, into the "fault
    to diagnose" class, which turned a true positive into a false all-clear on the read-out
    an assessor is shown. Both of those are interference: neither can happen by accident,
    and the second is the AUD-001 delete control's own signal.

    An I/O error, a parse failure, an implausible size or an unreadable field is a fault.
    Everything under this type is not.
    """


class AnchorRollbackError(AnchorTamperError):
    """Raised when the stored anchor records FEWER entries than this process has seen.

    A genuine older anchor was put back, which the high-water mark exists to catch.
    """


def reset_high_water_mark() -> None:
    """Forget the highest length seen. For tests and for a deliberate operator re-anchor."""
    with _high_water_lock:
        _high_water.clear()


def _key(data_dir: str) -> str:
    """Return the high-water key for a data directory."""
    return os.path.realpath(data_dir)


def _record_length(data_dir: str, length: int) -> None:
    """Record a length as seen, so a later read or write cannot go backwards."""
    with _high_water_lock:
        resolved = _key(data_dir)
        if length > _high_water.get(resolved, -1):
            _high_water[resolved] = length


def _set_length(data_dir: str, length: int) -> None:
    """Set the mark exactly, for a deliberate operator re-anchor.

    `_record_length` only ever raises the mark, so after a re-anchor from 9 to 4 the next
    legitimate write of 5 was refused and the audit path wedged. Since no register write
    may happen without an audit entry, that took the whole write path down.
    """
    with _high_water_lock:
        _high_water[_key(data_dir)] = length


def _seen_length(data_dir: str) -> int:
    """Return the highest length seen for a data directory, or -1."""
    with _high_water_lock:
        return _high_water.get(_key(data_dir), -1)


@dataclass(frozen=True)
class Anchor:
    """The expected end of the log, and where the active log begins.

    AUD-001 retains 24 months in the active log, exports annually to Library 08, and
    prunes the active log for query performance. Pruning is therefore a normal operation
    and must not read as a truncation, so the anchor records the archive boundary as well
    as the end:

    ● ``length`` is the number of entries in the ACTIVE log.
    ● ``total_length`` is the number ever written, active and archived together.
    ● ``pruned_head`` is the digest of the last archived entry, which is what the first
      active entry chains to. It is ``GENESIS_HASH`` until the first prune.

    So an active log that legitimately starts mid-chain verifies against ``pruned_head``
    with :func:`~complyops.audit.chain.verify_sample`, while ``total_length`` remains the
    figure a truncation would have to falsify. The annual export carries ``pruned_head``
    forward, which is what makes the chain span the archive boundary rather than restart
    at it.
    """

    head: str
    length: int
    key_id: str
    #: Entries ever written. ``UNSET`` means "the same as ``length``", which is a log that
    #: has never been pruned. A sentinel rather than ``None`` so the field is always an
    #: ``int`` after construction and no caller needs an ``or 0`` guard, where a genuine
    #: zero and an unset value would be indistinguishable.
    total_length: int = UNSET_TOTAL
    pruned_head: str = GENESIS_HASH
    schema_version: int = ANCHOR_SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Set ``total_length`` to ``length`` for a log that has never been pruned."""
        if self.total_length == UNSET_TOTAL:
            object.__setattr__(self, "total_length", self.length)
        if self.total_length < self.length:
            raise AnchorError(
                f"an anchor cannot record {self.total_length} entries ever while holding "
                f"{self.length} active: refusing to build one that could never be read back"
            )
        if self.total_length == self.length and self.pruned_head != GENESIS_HASH:
            raise AnchorError(
                "an anchor with nothing archived must carry the genesis boundary: a "
                "non-genesis boundary with no archived entries is incoherent"
            )

    @property
    def archived_length(self) -> int:
        """Return how many entries have been pruned out of the active log."""
        return self.total_length - self.length

    @classmethod
    def genesis(cls, key_id: str) -> Anchor:
        """Return the anchor for a log with no entries yet."""
        return cls(head=GENESIS_HASH, length=0, key_id=key_id)

    def after_prune(self, kept: int, pruned_head: str) -> Anchor:
        """Return the anchor after pruning all but the newest ``kept`` active entries.

        ``pruned_head`` is the digest of the newest entry being archived, which becomes
        what the remaining active log chains from. ``total_length`` does not move: the
        entries left the active log, not the chain.
        """
        if kept == self.length:
            # Nothing is archived, so there is no new boundary. Accepting the caller's
            # digest here wrote an anchor claiming a non-genesis boundary with zero
            # archived entries, which is incoherent, was refused nowhere, and made an
            # untouched log verify as tampered.
            return self
        if kept < 0 or kept > self.length:
            raise AnchorError(
                f"cannot keep {kept} of {self.length} active entries: pruning removes "
                f"entries from the active log, it never invents them"
            )
        if kept and not is_hash(pruned_head):
            raise AnchorError("the pruned head must be the digest of the last archived entry")
        if kept and kept < self.length and pruned_head == GENESIS_HASH:
            # Genesis satisfies is_hash, so this would otherwise write an anchor claiming
            # archived entries whose boundary is the start of the chain: incoherent, and it
            # reads and writes cleanly before failing much later at verification.
            raise AnchorError(
                "pruning archived entries, so the boundary cannot be the genesis digest: "
                "pass the digest of the last archived entry"
            )
        if not kept:
            # Everything archived, so the last archived entry IS the current head by
            # definition, whatever the caller passed. An empty active log ends where it
            # begins, so head and the boundary are the same digest.
            return Anchor(
                head=self.head,
                length=0,
                key_id=self.key_id,
                total_length=self.total_length,
                pruned_head=self.head,
            )
        return Anchor(
            head=self.head,
            length=kept,
            key_id=self.key_id,
            total_length=self.total_length,
            pruned_head=pruned_head,
        )

    def _signed_document(self) -> dict[str, object]:
        """Return the fields the authentication tag covers."""
        return {
            "schemaVersion": self.schema_version,
            "head": self.head,
            "length": self.length,
            "keyId": self.key_id,
            "totalLength": self.total_length,
            "prunedHead": self.pruned_head,
        }

    def mac(self, key: bytes) -> str:
        """Return the authentication tag over the anchor's fields."""
        if not key:
            raise AnchorError("the anchor cannot be authenticated without the signing key")
        message = json.dumps(self._signed_document(), sort_keys=True).encode("utf-8")
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def as_json(self, key: bytes) -> str:
        """Return the anchor as the stored, authenticated JSON document."""
        return json.dumps({**self._signed_document(), "mac": self.mac(key)}, sort_keys=True)


def anchor_path(data_dir: str) -> Path:
    """Return the anchor's path inside the persistent data directory."""
    return Path(data_dir) / ANCHOR_FILENAME


def marker_path(data_dir: str) -> Path:
    """Return the first-use marker's path."""
    return Path(data_dir) / MARKER_FILENAME


def _marker_tag(data_dir: str, key: bytes) -> str:
    """Return the marker's authentication tag.

    Bound to the resolved directory, so a marker cannot be copied between volumes, and
    keyed, so an actor without a key cannot plant one. Planting an unauthenticated marker
    on a virgin volume made every read raise, which denied the whole audit write path
    with a single zero-byte file.
    """
    if not key:
        raise AnchorError("the marker cannot be authenticated without the signing key")
    return hmac.new(key, _key(data_dir).encode("utf-8"), hashlib.sha256).hexdigest()


def _marker_is_valid(data_dir: str, key: bytes) -> bool:
    """Return whether a genuine marker is present, under the CURRENT signing key.

    Fails CLOSED on a hostile file, and never raises. The marker is written by us and read
    by us, but it sits on a volume an attacker may be able to write, so it is untrusted
    input like any other. Guarding the tag with :func:`is_hash` before comparing is the same
    fix already applied to the anchor's own tag: `hmac.compare_digest` raises `TypeError` on
    a non-ASCII string and `read_text` raises `UnicodeDecodeError` on invalid UTF-8, so one
    hostile byte here used to come out of `read_anchor` AND out of the write guard as an
    unhandled exception, turning the tamper alarm into a 500 and denying the whole audit
    path with a one-byte file.

    An empty ``key`` means "cannot verify", which fails closed by reporting no valid marker:
    a caller with no key has no business establishing that a log has been used before.
    """
    target = marker_path(data_dir)
    if not key or not target.exists():
        return False
    try:
        # `lstat` before opening: a FIFO here would block this call forever, and this call
        # is on the boot path. A marker that is not a regular file is not a marker.
        if not stat.S_ISREG(target.lstat().st_mode):
            return False
        if target.stat().st_size > MAXIMUM_ANCHOR_BYTES:
            return False
        stored = target.read_text(encoding="utf-8").strip()
    except (OSError, ValueError, UnicodeDecodeError):
        return False
    return is_hash(stored) and hmac.compare_digest(stored, _marker_tag(data_dir, key))


def write_anchor(
    data_dir: str,
    anchor: Anchor,
    key: bytes,
    *,
    allow_shortening: bool = False,
) -> None:
    """Write the anchor atomically and durably, refusing to shorten the record.

    A shorter total than the one already recorded destroys the durable record
    irrecoverably, which is worse than any read-time control can repair.

    ``key`` is the CURRENT signing key and the only key the anchor is ever authenticated
    under. See :func:`read_anchor` for why a retired key is not accepted here.

    Pass ``allow_shortening`` only for a deliberate operator re-anchor; it also lowers the
    in-process high-water mark, so the next ordinary write is not then refused.
    """
    if not allow_shortening:
        _refuse_regression(data_dir, anchor, key)

    _write(data_dir, anchor, key)
    if allow_shortening:
        _set_length(data_dir, anchor.total_length)
    else:
        _record_length(data_dir, anchor.total_length)


def _write(data_dir: str, anchor: Anchor, key: bytes) -> None:
    """Write the anchor and its marker atomically and durably. No policy, just the write."""
    target = anchor_path(data_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    document = anchor.as_json(key)

    # A unique temp name in the SAME directory: a shared fixed name is not atomic across
    # writers, and a rename is only atomic within one filesystem.
    handle, temporary = tempfile.mkstemp(dir=str(target.parent), prefix=".anchor-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(document)
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    # The marker goes down AFTER the anchor, and as durably. Before was worse in both
    # directions: a failed anchor write left a marker on a virgin volume, so the next read
    # raised "it was deleted" and wedged the audit path; and a plain non-fsynced write left
    # a zero-length marker beside a durable anchor, so deleting the anchor then read as a
    # fresh install, which is the alarm the ordering existed to protect. "Anchor present,
    # marker absent" is now repaired on read rather than treated as evidence.
    _write_marker(data_dir, key)
    _fsync_directory(target.parent)


def _refuse_regression(data_dir: str, anchor: Anchor, key: bytes) -> None:
    """Refuse a write that would shorten or erase the recorded log."""
    if not anchor_path(data_dir).exists() and _marker_is_valid(data_dir, key):
        # The anchor is gone but this log has been used before, which `read_anchor` treats
        # as a hard alarm. The write path has to agree with it: without this, deleting the
        # anchor and leaving the marker let the next write lay down a clean genesis anchor,
        # so ONE deletion produced a state indistinguishable from a fresh install. The
        # module claims the marker raises the cost to two deletions, and this is what makes
        # that true once a writer exists.
        raise AnchorError(
            f"the audit anchor at {anchor_path(data_dir)} is missing although this log has "
            f"been used before, so refusing to write over it. Pass allow_shortening for a "
            f"deliberate operator re-anchor."
        )
    floor = _seen_length(data_dir)
    if anchor_path(data_dir).exists():
        # Strict: an anchor that exists but does not authenticate under the current key is
        # evidence of a record, not the absence of one. Reading it leniently collapsed "there is no
        # anchor" and "there is one I cannot authenticate" into the same answer, and the
        # second is exactly the state the alarm exists for. An operator who genuinely needs
        # to write over it has `allow_shortening`.
        stored = _read_stored(data_dir, key, strict=True)
        if stored is not None:
            floor = max(floor, stored.total_length)
    total = anchor.total_length
    if total < floor:
        raise AnchorError(
            f"refusing to write an anchor recording {total} entries ever over one recording "
            f"{floor}: that would destroy the durable record. Pruning moves entries out of "
            f"the ACTIVE log and leaves this figure alone, so a fall here is not a prune. "
            f"Pass allow_shortening for a deliberate operator re-anchor."
        )


def _is_count(value: object) -> TypeGuard[int]:
    """Return whether a value is a usable non-negative count, refusing booleans."""
    return not isinstance(value, bool) and isinstance(value, int) and value >= 0


def _write_marker(data_dir: str, key: bytes) -> None:
    """Write the first-use marker atomically and durably, like the anchor itself."""
    target = marker_path(data_dir)
    handle, temporary = tempfile.mkstemp(dir=str(target.parent), prefix=".marker-", suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(_marker_tag(data_dir, key))
            stream.flush()
            os.fsync(stream.fileno())
        Path(temporary).replace(target)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def _fsync_directory(directory: Path) -> None:
    """Flush the directory entry, so the rename itself survives a power loss."""
    descriptor = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def re_anchor(
    data_dir: str, *, outgoing_key: bytes, incoming_key: bytes, expected_total: int
) -> Anchor | None:
    """Re-sign the stored anchor under a new key, carrying the record forward unchanged.

    The one operator step a key rotation costs, as executable code rather than prose in a
    runbook, because the write path deliberately refuses to read an anchor it cannot
    authenticate and would otherwise block the very procedure that fixes that.

    ``expected_total`` is REQUIRED and must come from OFF this volume: the total recorded by
    the last exported evidence pack, or the operator's own record. It is not a formality.
    This function is the one moment the outgoing key is trusted, and a rotation is the
    documented response to a key that MAY HAVE LEAKED, so the outgoing key is precisely the
    key that may have signed a forged anchor. Taking the floor from the volume would mean
    taking it from the attacker: an earlier version did, and a short forgery planted under
    the leaked key was then certified under the new key by the operator's own rotation step,
    with the record falling from nine entries to two and no alarm raised. That version's
    docstring said "safe by construction". It was not.

    So the honest description is this: re-anchoring carries forward whatever the outgoing key
    certified, and ``expected_total`` is how a number the attacker cannot reach gets into the
    decision. After a suspected compromise, corroborate against the exported pack first.

    ``key_id`` is untouched, because it records the key that signed the last ENTRY, not the
    key that signed this document. Returns the carried anchor, or ``None`` when the volume
    holds no anchor and none was expected.
    """
    if expected_total < 0:
        raise AnchorError("expected_total cannot be negative")
    stored = read_anchor(data_dir, outgoing_key)
    if stored is None:
        if expected_total:
            raise AnchorError(
                f"this volume holds no anchor, but {expected_total} entries were expected "
                f"from the off-volume record, so it was removed. Do not re-anchor: treat the "
                f"log as unverifiable until it is restored from the evidence library."
            )
        return None
    if stored.total_length < expected_total:
        raise AnchorError(
            f"the stored anchor records {stored.total_length} entries ever but "
            f"{expected_total} were expected from the off-volume record, so it was shortened "
            f"or replaced under the outgoing key. Refusing to carry it forward: re-anchoring "
            f"would certify it under the new key."
        )
    _write(data_dir, stored, incoming_key)
    _record_length(data_dir, stored.total_length)
    return stored


def read_anchor(data_dir: str, key: bytes) -> Anchor | None:
    """Return the stored anchor, ``None`` if this volume holds none, or fail closed.

    ``key`` is the CURRENT signing key, and it is the ONLY key an anchor is authenticated
    under. Accepting any key still held was a serious mistake, made to stop a rotation
    producing a false alarm: an actor holding a LEAKED RETIRED key and write access to the
    volume could then re-sign the whole log under that key, write a matching anchor and
    marker, and have wholly invented history certified as intact. A retired key exists so
    stored ENTRIES stay verifiable across a rotation, which is a different job; the anchor
    is the trusted reference, and a reference trusted to a key that may have leaked is not
    one. The rotation procedure therefore carries an explicit re-anchor step: read under
    the outgoing key, write under the incoming one. See `docs/DEPLOYMENT.md`.

    ``None`` means only "this volume holds no anchor". It is NOT proof the log is empty:
    an attacker with volume write access can delete the anchor and the marker together. The
    caller must corroborate against the last exported evidence pack before treating it as a
    fresh install.
    """
    anchor = _read_stored(data_dir, key, strict=True)
    if anchor is not None and not _marker_is_valid(data_dir, key):
        # The anchor is the evidence; the marker only records that a log exists. A missing
        # or truncated marker beside a genuine anchor is a crash artefact, so repair it
        # rather than raising: raising here would wedge the audit path over a control that
        # the anchor itself already satisfies. Best effort, so a full or read-only volume
        # cannot turn a successful read into a failure.
        with contextlib.suppress(OSError):
            _write_marker(data_dir, key)
    if anchor is None:
        if _marker_is_valid(data_dir, key):
            raise AnchorTamperError(
                f"the audit anchor at {anchor_path(data_dir)} is missing although this log "
                f"has been used before, so it was deleted. Treat the log as unverifiable "
                f"until an operator re-anchors it from the evidence library."
            )
        return None
    _check_not_rolled_back(anchor_path(data_dir), data_dir, anchor.total_length)
    _record_length(data_dir, anchor.total_length)
    return anchor


def _read_stored(data_dir: str, key: bytes, *, strict: bool) -> Anchor | None:
    """Return the anchor on disk, or ``None``. ``strict`` decides whether faults raise."""
    target = anchor_path(data_dir)
    try:
        _refuse_irregular(target)
        return _parse_stored(target, key)
    except (OSError, ValueError, AnchorError) as error:
        if not strict:
            return None
        # ONE arm. Splitting the access fault out and leaving it keyed on the exception's
        # type reintroduced the exact hole the split was made to close: `mkdir
        # audit-anchor.json` beside a valid marker raised `IsADirectoryError` and reported
        # as a fault to diagnose, so one command still bought the softer verdict. The rule
        # is the marker, for every read failure alike; `_content_fault` decides.
        raise _content_fault(data_dir, target, key, error) from error


def _refuse_irregular(target: Path) -> None:
    """Refuse anything at this path that is not a regular file, WITHOUT opening it.

    `mkfifo audit-anchor.json` made `read_text` block forever. `read_anchor` runs from the
    app factory, so the gunicorn worker never finished loading: nothing answered `/healthz`,
    `/readyz` or `/api/diagnostics`, the documented recovery channel was gone, the
    HEALTHCHECK failed and the pod restart-looped. One command, no key, and a tamper alarm
    became a permanent outage, against the hard rule that nothing in this path may prevent
    boot or block indefinitely.

    `lstat`, not `stat`, so a symlink is refused as itself rather than followed to whatever
    it points at.
    """
    try:
        mode = target.lstat().st_mode
    except FileNotFoundError:
        return
    if not stat.S_ISREG(mode):
        raise AnchorError(f"the audit anchor at {target} is not a regular file")


def _content_fault(data_dir: str, target: Path, key: bytes, error: Exception) -> AnchorError:
    """Return the right error for an anchor whose read FAILED, of any kind.

    Classified on STATE, never on the exception's type. That rule has now been got wrong
    twice in the same place. Keying off `ValueError` alone covered an emptied file and
    missed `{}`, `[]`, a bumped `schemaVersion` and a malformed key id, which raise
    `AnchorError`. Keeping a separate arm for `OSError` then missed a directory or a symlink
    put in the file's place. Every one of those is a single command, and each time the
    cheaper shape bought the softer verdict. So there is no type test here at all: beside a
    valid marker, a read that failed is interference.

    A genuine infrastructure fault beside a valid marker therefore reads as tampering, and
    that is the deliberate trade. The marker says this log has been used, so the anchor was
    readable from this pod before; a permissions or device fault appearing under a running
    volume is not routine, and a false alarm an operator can clear from the pod log costs
    less than an alarm that never fires.

    The rule is the marker. This application only ever writes the anchor by renaming a
    fully written, fsynced temporary file over it, so it cannot produce an unusable one; if
    the log has been used before and the anchor is now unusable, something else wrote it.

    Be exact about the reach: an actor who deletes the marker as well still gets the softer
    verdict, because nothing then says the log was ever used. That limit is the anchor's own
    and is recorded in `docs/DEPLOYMENT.md`; this closes the cheaper half of it.
    """
    if isinstance(error, AnchorTamperError):
        return error
    if _marker_is_valid(data_dir, key):
        return AnchorTamperError(
            f"the audit anchor at {target} could not be read although this log has been "
            f"used before, so it was overwritten or replaced. Treat the log as unverifiable "
            f"until an operator re-anchors it from the evidence library."
        )
    if isinstance(error, AnchorError):
        return error
    return AnchorError(f"the audit anchor at {target} could not be read: {error}")


def _parse_stored(target: Path, key: bytes) -> Anchor | None:
    """Read and validate the anchor document, or return ``None`` when there is none."""
    if not target.exists():
        return None
    if target.stat().st_size > MAXIMUM_ANCHOR_BYTES:
        raise AnchorError(f"the audit anchor at {target} is implausibly large")
    document = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise AnchorError(f"the audit anchor at {target} is not a usable anchor")
    return _validate(target, document, key)


def _check_not_rolled_back(target: Path, data_dir: str, length: int) -> None:
    """Refuse an anchor recording fewer entries ever than one already seen in this process.

    The total is the only component that can be guarded here. The active length and the
    head both fall legitimately on every prune, so refusing a fall in either would refuse
    the annual prune AUD-001 requires. That leaves a real gap, stated rather than implied:
    an actor who replaces a genuine anchor with an older genuine one of the SAME total but
    a shorter active log is not caught by this check. See the residual risk in
    `docs/DEPLOYMENT.md`, and note the mark is held in PROCESS memory: a restart clears it,
    and restarts are routine on this platform, so it narrows the window rather than closing
    it. The container runs a single worker, so at least no second process starts without
    it.
    """
    seen = _seen_length(data_dir)
    if length < seen:
        raise AnchorRollbackError(
            f"the audit anchor at {target} records {length} entries ever but {seen} were "
            f"already seen in this process, so an older anchor was restored. Treat the log as "
            f"unverifiable until an operator re-anchors it from the evidence library."
        )


def _validate(target: Path, document: dict[str, object], key: bytes) -> Anchor:
    """Return the anchor from a parsed document, or fail closed."""
    head, length, stored_key_id = (
        document.get("head"),
        document.get("length"),
        document.get("keyId"),
    )
    total = document.get("totalLength", length)
    pruned = document.get("prunedHead", GENESIS_HASH)
    unusable = AnchorError(f"the audit anchor at {target} is not a usable anchor")
    if not is_hash(head) or not is_hash(pruned):
        raise unusable
    # `isinstance(True, int)` is True, so booleans are refused explicitly: `length=True`
    # would otherwise compare equal to a one-entry log.
    if not _is_count(length) or not _is_count(total):
        raise unusable
    if total < length:
        raise unusable
    try:
        # `check_key_id` rejects a non-string as well as a malformed one, so there is no
        # separate isinstance guard: a surviving mutant proved that branch unreachable.
        checked_key_id = check_key_id(stored_key_id)  # type: ignore[arg-type]
    except AuditFieldError as error:
        raise AnchorError(f"the audit anchor at {target} names an unusable key id") from error

    version = document.get("schemaVersion", ANCHOR_SCHEMA_VERSION)
    if isinstance(version, bool) or not isinstance(version, int):
        raise AnchorError(f"the audit anchor at {target} has no usable schema version")
    if version != ANCHOR_SCHEMA_VERSION:
        raise AnchorError(
            f"the audit anchor at {target} is schema version {version}, and this build "
            f"reads version {ANCHOR_SCHEMA_VERSION}. Refusing to read it with the wrong "
            f"semantics."
        )

    anchor = Anchor(
        head=head,
        length=length,
        key_id=checked_key_id,
        total_length=total,
        pruned_head=pruned,
        schema_version=version,
    )
    tag = document.get("mac")
    # A non-digest tag must produce a verdict, not an exception: hmac.compare_digest raises
    # on a non-ASCII string, which let an actor with volume write and no key turn the
    # tamper alarm into an unhandled error.
    if not is_hash(tag) or not key or not hmac.compare_digest(tag, anchor.mac(key)):
        raise AnchorTamperError(
            f"the audit anchor at {target} is not authenticated under the current signing "
            f"key, so it was written or altered by something without that key. After a key "
            f"rotation, re-anchor: read under the outgoing key and write under the incoming "
            f"one."
        )
    return anchor
