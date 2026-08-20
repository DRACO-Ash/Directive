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

What closes it is corroboration against a store the volume attacker does not control. In
this application that is the SharePoint list itself: "the list holds audit rows but the
volume holds no anchor" is the tamper alarm, and "neither holds anything" is the only
honest fresh install. That comparison needs the Graph read path, which is a later slice,
so `read_anchor` returning ``None`` means only "this volume holds no anchor" and a caller
MUST corroborate it before treating it as an empty log. TBC, re-verify the design of that
corroboration with the ISM when the Graph module lands.

WHAT IT DOES DO, against the attacker who holds list rights but not the volume and not
the key, which is the attacker the threat model actually names:

It is authenticated. The document carries an HMAC under a signing key, verified against
every key still held so a rotation does not turn genuine evidence into an accusation. An
actor without a key can neither write one nor alter one.

It only moves forward. A write that would shorten the record is refused, and so is a read
of an anchor shorter than one already seen in this process. The first of those matters
most: one bad write used to destroy the durable head and length irrecoverably.

Writes are atomic and durable: a uniquely named temporary file in the target directory,
the file and the directory both flushed, then a rename over the target. A shared fixed
temporary name is not atomic across writers, and without the flushes a pod kill can leave
a stale or zero-length anchor. The marker is written BEFORE the rename, so an anchor can
never exist without one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

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
#: share the volume.
ANCHOR_SCHEMA_VERSION = 1

#: The anchor is a fixed, small document. Anything larger is refused unread.
MAXIMUM_ANCHOR_BYTES = 4096

#: The highest length seen in this process, per resolved data directory. Keyed on the
#: real path, so the same directory spelt two ways cannot bypass the refusal.
_high_water_lock = threading.Lock()
_high_water: dict[str, int] = {}


class AnchorError(RuntimeError):
    """Raised when the anchor cannot be read or is not trustworthy. Always fail closed."""


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


def _seen_length(data_dir: str) -> int:
    """Return the highest length seen for a data directory, or -1."""
    with _high_water_lock:
        return _high_water.get(_key(data_dir), -1)


@dataclass(frozen=True)
class Anchor:
    """The expected end of the log."""

    head: str
    length: int
    key_id: str
    schema_version: int = ANCHOR_SCHEMA_VERSION

    @classmethod
    def genesis(cls, key_id: str) -> Anchor:
        """Return the anchor for a log with no entries yet."""
        return cls(head=GENESIS_HASH, length=0, key_id=key_id)

    def _signed_document(self) -> dict[str, object]:
        """Return the fields the authentication tag covers."""
        return {
            "schemaVersion": self.schema_version,
            "head": self.head,
            "length": self.length,
            "keyId": self.key_id,
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


def _marker_is_valid(data_dir: str, keys: Mapping[str, bytes]) -> bool:
    """Return whether a genuine marker is present, under any key still held."""
    target = marker_path(data_dir)
    if not target.exists():
        return False
    try:
        stored = target.read_text(encoding="utf-8").strip()
    except OSError:
        return False
    return any(
        hmac.compare_digest(stored, _marker_tag(data_dir, candidate))
        for candidate in keys.values()
        if candidate
    )


def write_anchor(
    data_dir: str, anchor: Anchor, key: bytes, *, allow_shortening: bool = False
) -> None:
    """Write the anchor atomically and durably, refusing to shorten the record.

    A shorter length than the one already recorded destroys the durable head irrecoverably,
    which is worse than any read-time control can repair. Pass ``allow_shortening`` only
    for a deliberate operator re-anchor.
    """
    target = anchor_path(data_dir)
    target.parent.mkdir(parents=True, exist_ok=True)

    if not allow_shortening:
        _refuse_regression(data_dir, anchor, key)

    document = anchor.as_json(key)
    # The marker goes down BEFORE the rename, so an anchor can never exist without one: a
    # kill in that window used to leave an anchor whose deletion then read as a fresh
    # install, silently disarming the alarm.
    marker_path(data_dir).write_text(_marker_tag(data_dir, key), encoding="utf-8")

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
    _fsync_directory(target.parent)
    _record_length(data_dir, anchor.length)


def _refuse_regression(data_dir: str, anchor: Anchor, key: bytes) -> None:
    """Refuse a write that would shorten the recorded log."""
    floor = _seen_length(data_dir)
    stored = _read_stored(data_dir, {"": key}, strict=False)
    if stored is not None:
        floor = max(floor, stored.length)
    if anchor.length < floor:
        raise AnchorError(
            f"refusing to write an anchor recording {anchor.length} entries over one "
            f"recording {floor}: that would destroy the durable head. Pass "
            f"allow_shortening for a deliberate operator re-anchor."
        )


def _fsync_directory(directory: Path) -> None:
    """Flush the directory entry, so the rename itself survives a power loss."""
    descriptor = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_anchor(data_dir: str, keys: Mapping[str, bytes]) -> Anchor | None:
    """Return the stored anchor, ``None`` if this volume holds none, or fail closed.

    ``keys`` is every key still held, so an anchor written before a key rotation still
    authenticates: verifying under the current key alone turned genuine evidence into an
    accusation against the volume, with no recovery path that did not itself trip the
    deletion alarm.

    ``None`` means only "this volume holds no anchor". It is NOT proof the log is empty:
    an attacker with volume write access can delete the anchor and the marker together.
    The caller must corroborate against the list before treating it as a fresh install.
    """
    anchor = _read_stored(data_dir, keys, strict=True)
    if anchor is None:
        if _marker_is_valid(data_dir, keys):
            raise AnchorError(
                f"the audit anchor at {anchor_path(data_dir)} is missing although this log "
                f"has been used before, so it was deleted. Treat the log as unverifiable "
                f"until an operator re-anchors it from the evidence library."
            )
        return None
    _check_not_rolled_back(anchor_path(data_dir), data_dir, anchor.length)
    _record_length(data_dir, anchor.length)
    return anchor


def _read_stored(data_dir: str, keys: Mapping[str, bytes], *, strict: bool) -> Anchor | None:
    """Return the anchor on disk, or ``None``. ``strict`` decides whether faults raise."""
    target = anchor_path(data_dir)
    try:
        return _parse_stored(target, keys)
    except (OSError, ValueError) as error:
        if not strict:
            return None
        raise AnchorError(f"the audit anchor at {target} could not be read: {error}") from error
    except AnchorError:
        if not strict:
            return None
        raise


def _parse_stored(target: Path, keys: Mapping[str, bytes]) -> Anchor | None:
    """Read and validate the anchor document, or return ``None`` when there is none."""
    if not target.exists():
        return None
    if target.stat().st_size > MAXIMUM_ANCHOR_BYTES:
        raise AnchorError(f"the audit anchor at {target} is implausibly large")
    document = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise AnchorError(f"the audit anchor at {target} is not a usable anchor")
    return _validate(target, document, keys)


def _check_not_rolled_back(target: Path, data_dir: str, length: int) -> None:
    """Refuse an anchor shorter than one already seen in this process."""
    seen = _seen_length(data_dir)
    if length < seen:
        raise AnchorError(
            f"the audit anchor at {target} records {length} entries but {seen} were already "
            f"seen in this process, so an older anchor was restored. Treat the log as "
            f"unverifiable until an operator re-anchors it from the evidence library."
        )


def _validate(target: Path, document: dict[str, object], keys: Mapping[str, bytes]) -> Anchor:
    """Return the anchor from a parsed document, or fail closed."""
    head, length, stored_key_id = (
        document.get("head"),
        document.get("length"),
        document.get("keyId"),
    )
    unusable = AnchorError(f"the audit anchor at {target} is not a usable anchor")
    if not is_hash(head):
        raise unusable
    # `isinstance(True, int)` is True, so booleans are refused explicitly: `length=True`
    # would otherwise compare equal to a one-entry log.
    if isinstance(length, bool) or not isinstance(length, int) or length < 0:
        raise unusable
    if not isinstance(stored_key_id, str):
        raise unusable
    try:
        checked_key_id = check_key_id(stored_key_id)
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

    anchor = Anchor(head=head, length=length, key_id=checked_key_id, schema_version=version)
    tag = document.get("mac")
    # A non-digest tag must produce a verdict, not an exception: hmac.compare_digest raises
    # on a non-ASCII string, which let an actor with volume write and no key turn the
    # tamper alarm into an unhandled error.
    if not is_hash(tag) or not any(
        hmac.compare_digest(tag, anchor.mac(candidate)) for candidate in keys.values() if candidate
    ):
        raise AnchorError(
            f"the audit anchor at {target} is not authenticated under any key still held, so "
            f"it was written or altered by something without a key"
        )
    return anchor
