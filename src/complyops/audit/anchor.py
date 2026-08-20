"""The trusted anchor: where the audit log is supposed to end.

A hash chain is self-consistent by construction, so a chain rebuilt from the genesis
value verifies as intact however little of the original it contains. Chaining and keying
together stop an attacker editing or re-stamping a row, but nothing inside the log can
tell you that rows were deleted from the end, or that the whole log was replaced, because
the remaining run is internally perfect.

The anchor is the outside reference that closes that. It records the digest the log
should end on, how many entries it should hold, and which key signed the last of them, on
the persistent volume rather than in the list, so an actor with list rights cannot
rewrite both.

Three properties make the anchor itself hard to subvert.

It is authenticated. The document carries an HMAC under the signing key, so an actor with
write access to the volume but no key cannot forge one. Without this the anchor was
defeatable by an attacker who never touched the list: replay entry two's genuine digest
into the anchor and a six-entry log truncated to two verifies as intact.

Its absence is not the same as a fresh install. A marker file is written on first use, so
a deleted anchor after that point is a tamper alarm rather than a log with no history yet.
Without this, one ``rm`` removed the only truncation control.

It only ever moves forward within a run. A shorter log than the one already seen is
refused.

Writes are atomic AND durable: a uniquely named temp file in the target directory, the
file and then the directory flushed to disk, then a rename over the target. A shared fixed
temp name is not atomic across writers, which produced torn reads under two writers, and
without the flushes a pod kill can leave a stale or zero-length anchor.

Residual risk, stated rather than implied: an actor with volume write access who KEEPS a
genuine older anchor can restore it alongside a matching truncation of the log, and the
result is indistinguishable from that earlier moment in time. Closing that needs a
trusted record outside this container. The compensating controls are SharePoint list
versioning and retention on the list itself, and the operator's periodic export of the
anchor into the evidence library. TBC, re-verify both with the ISM.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

from .hashing import GENESIS_HASH, is_hash

#: The anchor file, held on the persistent volume.
ANCHOR_FILENAME = "audit-anchor.json"

#: Written on first use, so a missing anchor afterwards is a tamper alarm.
MARKER_FILENAME = "audit-initialised"

#: The stored shape's version, so a later shape change can migrate forward rather than
#: silently misread an older file.
ANCHOR_SCHEMA_VERSION = 1

#: The highest length seen in this process, per data directory. An authenticated anchor
#: cannot be forged, but a genuine OLDER one can be restored, so a read that goes
#: backwards within a run is refused. This does not survive a restart, and cannot: closing
#: the offline case needs a trusted record outside this container, which the module
#: docstring records as residual risk.
_high_water_lock = threading.Lock()
_high_water: dict[str, int] = {}


def reset_high_water_mark() -> None:
    """Forget the highest length seen. For tests and for a deliberate operator re-anchor."""
    with _high_water_lock:
        _high_water.clear()


def _record_length(data_dir: str, length: int) -> None:
    """Record a length as seen, so a later read cannot go backwards."""
    with _high_water_lock:
        if length > _high_water.get(data_dir, -1):
            _high_water[data_dir] = length


def _check_not_rolled_back(target: Path, data_dir: str, length: int) -> None:
    """Refuse an anchor shorter than one already seen in this process."""
    with _high_water_lock:
        seen = _high_water.get(data_dir, -1)
    if length < seen:
        raise AnchorError(
            f"the audit anchor at {target} records {length} entries but {seen} were already "
            f"seen in this process, so an older anchor was restored. Treat the log as "
            f"unverifiable until an operator re-anchors it from the evidence library."
        )


class AnchorError(RuntimeError):
    """Raised when the anchor cannot be read or is not trustworthy. Always fail closed."""


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


def write_anchor(data_dir: str, anchor: Anchor, key: bytes) -> None:
    """Write the anchor atomically and durably, and record first use."""
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
        _fsync_directory(target.parent)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    marker_path(data_dir).touch(exist_ok=True)
    _record_length(data_dir, anchor.length)


def _fsync_directory(directory: Path) -> None:
    """Flush the directory entry, so the rename itself survives a power loss."""
    descriptor = os.open(str(directory), os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def read_anchor(data_dir: str, key: bytes) -> Anchor | None:
    """Return the stored anchor, ``None`` if the log has never been used, or fail closed.

    A present but unreadable, unauthenticated, or implausible anchor raises rather than
    returning ``None``: treating a corrupt anchor as "no anchor yet" would silently drop
    the only control that detects a wholesale rewrite. A MISSING anchor after the
    first-use marker exists raises for the same reason.
    """
    target = anchor_path(data_dir)
    if not target.exists():
        if marker_path(data_dir).exists():
            raise AnchorError(
                f"the audit anchor at {target} is missing although this log has been used "
                f"before, so it was deleted. Treat the log as unverifiable until an "
                f"operator re-anchors it from the evidence library."
            )
        return None
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise AnchorError(f"the audit anchor at {target} could not be read: {error}") from error
    if not isinstance(document, dict):
        raise AnchorError(f"the audit anchor at {target} is not a usable anchor")
    anchor = _validate(target, document, key)
    _check_not_rolled_back(target, data_dir, anchor.length)
    _record_length(data_dir, anchor.length)
    return anchor


def _validate(target: Path, document: dict[str, object], key: bytes) -> Anchor:
    """Return the anchor from a parsed document, or fail closed."""
    head, length, stored_key_id = (
        document.get("head"),
        document.get("length"),
        document.get("keyId"),
    )
    # `isinstance(True, int)` is True, so booleans are refused explicitly: `length=True`
    # would otherwise compare equal to a one-entry log.
    unusable = AnchorError(f"the audit anchor at {target} is not a usable anchor")
    if not is_hash(head):
        raise unusable
    if isinstance(length, bool) or not isinstance(length, int) or length < 0:
        raise unusable
    if not isinstance(stored_key_id, str) or not stored_key_id:
        raise unusable

    version = document.get("schemaVersion", ANCHOR_SCHEMA_VERSION)
    if isinstance(version, bool) or not isinstance(version, int):
        raise AnchorError(f"the audit anchor at {target} has no usable schema version")

    anchor = Anchor(head=head, length=length, key_id=stored_key_id, schema_version=version)
    tag = document.get("mac")
    if not isinstance(tag, str) or not hmac.compare_digest(tag, anchor.mac(key)):
        raise AnchorError(
            f"the audit anchor at {target} is not authenticated under the signing key, so "
            f"it was written or altered by something without the key"
        )
    return anchor
