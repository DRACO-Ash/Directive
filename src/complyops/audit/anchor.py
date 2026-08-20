"""The trusted anchor: where the audit log is supposed to end.

A hash chain is self-consistent by construction, so a chain rebuilt from the genesis
value verifies as intact however little of the original it contains. Chaining and
keying together stop an attacker editing or re-stamping a row, but nothing inside the
log can tell you that rows were deleted from the end, or that the whole log was
replaced, because the remaining run is internally perfect.

The anchor is the outside reference that closes it. It records the digest the log should
end on and how many entries it should hold, on the persistent volume rather than in the
list, so an actor with list rights cannot rewrite both. Verification is only meaningful
against it: `verify_chain` will not call a run intact unless it terminates where the
anchor says it should.

Writes are atomic, temp file then rename in the same directory, so a crash never leaves
a half-written anchor that would read as a tamper alarm on the next start.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .hashing import GENESIS_HASH, is_hash

#: The anchor file, held on the persistent volume beside nothing else.
ANCHOR_FILENAME = "audit-anchor.json"

#: The stored shape's version, so a later shape change can migrate forward rather than
#: silently misread an older file.
ANCHOR_SCHEMA_VERSION = 1


class AnchorError(RuntimeError):
    """Raised when the anchor cannot be read or is not trustworthy."""


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

    def as_json(self) -> str:
        """Return the anchor as the stored JSON document."""
        return json.dumps(
            {
                "schemaVersion": self.schema_version,
                "head": self.head,
                "length": self.length,
                "keyId": self.key_id,
            },
            sort_keys=True,
        )


def anchor_path(data_dir: str) -> Path:
    """Return the anchor's path inside the persistent data directory."""
    return Path(data_dir) / ANCHOR_FILENAME


def write_anchor(data_dir: str, anchor: Anchor) -> None:
    """Write the anchor atomically: temp file, then rename over the target."""
    target = anchor_path(data_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(anchor.as_json(), encoding="utf-8")
    temporary.replace(target)


def read_anchor(data_dir: str) -> Anchor | None:
    """Return the stored anchor, ``None`` if there is none, or fail closed.

    A present but unreadable or implausible anchor raises rather than returning
    ``None``: treating a corrupt anchor as "no anchor yet" would silently drop the only
    control that detects a wholesale rewrite.
    """
    target = anchor_path(data_dir)
    if not target.exists():
        return None
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise AnchorError(f"the audit anchor at {target} could not be read: {error}") from error

    head, length, stored_key_id = (
        document.get("head"),
        document.get("length"),
        document.get("keyId"),
    )
    if not is_hash(head) or not isinstance(length, int) or length < 0 or not stored_key_id:
        raise AnchorError(f"the audit anchor at {target} is not a usable anchor")
    return Anchor(
        head=head,
        length=length,
        key_id=str(stored_key_id),
        schema_version=int(document.get("schemaVersion", ANCHOR_SCHEMA_VERSION)),
    )
