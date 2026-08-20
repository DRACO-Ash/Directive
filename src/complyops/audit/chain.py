"""The audit chain: appending an entry, and verifying a stretch of the log.

An entry is immutable once written. Appending derives the new entry's keyed digest from
the previous entry's digest, so the log is a chain rather than a pile of independently
stamped rows. Verification walks the chain and reports the FIRST break with its index
and reason, because everything after a break is untrustworthy by construction and
listing it all would bury the finding.

Appending is serialised under a lock. The head read, the digest, the head advance and
the length increment are one critical section: without the lock, two concurrent appends
read the same head, and the log then fails its own verification with no tampering at
all. A false tamper alarm on the evidence an assessor is shown is worse than no control.
The lock covers this process only, and the persistent write is the remaining gap: see
the note on that in `append`.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .anchor import Anchor
from .hashing import GENESIS_HASH, AuditHashError, entry_hash, hashes_equal, is_hash
from .validation import AuditFieldError, normalise_fields


@dataclass(frozen=True)
class AuditEntry:
    """One immutable audit-log row.

    ``resource_id`` is the identifier of the record acted on, for example an incident
    reference. No field holds a credential or the content of a personal data record: the
    log records that an action happened, not what the data said. ``key_id`` names the
    signing key, so history stays verifiable across a key rotation.
    """

    timestamp: str
    actor: str
    action: str
    resource: str
    resource_id: str
    key_id: str
    previous_hash: str
    entry_hash: str

    def covered_fields(self) -> dict[str, str]:
        """Return only the record fields the digest covers."""
        return {
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "resource": self.resource,
            "resource_id": self.resource_id,
        }


@dataclass(frozen=True)
class ChainVerdict:
    """The result of verifying a stretch of the chain. Fails closed on any doubt."""

    ok: bool
    checked: int
    break_index: int | None = None
    reason: str | None = None
    broken_entry_hash: str | None = None

    def summary(self) -> str:
        """Return a one-line summary fit for an audit record or an operator banner."""
        if self.ok:
            return f"chain intact across {self.checked} entries"
        return f"chain broken at index {self.break_index}: {self.reason}"


class AuditChain:
    """The chain head. Holds the last digest and the length, never the entries.

    Deliberately not a record of the log. The entries live in the SharePoint list; this
    object exists only to derive the next digest correctly and to advance the anchor.
    """

    def __init__(self, key: bytes, key_id: str, anchor: Anchor | None = None) -> None:
        """Start from an anchor where one exists, else from genesis."""
        self._key = key
        self._key_id = key_id
        self._lock = threading.Lock()
        self.head = anchor.head if anchor else GENESIS_HASH
        self.length = anchor.length if anchor else 0

    def append(self, fields: Mapping[str, object]) -> AuditEntry:
        """Validate, sign, and append one entry, advancing the head.

        Raises :class:`~complyops.audit.validation.AuditFieldError` or
        :class:`~complyops.audit.hashing.AuditHashError` on anything unfit to record,
        and the head is left untouched, so a rejected write cannot half-advance the
        chain.

        The lock makes this atomic within one process. Across processes, and once the
        entry is written to SharePoint rather than returned, the head read and the write
        must become one conditional operation against the list with the head as its
        precondition, or two workers can still fork the chain. TBC, re-verify when the
        Graph write path lands.
        """
        snapshot = normalise_fields(fields)
        with self._lock:
            digest = entry_hash(self.head, snapshot, key=self._key, key_id=self._key_id)
            entry = AuditEntry(
                **snapshot,
                key_id=self._key_id,
                previous_hash=self.head,
                entry_hash=digest,
            )
            self.head = digest
            self.length += 1
        return entry

    def anchor(self) -> Anchor:
        """Return the anchor describing where the log should now end."""
        with self._lock:
            return Anchor(head=self.head, length=self.length, key_id=self._key_id)


def _break(index: int, reason: str, entry: AuditEntry | None = None) -> ChainVerdict:
    """Build a failing verdict for the first break found."""
    return ChainVerdict(
        ok=False,
        checked=index,
        break_index=index,
        reason=reason,
        broken_entry_hash=entry.entry_hash if entry else None,
    )


def _verify_one(
    index: int, entry: AuditEntry, expected_previous: str, keys: Mapping[str, bytes]
) -> ChainVerdict | None:
    """Return a failing verdict for this entry, or ``None`` when it verifies."""
    if not hashes_equal(entry.previous_hash, expected_previous):
        return _break(
            index,
            "recorded previous hash does not match the preceding entry, so an entry was "
            "edited, reordered, or removed",
            entry,
        )
    key = keys.get(entry.key_id)
    if not key:
        return _break(index, f"no verification key is available for key id {entry.key_id!r}", entry)
    try:
        # Re-validate as well as re-hash: a stored row that breaks a boundary rule could
        # never have been written by this application, so name it as invalid rather than
        # reporting only that its digest does not match.
        fields = normalise_fields(entry.covered_fields())
        recomputed = entry_hash(entry.previous_hash, fields, key=key, key_id=entry.key_id)
    except (AuditHashError, AuditFieldError) as error:
        return _break(index, f"entry could not be re-hashed: {error}", entry)
    if not hashes_equal(recomputed, entry.entry_hash):
        return _break(
            index,
            "recomputed hash does not match the stored hash, so a field was altered or "
            "the entry was signed with a different key",
            entry,
        )
    return None


def verify_chain(
    entries: Sequence[AuditEntry],
    keys: Mapping[str, bytes],
    *,
    expected_first_previous_hash: str = GENESIS_HASH,
    expected_last_hash: str | None = None,
    expected_length: int | None = None,
) -> ChainVerdict:
    """Verify a contiguous run of entries, oldest first, against the trusted anchor.

    Pass ``expected_first_previous_hash`` when verifying a sample from the middle of the
    log rather than from the beginning. Pass ``expected_last_hash`` and
    ``expected_length`` from the anchor whenever verifying the whole log: without them a
    run that has been truncated, or replaced wholesale from genesis, is internally
    perfect and would otherwise be reported intact.
    """
    if not is_hash(expected_first_previous_hash):
        return _break(0, "the expected starting hash is not a digest")

    expected_previous = expected_first_previous_hash
    for index, entry in enumerate(entries):
        verdict = _verify_one(index, entry, expected_previous, keys)
        if verdict is not None:
            return verdict
        expected_previous = entry.entry_hash

    if expected_length is not None and len(entries) != expected_length:
        return _break(
            len(entries),
            f"the log holds {len(entries)} entries but the trusted anchor records "
            f"{expected_length}, so entries were added or removed",
        )
    if expected_last_hash is not None and not hashes_equal(expected_previous, expected_last_hash):
        return _break(
            len(entries),
            "the log does not end on the digest the trusted anchor records, so the end "
            "of the log was rewritten or truncated",
        )
    return ChainVerdict(ok=True, checked=len(entries))
