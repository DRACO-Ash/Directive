"""The audit chain: appending an entry, and verifying a stretch of the log.

An entry is immutable once written. Appending derives the new entry's hash from the
previous entry's hash, so the log is a chain rather than a pile of independently
stamped rows. Verification walks the chain and reports the FIRST break with its index
and reason, because everything after a break is untrustworthy by construction and
listing it all would bury the finding.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field

from .hashing import FIELD_ORDER, GENESIS_HASH, AuditHashError, entry_hash, is_hash


@dataclass(frozen=True)
class AuditEntry:
    """One immutable audit-log row.

    ``resource_id`` is the identifier of the record acted on, for example an incident
    reference. No field holds a credential or the content of a personal data record;
    the log records that an action happened, not what the data said.
    """

    timestamp: str
    actor: str
    action: str
    resource: str
    resource_id: str
    previous_hash: str
    entry_hash: str

    def covered_fields(self) -> dict[str, str]:
        """Return only the fields the hash covers, keyed as the hasher expects."""
        return {name: getattr(self, name) for name in FIELD_ORDER}


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


@dataclass
class AuditChain:
    """An append-only chain head. Holds the last hash, never the whole log."""

    head: str = GENESIS_HASH
    length: int = 0
    _entries: list[AuditEntry] = dataclass_field(default_factory=list, repr=False)

    def append(self, fields: Mapping[str, str]) -> AuditEntry:
        """Append one entry and return it, advancing the head.

        Raises :class:`~complyops.audit.hashing.AuditHashError` on any field the hasher
        rejects, and the head is left untouched, so a rejected write cannot leave the
        chain half-advanced.
        """
        digest = entry_hash(self.head, fields)
        entry = AuditEntry(
            timestamp=fields["timestamp"],
            actor=fields["actor"],
            action=fields["action"],
            resource=fields["resource"],
            resource_id=fields["resource_id"],
            previous_hash=self.head,
            entry_hash=digest,
        )
        self.head = digest
        self.length += 1
        self._entries.append(entry)
        return entry

    def entries(self) -> tuple[AuditEntry, ...]:
        """Return the entries appended through this chain head, oldest first."""
        return tuple(self._entries)


def verify_chain(
    entries: Sequence[AuditEntry],
    *,
    expected_first_previous_hash: str = GENESIS_HASH,
) -> ChainVerdict:
    """Verify a contiguous run of entries, oldest first.

    Pass ``expected_first_previous_hash`` when verifying a sample from the middle of
    the log rather than from the beginning. An empty run verifies as intact over zero
    entries, which is honest: there is nothing to contradict.
    """
    expected_previous = expected_first_previous_hash
    if not is_hash(expected_previous):
        return ChainVerdict(
            ok=False,
            checked=0,
            break_index=0,
            reason="the expected starting hash is not a SHA-256 digest",
        )

    for index, entry in enumerate(entries):
        if entry.previous_hash != expected_previous:
            return ChainVerdict(
                ok=False,
                checked=index,
                break_index=index,
                reason=(
                    "recorded previous hash does not match the preceding entry, so an "
                    "entry was edited, reordered, or removed"
                ),
                broken_entry_hash=entry.entry_hash,
            )
        try:
            recomputed = entry_hash(entry.previous_hash, entry.covered_fields())
        except AuditHashError as error:
            return ChainVerdict(
                ok=False,
                checked=index,
                break_index=index,
                reason=f"entry could not be re-hashed: {error}",
                broken_entry_hash=entry.entry_hash,
            )
        if recomputed != entry.entry_hash:
            return ChainVerdict(
                ok=False,
                checked=index,
                break_index=index,
                reason="recomputed hash does not match the stored hash, so a field was altered",
                broken_entry_hash=entry.entry_hash,
            )
        expected_previous = entry.entry_hash

    return ChainVerdict(ok=True, checked=len(entries))
