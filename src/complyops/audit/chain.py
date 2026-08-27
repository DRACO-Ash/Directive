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
The lock covers this process only, and the persistent write is the remaining gap: see the
note on that in `append`. The container therefore runs a SINGLE gunicorn worker with
threads: two workers would each hold their own view of the head, append from it, and write
two entries claiming the same predecessor, and that log fails its own verification with no
attacker anywhere near it. Raising the worker count is blocked on an inter-process lock.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .anchor import Anchor
from .hashing import (
    FIELD_ORDER,
    GENESIS_HASH,
    AuditHashError,
    entry_hash,
    hashes_equal,
    is_hash,
)
from .validation import AuditFieldError, check_key_id, normalise_fields


@dataclass(frozen=True)
class AuditEntry:
    """One immutable audit-log row.

    The field set is the AUD-001 Audit Log Scope table in one fixed shape. ``resource_id``
    is the identifier of the record acted on, for example an incident reference. Fields
    that do not apply to an event are empty rather than absent, so the digest covers a
    fixed shape.

    No field should hold a credential, a session token, or the content of a record, and
    the boundary rules in ``validation`` enforce that for the SHAPES record content
    usually takes rather than for record content itself. ``resource``, ``resource_id``,
    ``actor`` and ``user_agent`` are free-form within printable ASCII and a byte cap, so a
    caller that puts a clinical note in ``resource`` will succeed. Caller discipline is
    load-bearing; the rules narrow the surface, they do not close it.

    ``actor``, ``source_ip`` and ``user_agent`` are personal data, collected deliberately
    under legitimate interest per POL-002 section 03. ``fields_changed`` names the fields a
    change touched and never their values. ``key_id`` names the signing key, so history
    stays verifiable across a rotation.
    """

    timestamp: str
    actor: str
    action: str
    resource: str
    resource_id: str
    outcome: str
    source_ip: str
    user_agent: str
    fields_changed: str
    old_state: str
    new_state: str
    key_id: str
    previous_hash: str
    entry_hash: str

    def covered_fields(self) -> dict[str, str]:
        """Return only the record fields the digest covers, in FIELD_ORDER."""
        return {name: getattr(self, name) for name in FIELD_ORDER}


@dataclass(frozen=True)
class ChainVerdict:
    """The result of verifying a stretch of the chain. Fails closed on any doubt."""

    ok: bool
    checked: int
    break_index: int | None = None
    reason: str | None = None
    broken_entry_hash: str | None = None
    invalid_under_current_rules: bool = False
    key_unavailable: bool = False
    anchor_unusable: bool = False

    @property
    def tampered(self) -> bool:
        """Return whether this verdict means tampering, as opposed to a fault of ours.

        ``ok`` alone is not enough. A caller writing ``if not verdict.ok: alarm()`` would
        raise a tamper alarm for a tightened field rule or a mistyped retired key, which is
        the false alarm the other two flags exist to prevent.
        """
        return (
            not self.ok
            and not self.invalid_under_current_rules
            and not self.key_unavailable
            and not self.anchor_unusable
        )

    def summary(self) -> str:
        """Return a one-line summary fit for an audit record or an operator banner.

        An entry that no longer satisfies today's boundary rules is reported separately
        from a tampered one. Field caps and character rules can only ever tighten, so a
        historical entry written legitimately under looser rules would otherwise read as
        "chain broken" in an assessor pack, which is the one thing this control must not
        say when nothing was tampered with.
        """
        if self.ok:
            return f"chain intact across {self.checked} entries"
        if self.anchor_unusable:
            # Its own branch, and it must not name an entry index. Reusing the tightened
            # field-rule branch produced "entry None does not satisfy the current field
            # rules; its digest is unbroken" for a corrupt anchor file, which is a false
            # statement about an entry that was never examined.
            return (
                f"the trusted anchor could not be read or used, so the {self.checked} "
                f"entries present were not verified against it: {self.reason}"
            )
        if self.invalid_under_current_rules:
            return (
                f"entry {self.break_index} does not satisfy the current field rules; "
                f"its digest is unbroken: {self.reason}"
            )
        if self.key_unavailable:
            return (
                f"entry {self.break_index} cannot be checked because a key is missing, "
                f"which is a configuration fault and not evidence of tampering: {self.reason}"
            )
        if self.break_index is None:
            return f"the log does not match its trusted anchor: {self.reason}"
        return f"chain broken at index {self.break_index}: {self.reason}"


class AuditChain:
    """The chain head. Holds the last digest and the length, never the entries.

    Deliberately not a record of the log. The entries live in the record store; this
    object exists only to derive the next digest correctly and to advance the anchor.
    """

    def __init__(self, anchor: Anchor | None, *, key: bytes, key_id: str) -> None:
        """Start from an anchor, or from genesis when ``anchor`` is explicitly ``None``.

        The anchor is positional and required, for the same reason it is on
        :func:`verify_log`: defaulting it meant the shortest, most natural call produced a
        genesis chain, and writing that anchor destroyed the trusted head. Forgetting an
        argument must not be indistinguishable from a genuine first run, so a fresh
        install is now an explicit ``None``.
        """
        self._key = key
        self._key_id = check_key_id(key_id)
        self._lock = threading.Lock()
        self.head = anchor.head if anchor else GENESIS_HASH
        self.length = anchor.length if anchor else 0
        # The archive boundary. Carried, not recomputed: rebuilding it from `length` on
        # every append discarded it, so the first append after a prune tried to write an
        # anchor recording fewer entries ever than the stored one, `write_anchor` refused
        # it, and the audit path wedged. The escape hatch then wrote the regressed anchor
        # and a restart read it back clean, losing the archived entries with no alarm.
        self._total_length: int = anchor.total_length if anchor else 0
        self._pruned_head = anchor.pruned_head if anchor else GENESIS_HASH
        # The key that signed the LAST entry, which is not the current key between a
        # rotation and the next append. Stamping the current key into the anchor during
        # that window made verify_log report untampered evidence as re-signed.
        self._tail_key_id = anchor.key_id if anchor else self._key_id

    @property
    def key_id(self) -> str:
        """Return the identifier of the key this chain signs NEW entries with.

        Not the key the tail was signed with, which is what the anchor records: between a
        rotation and the next append those differ, and conflating them made verification
        report untampered evidence as re-signed.
        """
        return self._key_id

    def append(self, fields: Mapping[str, object]) -> AuditEntry:
        """Validate, sign, and append one entry, advancing the head.

        Raises :class:`~complyops.audit.validation.AuditFieldError` or
        :class:`~complyops.audit.hashing.AuditHashError` on anything unfit to record,
        and the head is left untouched, so a rejected write cannot half-advance the
        chain.

        The lock makes this atomic within one process, and this method does not persist
        the entry: :class:`complyops.audit.journal.JournalChain` wraps it and writes the
        line and the anchor. Across processes the head read and that write would have to
        become one operation under an inter-process lock on the volume, so until that
        exists the container runs a SINGLE worker and no second process appends.
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
            self._total_length += 1
            self._tail_key_id = self._key_id
        return entry

    def prune(self, kept: int, pruned_head: str) -> Anchor:
        """Move all but the newest ``kept`` active entries into the archive.

        The chain object must be told, not just the anchor. AUD-001 prunes annually and
        that runs as a job inside the serving process, so an anchor pruned beside a live
        chain left the chain still believing it held every entry: the next append produced
        an anchor with the archived entries and the boundary gone, the regression guard
        permitted it because the total had risen, and the genuine active log then verified
        as tampered. Six entries of evidence lost with no alarm and no attacker.

        Returns the new anchor to write. The caller writes it; this method only moves the
        chain's own view, under the same lock as an append so a concurrent append cannot
        interleave with the move.
        """
        with self._lock:
            current = Anchor(
                head=self.head,
                length=self.length,
                key_id=self._tail_key_id,
                total_length=self._total_length,
                pruned_head=self._pruned_head,
            )
            moved = current.after_prune(kept, pruned_head)
            self.length = moved.length
            self._pruned_head = moved.pruned_head
            return moved

    def anchor(self) -> Anchor:
        """Return the anchor describing where the log should now end.

        Stamps the key that signed the TAIL, not the key this chain would sign with next.
        """
        with self._lock:
            return Anchor(
                head=self.head,
                length=self.length,
                key_id=self._tail_key_id,
                total_length=self._total_length,
                pruned_head=self._pruned_head,
            )


def _break(index: int, reason: str, entry: AuditEntry | None = None) -> ChainVerdict:
    """Build a failing verdict for the first break found."""
    return ChainVerdict(
        ok=False,
        checked=index,
        break_index=index,
        reason=reason,
        broken_entry_hash=entry.entry_hash if entry else None,
    )


def _check_link(index: int, entry: AuditEntry, expected_previous: str) -> ChainVerdict | None:
    """Check the entry's shape and its link to the preceding entry."""
    if not is_hash(entry.previous_hash) or not is_hash(entry.entry_hash):
        # The two hash columns are exactly what an actor with write access to the log
        # can type into, so a non-digest value must produce a verdict, never an exception.
        return _break(
            index,
            "a stored hash field is not a 64-character lowercase digest, so the row was "
            "written or altered by something other than this application",
            None,
        )
    if not hashes_equal(entry.previous_hash, expected_previous):
        return _break(
            index,
            "recorded previous hash does not match the preceding entry, so an entry was "
            "edited, reordered, or removed",
            entry,
        )
    return None


def _anchor_break(checked: int, reason: str) -> ChainVerdict:
    """Build a failing verdict for a mismatch against the anchor, which has no index."""
    return ChainVerdict(ok=False, checked=checked, break_index=None, reason=reason)


def _verify_one(
    index: int, entry: AuditEntry, expected_previous: str, keys: Mapping[str, bytes]
) -> ChainVerdict | None:
    """Return a failing verdict for this entry, or ``None`` when it verifies."""
    linked = _check_link(index, entry, expected_previous)
    if linked is not None:
        return linked
    key = keys.get(entry.key_id)
    if not key:
        return ChainVerdict(
            ok=False,
            checked=index,
            break_index=index,
            reason=f"no verification key is available for key id {entry.key_id!r}",
            broken_entry_hash=entry.entry_hash,
            key_unavailable=True,
        )
    # Recompute from the STORED fields, never from a re-validated snapshot, so a later
    # tightening of a field rule cannot change what is hashed.
    try:
        recomputed = entry_hash(
            entry.previous_hash, entry.covered_fields(), key=key, key_id=entry.key_id
        )
    except AuditHashError as error:
        return _break(index, f"entry could not be re-hashed: {error}", entry)
    if not hashes_equal(recomputed, entry.entry_hash):
        return _break(
            index,
            "recomputed hash does not match the stored hash, so a field was altered or "
            "the entry was signed with a different key",
            entry,
        )
    # The digest is sound, so nothing was tampered with. Separately, report an entry that
    # would not be accepted under today's boundary rules, because the caps and character
    # rules can only tighten and a historical entry written legitimately under looser
    # rules must never be reported as tampering.
    try:
        normalise_fields(entry.covered_fields())
    except AuditFieldError as error:
        return ChainVerdict(
            ok=False,
            checked=index,
            break_index=index,
            reason=str(error),
            broken_entry_hash=entry.entry_hash,
            invalid_under_current_rules=True,
        )
    return None


def _walk(
    entries: Sequence[AuditEntry], keys: Mapping[str, bytes], first_previous_hash: str
) -> ChainVerdict:
    """Walk the run, returning the first break or an intact verdict."""
    if not is_hash(first_previous_hash):
        return _break(0, "the expected starting hash is not a digest")

    expected_previous = first_previous_hash
    for index, entry in enumerate(entries):
        verdict = _verify_one(index, entry, expected_previous, keys)
        if verdict is not None:
            return verdict
        expected_previous = entry.entry_hash
    return ChainVerdict(ok=True, checked=len(entries))


def verify_log(
    entries: Sequence[AuditEntry], keys: Mapping[str, bytes], anchor: Anchor
) -> ChainVerdict:
    """Verify the ACTIVE log against its trusted anchor.

    ``entries`` is the whole ACTIVE log, oldest first. It may legitimately begin mid-chain,
    because AUD-001 prunes the active log annually and archives what it removes, so the
    walk starts from the anchor's archive boundary rather than from genesis. Starting from
    genesis reported every pruned log as tampered, which is the one thing this control must
    never say about clean evidence.

    Scope, stated because it is easy to over-read: this verifies the ACTIVE log. It proves
    the active entries are unbroken, that they chain from the recorded boundary, that
    there are as many as the anchor records, and that they end on the anchor's head. It
    proves NOTHING about the archived entries, because they are not passed in and this
    function never sees them. Verifying the archive means walking the exported pack from
    genesis to the boundary digest, which is the export module's job and does not exist
    yet. A tautological count check was briefly here and removed: ``archived_length`` is
    derived from the anchor, so summing it back could never disagree with the anchor.

    The anchor is positional and required, deliberately. It was previously an optional
    keyword defaulting to off, which meant the ordinary call verified a log fabricated
    from genesis, or truncated to any length, as intact: the control existed only for a
    caller who remembered to opt in, and the first caller to forget would have shipped
    the hole. If you are verifying a sample rather than the whole active log, use
    :func:`verify_sample`, which is named so the difference cannot be accidental.
    """
    verdict = _walk(entries, keys, anchor.pruned_head)
    if not verdict.ok:
        return verdict

    if len(entries) != anchor.length:
        return _anchor_break(
            len(entries),
            f"the active log holds {len(entries)} entries but the trusted anchor records "
            f"{anchor.length}, so entries were added or removed",
        )
    ending = entries[-1].entry_hash if entries else anchor.pruned_head
    if not hashes_equal(ending, anchor.head):
        return _anchor_break(
            len(entries),
            "the log does not end on the digest the trusted anchor records, so the end of "
            "the log was rewritten or truncated",
        )
    if entries and entries[-1].key_id != anchor.key_id:
        # A retired key stays a valid signer so history survives a rotation, but a key is
        # retired because it may have leaked. Requiring the log to END under the anchor's
        # key stops a leaked retired key being used to re-sign the whole log.
        return _anchor_break(
            len(entries),
            f"the log ends on an entry signed by key {entries[-1].key_id!r} but the "
            f"trusted anchor records {anchor.key_id!r}, so the tail was re-signed",
        )
    return verdict


def verify_sample(
    entries: Sequence[AuditEntry],
    keys: Mapping[str, bytes],
    *,
    expected_first_previous_hash: str,
) -> ChainVerdict:
    """Verify a contiguous SAMPLE from the middle of the log, oldest first.

    This cannot detect a truncation or a wholesale rewrite, because a sample has no end
    to check against; only :func:`verify_log` can. Pass the digest of the entry
    immediately before the sample.
    """
    return _walk(entries, keys, expected_first_previous_hash)
