"""Chain tests: append, verify, and every way the log can be tampered with."""

from __future__ import annotations

import dataclasses
import sys
import threading
from pathlib import Path

import pytest

from complyops.audit import (
    GENESIS_HASH,
    Anchor,
    AuditChain,
    read_anchor,
    verify_log,
    verify_sample,
    write_anchor,
)
from complyops.audit import anchor as anchor_module
from complyops.audit.hashing import entry_hash
from complyops.audit.validation import AuditFieldError
from conftest import TEST_KEY, TEST_KEY_ID, fixed_entry, keys_for_verification, new_chain

KEYS = keys_for_verification()


def build(count: int) -> tuple[AuditChain, list[object]]:
    """Append ``count`` deterministic entries and return the chain and the entries."""
    chain = new_chain()
    entries = [chain.append(fixed_entry(index)) for index in range(1, count + 1)]
    return chain, entries


def test_the_first_entry_chains_to_the_genesis_hash() -> None:
    chain, entries = build(1)
    assert entries[0].previous_hash == GENESIS_HASH
    assert chain.head == entries[0].entry_hash
    assert chain.length == 1


def test_each_entry_chains_to_its_predecessor() -> None:
    _, entries = build(3)
    assert entries[1].previous_hash == entries[0].entry_hash
    assert entries[2].previous_hash == entries[1].entry_hash


def test_every_entry_records_the_key_that_signed_it() -> None:
    _, entries = build(2)
    assert {entry.key_id for entry in entries} == {TEST_KEY_ID}


def test_a_chain_refuses_a_key_identifier_that_never_passed_the_field_rules() -> None:
    """The key id reaches the digest and every stored row without the field rules."""
    with pytest.raises(AuditFieldError, match="signing key identifier"):
        AuditChain(None, key=TEST_KEY, key_id="=cmd|' /c calc'!A1")


def test_an_intact_log_verifies_against_its_anchor() -> None:
    chain, entries = build(4)
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert verdict.ok
    assert verdict.checked == 4
    assert "intact across 4" in verdict.summary()


def test_an_empty_log_verifies_against_a_genesis_anchor() -> None:
    verdict = verify_log([], KEYS, Anchor.genesis(TEST_KEY_ID))
    assert verdict.ok
    assert verdict.checked == 0


def test_an_empty_log_does_not_verify_against_a_non_empty_anchor() -> None:
    """The unsafe default this replaced reported an emptied log as intact."""
    chain, _ = build(3)
    assert not verify_log([], KEYS, chain.anchor()).ok


@pytest.mark.parametrize("field", ["timestamp", "actor", "action", "resource", "resource_id"])
def test_editing_any_field_breaks_the_chain(field: str) -> None:
    chain, entries = build(3)
    entries[1] = dataclasses.replace(entries[1], **{field: "TAMPERED"})
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert not verdict.ok
    assert verdict.break_index == 1
    assert not verdict.invalid_under_current_rules


def test_deleting_an_entry_breaks_the_chain() -> None:
    chain, entries = build(3)
    del entries[1]
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert not verdict.ok
    assert "edited, reordered, or removed" in (verdict.reason or "")


def test_reordering_entries_breaks_the_chain() -> None:
    chain, entries = build(3)
    entries[1], entries[2] = entries[2], entries[1]
    assert verify_log(entries, KEYS, chain.anchor()).break_index == 1


@pytest.mark.parametrize("field", ["entry_hash", "previous_hash"])
def test_a_stored_hash_that_is_not_a_digest_fails_closed_rather_than_raising(field: str) -> None:
    """The two hash columns are what a list editor can type into.

    Encoding a non-ASCII value as ASCII previously raised UnicodeEncodeError out of the
    verifier, which is a crash where the contract promises a verdict.
    """
    chain, entries = build(2)
    entries[0] = dataclasses.replace(entries[0], **{field: "é" * 64})
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert not verdict.ok
    assert "not a 64-character lowercase digest" in (verdict.reason or "")


def test_a_suffix_rewrite_without_the_key_cannot_be_re_stamped() -> None:
    """The named attacker has list edit rights but not the signing key."""
    chain, entries = build(4)
    forger_key = bytes.fromhex("ff" * 32)
    tampered = dataclasses.replace(entries[1], actor="someone.else@example.invalid")
    rebuilt = [entries[0]]
    previous = entries[0].entry_hash
    for original in (tampered, entries[2], entries[3]):
        candidate = dataclasses.replace(original, previous_hash=previous)
        candidate = dataclasses.replace(
            candidate,
            entry_hash=entry_hash(
                previous, candidate.covered_fields(), key=forger_key, key_id=TEST_KEY_ID
            ),
        )
        rebuilt.append(candidate)
        previous = candidate.entry_hash

    verdict = verify_log(rebuilt, KEYS, chain.anchor())
    assert not verdict.ok
    assert verdict.break_index == 1


def test_a_re_stamped_edit_by_a_key_holder_still_breaks_the_following_entry() -> None:
    chain, entries = build(3)
    forged = dataclasses.replace(entries[1], actor="someone.else@example.invalid")
    forged = dataclasses.replace(
        forged,
        entry_hash=entry_hash(
            forged.previous_hash, forged.covered_fields(), key=TEST_KEY, key_id=TEST_KEY_ID
        ),
    )
    entries[1] = forged
    assert verify_log(entries, KEYS, chain.anchor()).break_index == 2


def test_a_log_fabricated_from_genesis_is_caught_by_the_anchor() -> None:
    """A chain is self-consistent by construction, so only the anchor catches this."""
    real_chain, _ = build(5)
    _, fabricated = build(2)
    verdict = verify_log(fabricated, KEYS, real_chain.anchor())
    assert not verdict.ok
    assert "added or removed" in (verdict.reason or "")


@pytest.mark.parametrize("removed", [1, 2, 5])
def test_truncating_the_tail_is_caught_by_the_anchor(removed: int) -> None:
    chain, entries = build(5)
    assert not verify_log(entries[: len(entries) - removed], KEYS, chain.anchor()).ok


def test_a_run_of_the_right_length_ending_on_the_wrong_digest_is_caught() -> None:
    chain, _ = build(3)
    other = new_chain()
    replacement = [other.append(fixed_entry(index)) for index in (7, 8, 9)]
    verdict = verify_log(replacement, KEYS, chain.anchor())
    assert not verdict.ok
    assert "does not end on the digest" in (verdict.reason or "")


def test_a_log_re_signed_with_a_leaked_retired_key_is_caught() -> None:
    """A retired key is retired because it may have leaked.

    History signed before a rotation must keep verifying, so the retired key stays a
    valid signer. Requiring the log to END under the anchor's key is what stops that
    key being used to re-sign the whole log.
    """
    retired_id, retired_key = "k0", bytes.fromhex("ab" * 32)
    keys = {**KEYS, retired_id: retired_key}
    current_chain, _ = build(3)
    anchor = current_chain.anchor()

    forged_chain = AuditChain(None, key=retired_key, key_id=retired_id)
    forged = [forged_chain.append(fixed_entry(index)) for index in (1, 2, 3)]
    verdict = verify_log(forged, keys, anchor)
    assert not verdict.ok

    # And with the anchor also rewritten to match the forgery's head and length, the key
    # mismatch is what still catches it.
    matching = dataclasses.replace(forged_chain.anchor(), key_id=anchor.key_id)
    verdict = verify_log(forged, keys, matching)
    assert not verdict.ok
    assert "re-signed" in (verdict.reason or "")


def test_an_entry_naming_an_unknown_key_fails_closed() -> None:
    chain, entries = build(1)
    entries[0] = dataclasses.replace(entries[0], key_id="k-unknown")
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert not verdict.ok
    assert "no verification key" in (verdict.reason or "")


def test_verification_reports_the_first_break_only() -> None:
    chain, entries = build(5)
    entries[1] = dataclasses.replace(entries[1], actor="TAMPERED")
    entries[3] = dataclasses.replace(entries[3], actor="TAMPERED_TOO")
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert verdict.break_index == 1
    assert verdict.checked == 1


def test_a_sample_from_the_middle_verifies_against_its_starting_hash() -> None:
    _, entries = build(4)
    verdict = verify_sample(entries[2:], KEYS, expected_first_previous_hash=entries[1].entry_hash)
    assert verdict.ok
    assert verdict.checked == 2


def test_a_sample_verified_against_the_wrong_starting_hash_fails_closed() -> None:
    _, entries = build(4)
    verdict = verify_sample(entries[2:], KEYS, expected_first_previous_hash=GENESIS_HASH)
    assert verdict.break_index == 0


def test_a_starting_hash_that_is_not_a_digest_fails_closed() -> None:
    _, entries = build(1)
    verdict = verify_sample(entries, KEYS, expected_first_previous_hash="nope")
    assert not verdict.ok
    assert "not a digest" in (verdict.reason or "")


def test_an_entry_invalid_under_todays_rules_is_not_reported_as_tampering() -> None:
    """Field rules can only tighten, so history must not read as tampered.

    An entry written legitimately under a looser cap has an unbroken digest. Reporting it
    as "chain broken" in an assessor pack is the one thing this control must not say when
    nothing was tampered with.
    """
    chain, entries = build(1)
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert verdict.ok

    from complyops.audit import validation  # noqa: PLC0415 - patched for this assertion

    original = validation.FIELD_LIMITS["actor"]
    try:
        validation.FIELD_LIMITS["actor"] = 4
        tightened = verify_log(entries, KEYS, chain.anchor())
    finally:
        validation.FIELD_LIMITS["actor"] = original

    assert not tightened.ok
    assert tightened.invalid_under_current_rules
    assert "its digest is unbroken" in tightened.summary()
    assert "chain broken" not in tightened.summary()


def test_a_rejected_append_leaves_the_head_untouched() -> None:
    chain, _ = build(1)
    head_before, length_before = chain.head, chain.length
    bad = fixed_entry()
    del bad["actor"]
    with pytest.raises(AuditFieldError):
        chain.append(bad)
    assert (chain.head, chain.length) == (head_before, length_before)


def test_a_chain_resumes_from_a_stored_anchor() -> None:
    first, entries = build(2)
    resumed = new_chain(anchor=first.anchor())
    assert resumed.head == first.head
    assert resumed.length == 2
    third = resumed.append(fixed_entry(3))
    assert third.previous_hash == entries[1].entry_hash
    assert verify_log([*entries, third], KEYS, resumed.anchor()).ok


def test_the_broken_entry_hash_is_reported_for_the_operator() -> None:
    chain, entries = build(2)
    entries[0] = dataclasses.replace(entries[0], action="TAMPERED")
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert verdict.broken_entry_hash == entries[0].entry_hash
    assert "chain broken at index 0" in verdict.summary()


def test_concurrent_appends_do_not_fork_the_chain() -> None:
    """The container serves several threads, so append must be atomic.

    Without a lock two appends read the same head, and the log then fails its own
    verification with no tampering at all. A false tamper alarm on the evidence an
    assessor is shown is worse than no control.
    """
    chain = new_chain()
    collected: list[object] = []
    collect_lock = threading.Lock()
    workers, per_worker = 16, 8
    count = workers * per_worker
    # A barrier, several appends per worker, and the finest switch interval. With one
    # append per thread and no barrier the same mutation survived a lucky run, so the
    # control could be deleted without the suite noticing.
    ready = threading.Barrier(workers)

    def worker(index: int) -> None:
        ready.wait()
        for step in range(per_worker):
            entry = chain.append(fixed_entry((index * per_worker + step) % 60))
            with collect_lock:
                collected.append(entry)

    previous_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-9)
    try:
        threads = [threading.Thread(target=worker, args=(index,)) for index in range(workers)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        sys.setswitchinterval(previous_interval)

    assert len(collected) == count
    assert chain.length == count
    assert len({entry.previous_hash for entry in collected}) == count, "a head was reused"

    by_previous = {entry.previous_hash: entry for entry in collected}
    walk: list[object] = []
    cursor = GENESIS_HASH
    while cursor in by_previous:
        entry = by_previous[cursor]
        walk.append(entry)
        cursor = entry.entry_hash
    assert len(walk) == count, "the chain did not form one unbroken run"
    assert verify_log(walk, KEYS, chain.anchor()).ok


def test_the_anchor_tracks_the_head_the_length_and_the_key() -> None:
    chain, entries = build(3)
    assert chain.anchor() == Anchor(head=entries[2].entry_hash, length=3, key_id=TEST_KEY_ID)


def test_an_emptied_required_field_reports_a_digest_mismatch() -> None:
    """The hash path no longer enforces the required set, so this is a normal mismatch.

    It used to raise out of the hasher, which the verifier then reported as
    "could not be re-hashed". That was a problem in the other direction: tightening the
    required set made untouched history raise the same way and read as tampering, against
    the rule that history under looser rules must never do so.
    """
    chain, entries = build(1)
    entries[0] = dataclasses.replace(entries[0], actor="")
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert not verdict.ok
    assert verdict.tampered
    assert "recomputed hash does not match" in (verdict.reason or "")


def test_a_field_missing_altogether_still_fails_closed_in_the_hasher() -> None:
    """Absence is not emptiness: it would shift every later field in the payload.

    So it stays fail-closed inside the hash path regardless of the required-field rule.
    """
    from complyops.audit.hashing import AuditHashError, entry_hash  # noqa: PLC0415

    fields = fixed_entry()
    del fields["user_agent"]
    with pytest.raises(AuditHashError, match="missing the 'user_agent' field"):
        entry_hash(GENESIS_HASH, fields, key=TEST_KEY, key_id=TEST_KEY_ID)


def test_tightening_the_required_set_reports_a_rule_failure_not_tampering() -> None:
    """The hard rule this protects: history under looser rules never reads as tampered.

    Enforcing the required set inside the hash path made `entry_hash` raise on
    legitimately written entries the moment the set grew, and the verifier called that
    "chain broken".
    """
    from complyops.audit import hashing, validation  # noqa: PLC0415

    chain, entries = build(1)
    assert verify_log(entries, KEYS, chain.anchor()).ok

    original_required = validation.REQUIRED_FIELDS
    original_hashed = hashing._REQUIRED_NON_EMPTY
    try:
        validation.REQUIRED_FIELDS = (*original_required, "outcome")
        hashing._REQUIRED_NON_EMPTY = original_hashed | {"outcome"}
        verdict = verify_log(entries, KEYS, chain.anchor())
    finally:
        validation.REQUIRED_FIELDS = original_required
        hashing._REQUIRED_NON_EMPTY = original_hashed

    assert not verdict.ok
    assert verdict.invalid_under_current_rules
    assert not verdict.tampered
    assert "its digest is unbroken" in verdict.summary()


def test_a_key_rotation_does_not_make_untampered_evidence_read_as_tampered() -> None:
    """The window between a rotation and the next append is days on a compliance console.

    The chain used to stamp the CURRENT key into the anchor while the tail was still
    signed by the previous one, so verify_log reported clean evidence as re-signed.
    """
    rotated_key = bytes(range(16)) + bytes(range(240, 256))
    keys = {**KEYS, "k2": rotated_key}

    old_chain, entries = build(3)
    rotated = AuditChain(old_chain.anchor(), key=rotated_key, key_id="k2")

    assert rotated.anchor().key_id == TEST_KEY_ID, "the anchor must name the tail's signer"
    verdict = verify_log(entries, keys, rotated.anchor())
    assert verdict.ok, verdict.summary()
    assert not verdict.tampered

    fourth = rotated.append(fixed_entry(4))
    assert rotated.anchor().key_id == "k2"
    assert verify_log([*entries, fourth], keys, rotated.anchor()).ok


def test_a_configuration_fault_is_not_reported_as_tampering() -> None:
    """A mistyped retired key used to produce a verdict indistinguishable from an attack."""
    chain, entries = build(1)
    entries[0] = dataclasses.replace(entries[0], key_id="k-not-configured")
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert not verdict.ok
    assert verdict.key_unavailable
    assert not verdict.tampered
    assert "configuration fault" in verdict.summary()


def test_a_real_break_reports_as_tampering() -> None:
    """The boundary in the other direction: the flag must not swallow a real attack."""
    chain, entries = build(2)
    entries[0] = dataclasses.replace(entries[0], actor="TAMPERED")
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert verdict.tampered
    assert not verdict.key_unavailable
    assert not verdict.invalid_under_current_rules


def test_an_anchor_level_break_reports_no_entry_index() -> None:
    """A three-entry log used to report "chain broken at index 3", which no entry occupies."""
    chain, entries = build(3)
    verdict = verify_log(entries[:2], KEYS, chain.anchor())
    assert verdict.break_index is None
    assert "does not match its trusted anchor" in verdict.summary()


def test_a_chain_requires_its_anchor_to_be_passed_explicitly() -> None:
    """A fresh install must be an explicit None, never a forgotten argument.

    Defaulting it meant the shortest call produced a genesis chain, and writing that
    anchor destroyed the trusted head. That is the same fail-open shape verify_log's
    required positional anchor exists to prevent.
    """
    with pytest.raises(TypeError):
        AuditChain(key=TEST_KEY, key_id=TEST_KEY_ID)  # type: ignore[call-arg]


def test_the_archive_boundary_survives_a_prune_a_restart_and_an_append(tmp_path: Path) -> None:
    """The round trip that had no test, which is why the boundary never worked.

    Every piece existed and was tested in isolation, and nothing drove them together
    through the object the write path actually uses. The consequence was not a subtle
    one: the first append after a prune tried to write an anchor recording fewer entries
    ever than the stored one, the write was refused, and the audit path wedged.
    """
    chain, entries = build(10)
    write_anchor(str(tmp_path), chain.anchor(), TEST_KEY, KEYS)

    # Prune to the newest four, archiving six.
    pruned = chain.anchor().after_prune(kept=4, pruned_head=entries[5].entry_hash)
    write_anchor(str(tmp_path), pruned, TEST_KEY, KEYS)

    # Restart: a fresh process reads the anchor and rebuilds the chain from it.
    anchor_module.reset_high_water_mark()
    stored = read_anchor(str(tmp_path), KEYS)
    assert stored is not None
    assert (stored.length, stored.total_length, stored.archived_length) == (4, 10, 6)

    resumed = AuditChain(stored, key=TEST_KEY, key_id=TEST_KEY_ID)
    eleventh = resumed.append(fixed_entry(11))

    advanced = resumed.anchor()
    assert advanced.length == 5
    assert advanced.total_length == 11, "the total must count the archived entries"
    assert advanced.pruned_head == entries[5].entry_hash, "the boundary must be carried"

    # And the advanced anchor is a legitimate write, not a regression.
    write_anchor(str(tmp_path), advanced, TEST_KEY, KEYS)

    active = [*entries[6:], eleventh]
    verdict = verify_log(active, KEYS, advanced)
    assert verdict.ok, verdict.summary()
    assert not verdict.tampered


def test_a_pruned_active_log_verifies_rather_than_reading_as_tampered() -> None:
    """verify_log walked from genesis, so every legitimately pruned log read as tampered.

    That is the false tamper alarm on assessor evidence this whole module exists to
    avoid, and it left verify_sample as the only usable verifier, which by construction
    cannot detect a truncation.
    """
    chain, entries = build(8)
    pruned = chain.anchor().after_prune(kept=3, pruned_head=entries[4].entry_hash)

    verdict = verify_log(entries[5:], KEYS, pruned)
    assert verdict.ok, verdict.summary()
    assert not verdict.tampered


def test_a_truncated_active_log_is_still_caught_after_a_prune() -> None:
    """The boundary must not become a way to bless a shorter log."""
    chain, entries = build(8)
    pruned = chain.anchor().after_prune(kept=3, pruned_head=entries[4].entry_hash)

    assert not verify_log(entries[5:7], KEYS, pruned).ok
    assert not verify_log(entries[6:], KEYS, pruned).ok


def test_verifying_the_active_log_says_nothing_about_the_archive() -> None:
    """The scope limit, asserted so nobody reads more into a green verdict.

    verify_log never sees the archived entries, so it cannot speak for them. Lowering the
    recorded total is caught by the anchor's authentication tag, not here; detecting the
    deletion of an archived entry needs the exported pack, which is a later slice.
    """
    chain, entries = build(8)
    honest = chain.anchor().after_prune(kept=3, pruned_head=entries[4].entry_hash)

    verdict = verify_log(entries[5:], KEYS, honest)
    assert verdict.ok
    assert verdict.checked == 3, "the count is the ACTIVE log, not the whole history"
    assert honest.archived_length == 5


def test_a_fully_pruned_log_verifies_as_empty() -> None:
    chain, _ = build(5)
    pruned = chain.anchor().after_prune(kept=0, pruned_head=chain.head)
    verdict = verify_log([], KEYS, pruned)
    assert verdict.ok, verdict.summary()
    assert (pruned.length, pruned.total_length) == (0, 5)


def test_pruning_a_live_chain_keeps_the_boundary_without_a_restart(tmp_path: Path) -> None:
    """The annual prune AUD-001 mandates runs as a job inside the serving process.

    The chain object has to be told, not just the anchor. Pruning the anchor beside a live
    chain left the chain believing it still held every entry: the next append produced an
    anchor with the archived entries and the boundary gone, the regression guard permitted
    it because the total had risen, and the genuine active log then verified as tampered.
    Six entries of evidence lost with no alarm and no attacker.
    """
    chain, entries = build(10)
    write_anchor(str(tmp_path), chain.anchor(), TEST_KEY, KEYS)

    moved = chain.prune(kept=4, pruned_head=entries[5].entry_hash)
    write_anchor(str(tmp_path), moved, TEST_KEY, KEYS)

    eleventh = chain.append(fixed_entry(11))
    advanced = chain.anchor()
    assert advanced.length == 5
    assert advanced.total_length == 11
    assert advanced.archived_length == 6
    assert advanced.pruned_head == entries[5].entry_hash

    write_anchor(str(tmp_path), advanced, TEST_KEY, KEYS)
    verdict = verify_log([*entries[6:], eleventh], KEYS, advanced)
    assert verdict.ok, verdict.summary()
    assert not verdict.tampered
    assert not verify_log(entries[7:], KEYS, advanced).ok


def test_pruning_is_serialised_against_a_concurrent_append() -> None:
    """The move and an append must not interleave, or the head forks."""
    chain, entries = build(6)
    results: list[object] = []

    def appender() -> None:
        results.append(chain.append(fixed_entry(20)))

    def pruner() -> None:
        results.append(chain.prune(kept=3, pruned_head=entries[2].entry_hash))

    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-9)
    try:
        threads = [threading.Thread(target=appender), threading.Thread(target=pruner)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        sys.setswitchinterval(previous)

    final = chain.anchor()
    assert final.total_length == 7, "the append is counted whichever order they ran in"
    assert final.archived_length == final.total_length - final.length
    assert final.archived_length >= 0


def test_a_no_op_prune_leaves_the_anchor_untouched() -> None:
    """Nothing archived means no new boundary.

    Accepting the caller's digest here wrote an anchor claiming a non-genesis boundary with
    zero archived entries, which is incoherent, was refused nowhere, and made an untouched
    log verify as tampered.
    """
    chain, entries = build(3)
    before = chain.anchor()
    assert chain.prune(kept=3, pruned_head="d" * 64) == before
    assert chain.anchor() == before
    assert verify_log(entries, KEYS, chain.anchor()).ok


def test_an_entry_missing_a_covered_field_reports_a_break_rather_than_raising() -> None:
    """Absence still fails closed inside the hasher, and the verifier converts it.

    A verdict for every input including a hostile one, so a row with a field removed
    outright is reported, never raised.
    """
    chain, entries = build(1)
    broken = _EntryMissingAField(entries[0])
    verdict = verify_log([broken], KEYS, chain.anchor())  # type: ignore[list-item]
    assert not verdict.ok
    assert "could not be re-hashed" in (verdict.reason or "")


class _EntryMissingAField:
    """An entry whose covered fields are incomplete, as a hostile store might return."""

    def __init__(self, real: object) -> None:
        self._real = real
        self.key_id = real.key_id
        self.previous_hash = real.previous_hash
        self.entry_hash = real.entry_hash

    def covered_fields(self) -> dict[str, str]:
        """Return the covered fields with one removed."""
        fields = self._real.covered_fields()
        del fields["user_agent"]
        return fields
