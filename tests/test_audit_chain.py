"""Chain tests: append, verify, and every way the log can be tampered with."""

from __future__ import annotations

import dataclasses
import sys
import threading

import pytest

from complyops.audit import GENESIS_HASH, Anchor, AuditChain, verify_chain
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


def test_an_intact_chain_verifies_against_its_anchor() -> None:
    chain, entries = build(4)
    anchor = chain.anchor()
    verdict = verify_chain(
        entries, KEYS, expected_last_hash=anchor.head, expected_length=anchor.length
    )
    assert verdict.ok
    assert verdict.checked == 4
    assert "intact across 4" in verdict.summary()


def test_an_empty_run_verifies_over_zero_entries() -> None:
    assert verify_chain([], KEYS).ok


@pytest.mark.parametrize("field", ["timestamp", "actor", "action", "resource", "resource_id"])
def test_editing_any_field_breaks_the_chain(field: str) -> None:
    _, entries = build(3)
    entries[1] = dataclasses.replace(entries[1], **{field: "TAMPERED"})
    verdict = verify_chain(entries, KEYS)
    assert not verdict.ok
    assert verdict.break_index == 1


def test_deleting_an_entry_breaks_the_chain() -> None:
    _, entries = build(3)
    del entries[1]
    verdict = verify_chain(entries, KEYS)
    assert not verdict.ok
    assert "edited, reordered, or removed" in (verdict.reason or "")


def test_reordering_entries_breaks_the_chain() -> None:
    _, entries = build(3)
    entries[1], entries[2] = entries[2], entries[1]
    assert verify_chain(entries, KEYS).break_index == 1


def test_a_suffix_rewrite_without_the_key_cannot_be_re_stamped() -> None:
    """The named attacker has list edit rights but not the signing key.

    Editing a row and recomputing every digest after it with the documented algorithm
    is the attack an unkeyed chain reports as intact. Under HMAC the forger needs the
    key, so a rewrite with the wrong key is caught.
    """
    _, entries = build(4)
    forger_key = b"the-attacker-does-not-hold-the-real-key!!"
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

    verdict = verify_chain(rebuilt, KEYS)
    assert not verdict.ok
    assert verdict.break_index == 1


def test_a_re_stamped_edit_by_a_key_holder_still_breaks_the_following_entry() -> None:
    """Even with the key, re-stamping one row in place breaks the next one."""
    _, entries = build(3)
    forged = dataclasses.replace(entries[1], actor="someone.else@example.invalid")
    forged = dataclasses.replace(
        forged,
        entry_hash=entry_hash(
            forged.previous_hash, forged.covered_fields(), key=TEST_KEY, key_id=TEST_KEY_ID
        ),
    )
    entries[1] = forged
    assert verify_chain(entries, KEYS).break_index == 2


def test_a_log_fabricated_from_genesis_is_caught_by_the_anchor() -> None:
    """A chain is self-consistent by construction, so only the anchor catches this."""
    real_chain, _ = build(5)
    anchor = real_chain.anchor()
    _, fabricated = build(2)

    assert verify_chain(fabricated, KEYS).ok, "internally consistent, as expected"
    verdict = verify_chain(
        fabricated, KEYS, expected_last_hash=anchor.head, expected_length=anchor.length
    )
    assert not verdict.ok
    assert "added or removed" in (verdict.reason or "")


@pytest.mark.parametrize("removed", [1, 2, 5])
def test_truncating_the_tail_is_caught_by_the_anchor(removed: int) -> None:
    chain, entries = build(5)
    anchor = chain.anchor()
    truncated = entries[: len(entries) - removed]

    assert verify_chain(truncated, KEYS).ok, "internally consistent, as expected"
    verdict = verify_chain(
        truncated, KEYS, expected_last_hash=anchor.head, expected_length=anchor.length
    )
    assert not verdict.ok


def test_a_run_of_the_right_length_ending_on_the_wrong_digest_is_caught() -> None:
    chain, _ignored = build(3)
    other_chain = new_chain()
    replacement = [other_chain.append(fixed_entry(index)) for index in (7, 8, 9)]
    verdict = verify_chain(
        replacement,
        KEYS,
        expected_last_hash=chain.anchor().head,
        expected_length=3,
    )
    assert not verdict.ok
    assert "does not end on the digest" in (verdict.reason or "")


def test_an_entry_naming_an_unknown_key_fails_closed() -> None:
    _, entries = build(1)
    entries[0] = dataclasses.replace(entries[0], key_id="k-unknown")
    verdict = verify_chain(entries, KEYS)
    assert not verdict.ok
    assert "no verification key" in (verdict.reason or "")


def test_verification_reports_the_first_break_only() -> None:
    _, entries = build(5)
    entries[1] = dataclasses.replace(entries[1], actor="TAMPERED")
    entries[3] = dataclasses.replace(entries[3], actor="TAMPERED_TOO")
    verdict = verify_chain(entries, KEYS)
    assert verdict.break_index == 1
    assert verdict.checked == 1


def test_a_sample_from_the_middle_verifies_against_its_starting_hash() -> None:
    _, entries = build(4)
    verdict = verify_chain(entries[2:], KEYS, expected_first_previous_hash=entries[1].entry_hash)
    assert verdict.ok
    assert verdict.checked == 2


def test_a_sample_verified_against_the_wrong_starting_hash_fails_closed() -> None:
    _, entries = build(4)
    assert verify_chain(entries[2:], KEYS).break_index == 0


def test_a_starting_hash_that_is_not_a_digest_fails_closed() -> None:
    _, entries = build(1)
    verdict = verify_chain(entries, KEYS, expected_first_previous_hash="nope")
    assert not verdict.ok
    assert "not a digest" in (verdict.reason or "")


def test_an_unhashable_entry_fails_closed_rather_than_raising() -> None:
    _, entries = build(1)
    entries[0] = dataclasses.replace(entries[0], actor="   ")
    verdict = verify_chain(entries, KEYS)
    assert not verdict.ok
    assert "could not be re-hashed" in (verdict.reason or "")


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
    assert verify_chain([*entries, third], KEYS).ok


def test_the_broken_entry_hash_is_reported_for_the_operator() -> None:
    _, entries = build(2)
    entries[0] = dataclasses.replace(entries[0], action="TAMPERED")
    verdict = verify_chain(entries, KEYS)
    assert verdict.broken_entry_hash == entries[0].entry_hash
    assert "chain broken at index 0" in verdict.summary()


def test_concurrent_appends_do_not_fork_the_chain() -> None:
    """The container serves several threads, so append must be atomic.

    Without a lock two appends read the same head, and the log then fails its own
    verification with no tampering at all. A false tamper alarm on the evidence an
    assessor is shown is worse than no control.
    """
    switch_interval = 1e-9
    original = threading.TIMEOUT_MAX  # touched only to keep the import honest
    assert original > 0

    chain = new_chain()
    collected: list[object] = []
    collect_lock = threading.Lock()
    count = 64

    def worker(index: int) -> None:
        entry = chain.append(fixed_entry(index % 60))
        with collect_lock:
            collected.append(entry)

    previous_interval = sys.getswitchinterval()
    sys.setswitchinterval(switch_interval)
    try:
        workers = [threading.Thread(target=worker, args=(index,)) for index in range(count)]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join()
    finally:
        sys.setswitchinterval(previous_interval)

    assert len(collected) == count
    assert chain.length == count
    assert len({entry.previous_hash for entry in collected}) == count, "a head was reused"

    ordered = sorted(collected, key=lambda entry: entry.previous_hash != GENESIS_HASH)
    by_previous = {entry.previous_hash: entry for entry in collected}
    walk: list[object] = []
    cursor = GENESIS_HASH
    while cursor in by_previous:
        entry = by_previous[cursor]
        walk.append(entry)
        cursor = entry.entry_hash
    assert len(walk) == count, "the chain did not form one unbroken run"
    assert ordered[0].previous_hash == GENESIS_HASH

    anchor = chain.anchor()
    verdict = verify_chain(
        walk, KEYS, expected_last_hash=anchor.head, expected_length=anchor.length
    )
    assert verdict.ok, verdict.summary()


def test_the_anchor_tracks_the_head_and_length() -> None:
    chain, entries = build(3)
    assert chain.anchor() == Anchor(head=entries[2].entry_hash, length=3, key_id=TEST_KEY_ID)
