"""Chain tests: append, verify, and every way the log can be tampered with."""

from __future__ import annotations

import dataclasses
import sys
import threading

import pytest

from complyops.audit import GENESIS_HASH, Anchor, AuditChain, verify_log, verify_sample
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
        AuditChain(key=TEST_KEY, key_id="=cmd|' /c calc'!A1")


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

    forged_chain = AuditChain(key=retired_key, key_id=retired_id)
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
    count = 64

    def worker(index: int) -> None:
        entry = chain.append(fixed_entry(index % 60))
        with collect_lock:
            collected.append(entry)

    previous_interval = sys.getswitchinterval()
    sys.setswitchinterval(1e-9)
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


def test_an_entry_that_cannot_be_re_hashed_reports_a_break_rather_than_raising() -> None:
    """An empty covered field passes the shape checks and then defeats the hasher."""
    chain, entries = build(1)
    entries[0] = dataclasses.replace(entries[0], actor="")
    verdict = verify_log(entries, KEYS, chain.anchor())
    assert not verdict.ok
    assert "could not be re-hashed" in (verdict.reason or "")
