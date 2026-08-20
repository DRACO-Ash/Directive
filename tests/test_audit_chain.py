"""Chain tests: append, verify, and every way the log can be tampered with."""

from __future__ import annotations

import dataclasses

import pytest

from complyops.audit import GENESIS_HASH, AuditChain, verify_chain
from complyops.audit.hashing import AuditHashError, entry_hash
from conftest import fixed_entry


def build_chain(count: int) -> AuditChain:
    """Append ``count`` deterministic entries and return the chain."""
    chain = AuditChain()
    for index in range(1, count + 1):
        chain.append(fixed_entry(index))
    return chain


def test_the_first_entry_chains_to_the_genesis_hash() -> None:
    chain = AuditChain()
    entry = chain.append(fixed_entry())
    assert entry.previous_hash == GENESIS_HASH
    assert chain.head == entry.entry_hash
    assert chain.length == 1


def test_each_entry_chains_to_its_predecessor() -> None:
    chain = build_chain(3)
    entries = chain.entries()
    assert entries[1].previous_hash == entries[0].entry_hash
    assert entries[2].previous_hash == entries[1].entry_hash


def test_an_intact_chain_verifies() -> None:
    verdict = verify_chain(build_chain(4).entries())
    assert verdict.ok
    assert verdict.checked == 4
    assert verdict.break_index is None
    assert "intact across 4" in verdict.summary()


def test_an_empty_run_verifies_over_zero_entries() -> None:
    verdict = verify_chain([])
    assert verdict.ok
    assert verdict.checked == 0


@pytest.mark.parametrize("field", ["timestamp", "actor", "action", "resource", "resource_id"])
def test_editing_any_field_breaks_the_chain(field: str) -> None:
    entries = list(build_chain(3).entries())
    entries[1] = dataclasses.replace(entries[1], **{field: "tampered"})
    verdict = verify_chain(entries)
    assert not verdict.ok
    assert verdict.break_index == 1
    assert "does not match the stored hash" in (verdict.reason or "")


def test_deleting_an_entry_breaks_the_chain() -> None:
    entries = list(build_chain(3).entries())
    del entries[1]
    verdict = verify_chain(entries)
    assert not verdict.ok
    assert verdict.break_index == 1
    assert "edited, reordered, or removed" in (verdict.reason or "")


def test_reordering_entries_breaks_the_chain() -> None:
    entries = list(build_chain(3).entries())
    entries[1], entries[2] = entries[2], entries[1]
    verdict = verify_chain(entries)
    assert not verdict.ok
    assert verdict.break_index == 1


def test_appending_a_forged_entry_after_an_edit_still_breaks() -> None:
    """Re-stamping an edited row is the attack a per-row hash cannot see."""
    entries = list(build_chain(3).entries())
    forged = dataclasses.replace(entries[1], actor="someone.else@example.invalid")
    forged = dataclasses.replace(
        forged, entry_hash=entry_hash(forged.previous_hash, forged.covered_fields())
    )
    entries[1] = forged
    verdict = verify_chain(entries)
    assert not verdict.ok, "a re-stamped edit must still break the following entry"
    assert verdict.break_index == 2


def test_verification_reports_the_first_break_only() -> None:
    entries = list(build_chain(5).entries())
    entries[1] = dataclasses.replace(entries[1], actor="tampered")
    entries[3] = dataclasses.replace(entries[3], actor="tampered too")
    verdict = verify_chain(entries)
    assert verdict.break_index == 1
    assert verdict.checked == 1


def test_a_sample_from_the_middle_verifies_against_its_starting_hash() -> None:
    entries = build_chain(4).entries()
    verdict = verify_chain(entries[2:], expected_first_previous_hash=entries[1].entry_hash)
    assert verdict.ok
    assert verdict.checked == 2


def test_a_sample_verified_against_the_wrong_starting_hash_fails_closed() -> None:
    entries = build_chain(4).entries()
    verdict = verify_chain(entries[2:])
    assert not verdict.ok
    assert verdict.break_index == 0


def test_a_starting_hash_that_is_not_a_digest_fails_closed() -> None:
    verdict = verify_chain(build_chain(1).entries(), expected_first_previous_hash="nope")
    assert not verdict.ok
    assert verdict.checked == 0
    assert "not a SHA-256 digest" in (verdict.reason or "")


def test_an_unhashable_entry_fails_closed_rather_than_raising() -> None:
    entries = list(build_chain(1).entries())
    entries[0] = dataclasses.replace(entries[0], actor="   ")
    verdict = verify_chain(entries)
    assert not verdict.ok
    assert "could not be re-hashed" in (verdict.reason or "")


def test_a_rejected_append_leaves_the_head_untouched() -> None:
    chain = build_chain(1)
    head_before, length_before = chain.head, chain.length
    bad = fixed_entry()
    del bad["actor"]
    with pytest.raises(AuditHashError):
        chain.append(bad)
    assert chain.head == head_before
    assert chain.length == length_before
    assert len(chain.entries()) == length_before


def test_the_broken_entry_hash_is_reported_for_the_operator() -> None:
    entries = list(build_chain(2).entries())
    entries[0] = dataclasses.replace(entries[0], action="tampered")
    verdict = verify_chain(entries)
    assert verdict.broken_entry_hash == entries[0].entry_hash
    assert "chain broken at index 0" in verdict.summary()
