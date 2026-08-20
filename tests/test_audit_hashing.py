"""Hashing tests: determinism, fail-closed fields, and the field-absorption attack."""

from __future__ import annotations

import hashlib

import pytest

from complyops.audit import hashing
from conftest import fixed_entry


def test_genesis_hash_is_a_full_length_digest_of_zeroes() -> None:
    assert hashing.GENESIS_HASH == "0" * hashing.HASH_LENGTH
    assert hashing.is_hash(hashing.GENESIS_HASH)


def test_entry_hash_is_deterministic_and_full_length() -> None:
    first = hashing.entry_hash(hashing.GENESIS_HASH, fixed_entry())
    second = hashing.entry_hash(hashing.GENESIS_HASH, fixed_entry())
    assert first == second
    assert len(first) == hashing.HASH_LENGTH
    assert hashing.is_hash(first)


def test_entry_hash_covers_the_previous_hash() -> None:
    """A different predecessor must produce a different digest, or the chain is fiction."""
    from_genesis = hashing.entry_hash(hashing.GENESIS_HASH, fixed_entry())
    from_other = hashing.entry_hash("a" * 64, fixed_entry())
    assert from_genesis != from_other


@pytest.mark.parametrize("field", hashing.FIELD_ORDER)
def test_changing_any_covered_field_changes_the_hash(field: str) -> None:
    baseline = hashing.entry_hash(hashing.GENESIS_HASH, fixed_entry())
    altered = fixed_entry()
    altered[field] = altered[field] + "x"
    assert hashing.entry_hash(hashing.GENESIS_HASH, altered) != baseline


def test_length_prefixing_defeats_field_absorption() -> None:
    """Two records that a delimiter scheme would conflate must not share a payload.

    With a pipe delimiter, actor "a|b" with action "c" and actor "a" with action "b|c"
    serialise identically. Length prefixes make the boundary unambiguous.
    """
    left = fixed_entry()
    right = fixed_entry()
    left["actor"], left["action"] = "a|b", "c"
    right["actor"], right["action"] = "a", "b|c"
    assert hashing.canonical_payload(left) != hashing.canonical_payload(right)
    assert hashing.entry_hash(hashing.GENESIS_HASH, left) != hashing.entry_hash(
        hashing.GENESIS_HASH, right
    )


def test_canonical_payload_is_length_prefixed_utf8() -> None:
    fields = dict.fromkeys(hashing.FIELD_ORDER, "a")
    assert hashing.canonical_payload(fields) == b"1:a" * len(hashing.FIELD_ORDER)


def test_canonical_payload_counts_bytes_not_characters() -> None:
    """Prefix by byte length, not character count.

    A multi-byte character prefixed by its character count would let two different
    values share a payload.
    """
    fields = dict.fromkeys(hashing.FIELD_ORDER, "a")
    fields["actor"] = "é"
    assert b"2:\xc3\xa9" in hashing.canonical_payload(fields)


@pytest.mark.parametrize("field", hashing.FIELD_ORDER)
def test_a_missing_field_fails_closed(field: str) -> None:
    fields = fixed_entry()
    del fields[field]
    with pytest.raises(hashing.AuditHashError, match=field):
        hashing.entry_hash(hashing.GENESIS_HASH, fields)


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
def test_a_blank_field_fails_closed(blank: str) -> None:
    fields = fixed_entry()
    fields["actor"] = blank
    with pytest.raises(hashing.AuditHashError, match="must not be blank"):
        hashing.entry_hash(hashing.GENESIS_HASH, fields)


def test_a_non_string_field_fails_closed() -> None:
    fields: dict[str, object] = dict(fixed_entry())
    fields["resource_id"] = 7
    with pytest.raises(hashing.AuditHashError, match="must be a string"):
        hashing.entry_hash(hashing.GENESIS_HASH, fields)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "bad_previous",
    [
        "",
        "0" * 63,
        "0" * 65,
        "0" * 63 + "G",
        "A" * 64,
        None,
    ],
)
def test_a_previous_hash_that_is_not_a_digest_fails_closed(bad_previous: object) -> None:
    with pytest.raises(hashing.AuditHashError, match="previous hash"):
        hashing.entry_hash(bad_previous, fixed_entry())  # type: ignore[arg-type]


def test_is_hash_rejects_uppercase_and_short_values() -> None:
    assert not hashing.is_hash("A" * 64)
    assert not hashing.is_hash("f" * 63)
    assert hashing.is_hash("f" * 64)


def test_the_digest_is_sha256_over_the_documented_input() -> None:
    """Pin the construction, so a silent change of algorithm or input order fails."""
    fields = fixed_entry()
    expected = hashlib.sha256(
        hashing.GENESIS_HASH.encode("ascii") + hashing.canonical_payload(fields)
    ).hexdigest()
    assert hashing.entry_hash(hashing.GENESIS_HASH, fields) == expected
