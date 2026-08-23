"""Hashing tests: the pinned construction, keying, and field absorption."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest

from complyops.audit import hashing
from conftest import TEST_KEY, TEST_KEY_ID, fixed_entry


def digest(fields: dict[str, str] | None = None, previous: str | None = None) -> str:
    """Hash one entry with the suite's key."""
    return hashing.entry_hash(
        previous or hashing.GENESIS_HASH,
        fields or fixed_entry(),
        key=TEST_KEY,
        key_id=TEST_KEY_ID,
    )


def test_the_construction_is_pinned_by_a_golden_vector() -> None:
    """Pin the whole construction with one known answer.

    Derived independently of the module under test, so it fails if the field set, the
    field ORDER, the digest algorithm, the length prefix, the separator, the key
    binding, or the chaining changes. Each of those is the irreversible change that
    breaks every historical entry, and a test that derives its expectation from the
    code it checks cannot see any of them.
    """
    assert hashing.FIELD_ORDER == (
        "timestamp",
        "actor",
        "action",
        "resource",
        "resource_id",
        "outcome",
        "source_ip",
        "user_agent",
        "fields_changed",
        "old_state",
        "new_state",
    )
    # An empty optional field is `0:`, which is what makes a fixed field set safe: the
    # payload cannot shift when a field does not apply to an event.
    payload = (
        b"20:2026-08-20T09:01:00Z"
        b"23:ash.higgins@bluestaq.uk"
        b"13:TASK_COMPLETE"
        b"9:lst-Tasks"
        b"4:D-01"
        b"0:"
        b"0:"
        b"0:"
        b"0:"
        b"0:"
        b"0:"
        b"7:test-k1"
    )
    expected = hmac.new(
        TEST_KEY, hashing.GENESIS_HASH.encode("ascii") + payload, hashlib.sha256
    ).hexdigest()
    assert digest() == expected
    assert hashing.canonical_payload(fixed_entry(), TEST_KEY_ID) == payload


def test_the_digest_is_keyed_so_edit_rights_alone_cannot_re_stamp() -> None:
    """A different key must produce a different digest, or keying is decoration."""
    other = hashing.entry_hash(
        hashing.GENESIS_HASH,
        fixed_entry(),
        key=bytes(range(100, 132)),
        key_id=TEST_KEY_ID,
    )
    assert other != digest()


def test_the_key_identifier_is_covered_so_it_cannot_be_swapped() -> None:
    assert digest() != hashing.entry_hash(
        hashing.GENESIS_HASH, fixed_entry(), key=TEST_KEY, key_id="k-other"
    )


def test_an_unkeyed_digest_is_refused() -> None:
    with pytest.raises(hashing.AuditHashError, match="no signing key"):
        hashing.entry_hash(hashing.GENESIS_HASH, fixed_entry(), key=b"", key_id=TEST_KEY_ID)


def test_genesis_hash_is_a_full_length_digest_of_zeroes() -> None:
    assert hashing.GENESIS_HASH == "0" * hashing.HASH_LENGTH
    assert hashing.is_hash(hashing.GENESIS_HASH)


def test_entry_hash_is_deterministic_and_full_length() -> None:
    assert digest() == digest()
    assert len(digest()) == hashing.HASH_LENGTH
    assert hashing.is_hash(digest())


def test_entry_hash_covers_the_previous_hash() -> None:
    assert digest() != digest(previous="a" * 64)


@pytest.mark.parametrize("field", hashing.FIELD_ORDER)
def test_changing_any_covered_field_changes_the_hash(field: str) -> None:
    altered = fixed_entry()
    altered[field] = "2026-08-20T09:02:00Z" if field == "timestamp" else altered[field] + "x"
    assert digest(altered) != digest()


def test_length_prefixing_defeats_field_absorption() -> None:
    """Two records a delimiter scheme would conflate must not share a payload.

    With a pipe delimiter, actor "a|b" with action "C" and actor "a" with action "B|C"
    serialise identically. Length prefixes make the boundary unambiguous.
    """
    left, right = fixed_entry(), fixed_entry()
    left["actor"], left["action"] = "a|b", "C"
    right["actor"], right["action"] = "a", "B|C"
    assert hashing.canonical_payload(left, TEST_KEY_ID) != hashing.canonical_payload(
        right, TEST_KEY_ID
    )
    assert digest(left) != digest(right)


def test_canonical_payload_counts_bytes_not_characters() -> None:
    """Prefix by byte length, not character count.

    A multi-byte character prefixed by its character count would let two different
    values share a payload.
    """
    fields = fixed_entry()
    fields["actor"] = "é"
    assert b"2:\xc3\xa9" in hashing.canonical_payload(fields, TEST_KEY_ID)


@pytest.mark.parametrize("field", hashing.FIELD_ORDER)
def test_a_missing_field_fails_closed(field: str) -> None:
    fields = fixed_entry()
    del fields[field]
    with pytest.raises(hashing.AuditHashError, match=field):
        digest(fields)


@pytest.mark.parametrize(
    "bad_previous", ["", "0" * 63, "0" * 65, "0" * 63 + "G", "A" * 64, None, 7]
)
def test_a_previous_hash_that_is_not_a_digest_fails_closed(bad_previous: object) -> None:
    with pytest.raises(hashing.AuditHashError, match="previous hash"):
        hashing.entry_hash(bad_previous, fixed_entry(), key=TEST_KEY, key_id=TEST_KEY_ID)


def test_is_hash_rejects_uppercase_short_and_non_string_values() -> None:
    assert not hashing.is_hash("A" * 64)
    assert not hashing.is_hash("f" * 63)
    assert not hashing.is_hash(None)
    assert hashing.is_hash("f" * 64)


def test_hashes_are_compared_in_constant_time() -> None:
    assert hashing.hashes_equal("f" * 64, "f" * 64)
    assert not hashing.hashes_equal("f" * 64, "e" * 64)


@pytest.mark.parametrize("hostile", [None, 7, b"bytes", ["a"], {"a": 1}])
def test_a_non_string_field_value_fails_closed_in_the_hasher(hostile: object) -> None:
    """Type is the one rule the hash path still enforces, and it must stay.

    The required-field rule was deliberately removed from here, because enforcing today's
    rules inside the digest made tightened history read as tampering. Type is different: a
    non-string cannot be length-prefixed at all, so hashing a guess is the only alternative.
    """
    fields = dict(fixed_entry())
    fields["user_agent"] = hostile  # type: ignore[assignment]
    with pytest.raises(hashing.AuditHashError, match="missing the 'user_agent' field"):
        hashing.canonical_payload(fields, TEST_KEY_ID)  # type: ignore[arg-type]


def test_the_key_identifier_must_be_a_string_too() -> None:
    with pytest.raises(hashing.AuditHashError, match="missing the 'key_id' field"):
        hashing.canonical_payload(fixed_entry(), None)  # type: ignore[arg-type]


def test_the_anchor_authentication_tag_is_pinned_by_a_golden_vector() -> None:
    """The anchor's signed form needs the same protection as the entry digest.

    Nothing pinned it: removing `sort_keys=True` from the MAC message left the whole suite
    green. Reordering the signed document in a later slice would then make every stored
    anchor read as "not authenticated", which is a tamper accusation over clean evidence,
    the one failure this module must never produce. Changing the construction below is the
    same irreversible decision as changing FIELD_ORDER and needs the same sign-off.
    """
    from complyops.audit import Anchor  # noqa: PLC0415

    anchor = Anchor(
        head="a" * 64, length=3, key_id=TEST_KEY_ID, total_length=12, pruned_head="c" * 64
    )
    message = (
        b'{"head": "' + b"a" * 64 + b'", "keyId": "test-k1", "length": 3, '
        b'"prunedHead": "' + b"c" * 64 + b'", "schemaVersion": 2, "totalLength": 12}'
    )
    expected = hmac.new(TEST_KEY, message, hashlib.sha256).hexdigest()
    assert anchor.mac(TEST_KEY) == expected, "the anchor's signed form changed"

    # And the stored document is exactly that message plus the tag.
    stored = json.loads(anchor.as_json(TEST_KEY))
    assert stored.pop("mac") == expected
    assert json.dumps(stored, sort_keys=True).encode("utf-8") == message


def test_hashes_are_compared_in_constant_time_by_construction() -> None:
    """A mutation showed `==` passed all 467 tests, so the property needs asserting.

    Timing cannot be measured reliably in a test, so this asserts the implementation
    instead: the comparison must go through `hmac.compare_digest`. The digests are public,
    so nothing secret leaks by timing today, but the control is load-bearing the moment a
    verification endpoint exists and the suite could not defend it.
    """
    calls: list[tuple[str, str]] = []
    real = hmac.compare_digest

    def watching(left: object, right: object) -> bool:
        calls.append((str(left), str(right)))
        return real(left, right)  # type: ignore[arg-type]

    hashing.hmac.compare_digest = watching  # type: ignore[attr-defined]
    try:
        assert hashing.hashes_equal("a" * 64, "a" * 64) is True
        assert hashing.hashes_equal("a" * 64, "b" * 64) is False
    finally:
        hashing.hmac.compare_digest = real  # type: ignore[attr-defined]

    assert len(calls) == 2, "hashes_equal must compare through hmac.compare_digest"
