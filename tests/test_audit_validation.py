"""Validation tests: the caps and character rules that must exist before entry one."""

from __future__ import annotations

import pytest

from complyops.audit import validation
from conftest import fixed_entry


def test_a_clean_entry_passes_and_is_returned_as_a_snapshot() -> None:
    snapshot = validation.normalise_fields(fixed_entry())
    assert snapshot == fixed_entry()


def test_the_snapshot_is_independent_of_the_caller_mapping() -> None:
    """Read each field exactly once.

    Hashing one read and storing a second lets a mapping whose values change between
    reads produce a stored row that can never verify.
    """
    reads: list[str] = []

    class Shifting(dict):
        def __getitem__(self, key: str) -> str:
            if key == "actor":
                reads.append(key)
                return f"actor-{len(reads)}@bluestaq.uk"
            return super().__getitem__(key)

    shifting = Shifting(fixed_entry())
    snapshot = validation.normalise_fields(shifting)
    assert snapshot["actor"] == "actor-1@bluestaq.uk"
    assert len(reads) == 1


@pytest.mark.parametrize("field", sorted(validation.FIELD_LIMITS))
def test_a_missing_field_is_rejected(field: str) -> None:
    fields = fixed_entry()
    del fields[field]
    with pytest.raises(validation.AuditFieldError, match=field):
        validation.normalise_fields(fields)


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_a_blank_field_is_rejected(blank: str) -> None:
    fields = fixed_entry()
    fields["resource"] = blank
    with pytest.raises(validation.AuditFieldError):
        validation.normalise_fields(fields)


def test_a_non_string_field_is_rejected() -> None:
    fields: dict[str, object] = dict(fixed_entry())
    fields["resource_id"] = 7
    with pytest.raises(validation.AuditFieldError, match="must be a string"):
        validation.normalise_fields(fields)


@pytest.mark.parametrize("field", ["actor", "resource", "resource_id"])
def test_the_cap_is_enforced_at_the_boundary_in_both_directions(field: str) -> None:
    """A cap of N must accept N and reject N plus one, or it asserts nothing."""
    limit = validation.FIELD_LIMITS[field]
    at_limit = fixed_entry()
    at_limit[field] = "a" * limit
    assert validation.normalise_fields(at_limit)[field] == "a" * limit

    over = fixed_entry()
    over[field] = "a" * (limit + 1)
    with pytest.raises(validation.AuditFieldError, match="over its cap"):
        validation.normalise_fields(over)


def test_the_cap_is_measured_in_bytes() -> None:
    """The cap is a byte cap, checked before the character rule."""
    fields = fixed_entry()
    fields["actor"] = "é" * validation.FIELD_LIMITS["actor"]
    with pytest.raises(validation.AuditFieldError, match="over its cap"):
        validation.normalise_fields(fields)


@pytest.mark.parametrize(
    "hostile",
    [" =cmd|' /c calc'!A1", "\u00a0=cmd", "=cmd ", " D-01", "D-01 ", "\t D-01"],
)
def test_leading_or_trailing_whitespace_is_rejected(hostile: str) -> None:
    """A leading space lets a formula character hide from the export guard."""
    fields = fixed_entry()
    fields["resource_id"] = hostile
    with pytest.raises(validation.AuditFieldError):
        validation.normalise_fields(fields)


@pytest.mark.parametrize("hostile", ["=cmd|' /c calc'!A1", "+1", "-1+2", "@SUM(A1)"])
def test_a_leading_formula_character_is_rejected_however_it_is_spelled(hostile: str) -> None:
    fields = fixed_entry()
    fields["resource_id"] = hostile
    with pytest.raises(validation.AuditFieldError):
        validation.normalise_fields(fields)


@pytest.mark.parametrize("hostile", ["=cmd", "k 1", "k:1", "k" * 33, "kéy"])
def test_a_hostile_key_identifier_is_rejected(hostile: str) -> None:
    """The identifier reaches the digest and every stored row without the field rules."""
    with pytest.raises(validation.AuditFieldError, match="signing key identifier"):
        validation.check_key_id(hostile)


@pytest.mark.parametrize("good", ["k1", "test-k1", "K_9", "k" * 32])
def test_a_conforming_key_identifier_is_accepted(good: str) -> None:
    assert validation.check_key_id(good) == good


def test_the_field_list_and_the_digest_field_order_agree() -> None:
    """Two lists that must not drift: one is validated, the other is hashed."""
    from complyops.audit.hashing import FIELD_ORDER  # noqa: PLC0415 - for this assertion

    assert tuple(validation.FIELD_LIMITS) == FIELD_ORDER


@pytest.mark.parametrize(
    ("label", "hostile"),
    [
        ("newline", "ash\n2026-08-20 CRITICAL chain verified intact by admin"),
        ("carriage return", "ash\rlevel=INFO"),
        ("escape sequence", "ash\x1b[2Kadmin"),
        ("null", "ash\x00admin"),
        ("delete", "ash\x7fadmin"),
        # Categories Zl and Zp. A denylist on category Cc missed both, and each terminates
        # a line for str.splitlines and for most log and comma-separated-value consumers,
        # so an actor could forge "CRITICAL chain verified intact by admin".
        ("line separator", "ash\u2028CRITICAL chain verified intact"),
        ("paragraph separator", "ash\u2029CRITICAL chain verified intact"),
        # Category Cf. Each misrepresents the recorded actor without changing what a
        # reader sees.
        ("zero width space", "ash\u200badmin"),
        ("soft hyphen", "ash\u00adadmin"),
        ("word joiner", "ash\u2060admin"),
        ("byte order mark", "ash\ufeffadmin"),
        # Bidirectional overrides, which reverse how the actor renders.
        ("right to left override", "ash\u202eadmin"),
        ("left to right override", "ash\u202dadmin"),
        ("isolate", "ash\u2066admin"),
        ("right to left mark", "ash\u200fadmin"),
        # A homoglyph, which no Unicode category can exclude: the first character is
        # Cyrillic small a, not Latin.
        ("cyrillic homoglyph", "\u0430sh@bluestaq.uk"),
    ],
)
def test_anything_outside_printable_ascii_is_rejected(label: str, hostile: str) -> None:
    """An allowlist, because a denylist over Unicode leaked twice in one review."""
    fields = fixed_entry()
    fields["actor"] = hostile
    with pytest.raises(validation.AuditFieldError, match="outside printable ASCII"):
        validation.normalise_fields(fields)
    assert label


@pytest.mark.parametrize("lead", ["=", "+", "-", "@"])
def test_a_leading_formula_character_is_rejected_for_the_evidence_export(lead: str) -> None:
    """An evidence pack is exported to a spreadsheet, which executes a leading formula."""
    fields = fixed_entry()
    fields["resource_id"] = f"{lead}cmd|' /c calc'!A1"
    with pytest.raises(validation.AuditFieldError, match="formula"):
        validation.normalise_fields(fields)


@pytest.mark.parametrize(
    "bad_timestamp",
    [
        "not a timestamp at all",
        "2026-08-20 09:01:00",
        "2026-08-20T09:01:00",
        "2026-08-20T09:01:00+01:00",
        "20260820T090100Z",
        "2026-13-40T09:01:00Z",
    ],
)
def test_a_timestamp_that_is_not_rfc_3339_utc_is_rejected(bad_timestamp: str) -> None:
    """Chain order and claimed time must not be able to diverge in evidence."""
    fields = fixed_entry()
    fields["timestamp"] = bad_timestamp
    with pytest.raises(validation.AuditFieldError, match="RFC 3339"):
        validation.normalise_fields(fields)


@pytest.mark.parametrize("good", ["2026-08-20T09:01:00Z", "2026-08-20T09:01:00.123456Z"])
def test_a_valid_utc_timestamp_is_accepted(good: str) -> None:
    fields = fixed_entry()
    fields["timestamp"] = good
    assert validation.normalise_fields(fields)["timestamp"] == good


@pytest.mark.parametrize(
    "bad_action", ["task complete", "TaskComplete", "task_complete", "T", "1TASK"]
)
def test_an_action_outside_the_naming_shape_is_rejected(bad_action: str) -> None:
    fields = fixed_entry()
    fields["action"] = bad_action
    with pytest.raises(validation.AuditFieldError, match="upper snake case"):
        validation.normalise_fields(fields)


@pytest.mark.parametrize("good", ["TASK_COMPLETE", "INCIDENT_CREATED", "DSAR_LOGGED", "AB"])
def test_a_conforming_action_is_accepted(good: str) -> None:
    fields = fixed_entry()
    fields["action"] = good
    assert validation.normalise_fields(fields)["action"] == good
