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


def test_a_multi_byte_field_is_capped_by_bytes_not_characters() -> None:
    fields = fixed_entry()
    fields["actor"] = "é" * validation.FIELD_LIMITS["actor"]
    with pytest.raises(validation.AuditFieldError, match="over its cap"):
        validation.normalise_fields(fields)


@pytest.mark.parametrize(
    "hostile",
    [
        "ash\n2026-08-20 CRITICAL chain verified intact by admin",
        "ash\rlevel=INFO",
        "ash\x1b[2Kadmin",
        "ash\x00admin",
        "ash\x7fadmin",
    ],
)
def test_a_control_character_is_rejected_because_it_forges_a_log_line(hostile: str) -> None:
    fields = fixed_entry()
    fields["actor"] = hostile
    with pytest.raises(validation.AuditFieldError, match="control character"):
        validation.normalise_fields(fields)


@pytest.mark.parametrize("override", ["\u202e", "\u202d", "\u2066", "\u200f"])
def test_a_bidirectional_override_is_rejected(override: str) -> None:
    fields = fixed_entry()
    fields["actor"] = f"ash{override}admin"
    with pytest.raises(validation.AuditFieldError, match="bidirectional"):
        validation.normalise_fields(fields)


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
