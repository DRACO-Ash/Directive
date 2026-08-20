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


@pytest.mark.parametrize("field", validation.REQUIRED_FIELDS)
def test_a_missing_required_field_is_rejected(field: str) -> None:
    fields = fixed_entry()
    del fields[field]
    with pytest.raises(validation.AuditFieldError, match=field):
        validation.normalise_fields(fields)


@pytest.mark.parametrize(
    "field",
    sorted(set(validation.FIELD_LIMITS) - set(validation.REQUIRED_FIELDS)),
)
def test_a_per_category_field_may_be_absent_or_empty(field: str) -> None:
    """An authentication event has no fields_changed; a task completion has no user agent.

    Absent and empty must both normalise to empty, so the digest covers a fixed shape
    whatever the event category.
    """
    without = fixed_entry()
    del without[field]
    assert validation.normalise_fields(without)[field] == ""
    assert validation.normalise_fields(fixed_entry(**{field: ""}))[field] == ""


@pytest.mark.parametrize("blank", ["", "   ", "\t"])
def test_a_blank_required_field_is_rejected(blank: str) -> None:
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


@pytest.mark.parametrize("outcome", ["SUCCESS", "FAILURE"])
def test_an_authentication_outcome_is_accepted(outcome: str) -> None:
    """AUD-001 requires success or failure on an authentication event."""
    assert validation.normalise_fields(fixed_entry(outcome=outcome))["outcome"] == outcome


@pytest.mark.parametrize("outcome", ["success", "PARTIAL", "OK", "SUCCESS "])
def test_an_outcome_outside_the_closed_set_is_rejected(outcome: str) -> None:
    """A closed set, so the column cannot drift into free text."""
    with pytest.raises(validation.AuditFieldError, match="outcome"):
        validation.normalise_fields(fixed_entry(outcome=outcome))


@pytest.mark.parametrize("state", ["OPEN", "IN_PROGRESS", "PHASE_3", "A", "S" * 32])
def test_an_enumerated_workflow_state_is_accepted(state: str) -> None:
    """A task status and an incident phase are exactly what AUD-001 wants recorded."""
    fields = validation.normalise_fields(fixed_entry(old_state="OPEN", new_state=state))
    assert fields["new_state"] == state


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("an email address", "ash.higgins@bluestaq.uk"),
        ("a person's name", "Ash Higgins"),
        ("a postal address", "1 Example Street"),
        ("lower case free text", "reporter was jane"),
        ("a short sentence", "REPORTER CHANGED"),
    ],
)
def test_a_state_field_structurally_cannot_carry_record_content(label: str, value: str) -> None:
    """The pattern is the data-minimisation control, not a convention.

    AUD-001 asks for the old and new value of a changed field. For a status that is
    right; for an incident's content it would put personal data into a log that is
    immutable by design, which no correction and no Article 17 erasure can reach. A field
    that cannot hold a name, an address, an email or a sentence cannot carry that content
    by accident, whatever a future caller intends.
    """
    with pytest.raises(validation.AuditFieldError, match="cannot carry record content"):
        validation.normalise_fields(fixed_entry(new_state=value))
    assert label


@pytest.mark.parametrize("value", ["REPORTER CHANGED TO A NAMED INDIVIDUAL", "S" * 33])
def test_a_state_field_longer_than_a_state_is_rejected_by_the_cap(value: str) -> None:
    """Anything long enough to be a sentence is refused before the pattern is reached.

    Two independent rules, so a value that slipped past the character set would still
    have to fit in 32 bytes.
    """
    with pytest.raises(validation.AuditFieldError, match="over its cap"):
        validation.normalise_fields(fixed_entry(new_state=value))


@pytest.mark.parametrize(
    "names",
    ["status", "status,phase", "incident.reporter", "a.b.c,d_e,f", "old_status,new_status"],
)
def test_a_list_of_changed_field_names_is_accepted(names: str) -> None:
    assert validation.normalise_fields(fixed_entry(fields_changed=names))["fields_changed"] == names


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("a value rather than a name", "reporter=Ash Higgins"),
        ("an email address", "ash.higgins@bluestaq.uk"),
        ("upper case", "STATUS"),
        ("a space", "status, phase"),
        ("a trailing comma", "status,"),
        ("free text", "the reporter field changed"),
    ],
)
def test_fields_changed_takes_names_only(label: str, value: str) -> None:
    """A value here would put record content into an immutable log."""
    with pytest.raises(validation.AuditFieldError, match=r"Names\s+only"):
        validation.normalise_fields(fixed_entry(fields_changed=value))
    assert label


def test_an_authentication_event_carries_the_full_aud_001_shape() -> None:
    """The one worked example from the AUD-001 Authentication row, end to end."""
    fields = validation.normalise_fields(
        fixed_entry(
            action="LOGIN",
            resource="session",
            resource_id="sess-01",
            outcome="FAILURE",
            source_ip="203.0.113.42",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        )
    )
    assert fields["outcome"] == "FAILURE"
    assert fields["source_ip"] == "203.0.113.42"
    assert fields["fields_changed"] == ""


def test_an_ipv6_address_fits_the_source_address_cap() -> None:
    """45 characters is the longest IPv6 form, so the cap must not reject a real address."""
    longest = "1234:1234:1234:1234:1234:1234:255.255.255.255"
    assert len(longest) == validation.FIELD_LIMITS["source_ip"]
    assert validation.normalise_fields(fixed_entry(source_ip=longest))["source_ip"] == longest
