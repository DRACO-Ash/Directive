"""Boundary validation for audit fields, applied before anything is hashed.

Caps and character rules belong here, at the append boundary, and not on read. An
audit entry is immutable and chained, so an over-collected or malformed field cannot
later be corrected or erased without breaking every hash after it. That makes the
boundary the only place a limit can be added, and it makes adding one after the first
entry is written the same irreversible change as altering the hash construction.

Four classes are rejected rather than escaped, because an audit entry is evidence and
evidence should be refused rather than quietly rewritten:

* control characters, which forge a line in the structured audit log;
* bidirectional overrides, which make a recorded actor render as somebody else;
* a leading formula character, because an assessor evidence pack is exported to a
  spreadsheet and a leading equals sign is then executed;
* anything over its byte cap, so one entry cannot grow the log without bound.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Mapping
from datetime import datetime

#: Byte caps per field. Generous enough for a real user principal name and a real list
#: item reference, small enough that no single entry can dominate the log.
FIELD_LIMITS: dict[str, int] = {
    "timestamp": 32,
    "actor": 320,
    "action": 64,
    "resource": 128,
    "resource_id": 128,
}

#: Bidirectional formatting characters. Permitted nowhere: they change how a recorded
#: actor renders without changing what was recorded.
_BIDI_CHARACTERS = frozenset("\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")

#: A leading character a spreadsheet treats as the start of a formula.
_FORMULA_LEAD = frozenset("=+-@\t\r")

#: RFC 3339 in UTC, which is the only timestamp form accepted. A local offset would let
#: two entries claim an order the chain contradicts.
_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z\Z")

#: An action name. Upper snake case, so the vocabulary stays a closed, greppable set.
#: The full vocabulary is not yet defined; this constrains the shape, not the list.
#: TBC, re-verify the action vocabulary against AUD-001.
_ACTION = re.compile(r"\A[A-Z][A-Z0-9_]{1,63}\Z")


class AuditFieldError(ValueError):
    """Raised when a field is not fit to be recorded. Always reject, never coerce."""


def _reject_characters(name: str, value: str) -> None:
    """Reject control characters and bidirectional overrides in ``value``."""
    for character in value:
        if unicodedata.category(character) == "Cc":
            raise AuditFieldError(
                f"audit field {name!r} contains a control character, "
                f"which would forge a line in the audit log"
            )
        if character in _BIDI_CHARACTERS:
            raise AuditFieldError(
                f"audit field {name!r} contains a bidirectional override, "
                f"which would misrepresent the recorded value"
            )


def _check_one(name: str, value: object) -> str:
    """Validate one field and return it, or raise :class:`AuditFieldError`."""
    if not isinstance(value, str):
        raise AuditFieldError(f"audit field {name!r} must be a string, got {type(value).__name__}")
    if not value.strip():
        raise AuditFieldError(f"audit field {name!r} must not be blank")

    limit = FIELD_LIMITS[name]
    encoded = len(value.encode("utf-8"))
    if encoded > limit:
        raise AuditFieldError(f"audit field {name!r} is {encoded} bytes, over its cap of {limit}")

    _reject_characters(name, value)

    if value[0] in _FORMULA_LEAD:
        raise AuditFieldError(
            f"audit field {name!r} starts with {value[0]!r}, which a spreadsheet "
            f"treats as a formula when the evidence pack is exported"
        )
    return value


def _check_timestamp(value: str) -> None:
    """Reject a timestamp that is not RFC 3339 in UTC, and not a real date.

    The shape and the calendar are separate checks: a pattern alone accepts month 13
    and day 40, which would let an entry claim a date that does not exist.
    """
    invalid = AuditFieldError(
        f"audit timestamp must be RFC 3339 in UTC, for example 2026-08-20T09:01:00Z, got {value!r}"
    )
    if not _TIMESTAMP.match(value):
        raise invalid
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise invalid from error


def normalise_fields(fields: Mapping[str, object]) -> dict[str, str]:
    """Validate every covered field and return an independent snapshot.

    The snapshot matters as much as the validation. Hashing one read of a mapping and
    then storing a second read allows a mapping whose values change between reads to
    produce a stored row that can never verify, so the fields are read exactly once.
    """
    snapshot: dict[str, str] = {}
    for name in FIELD_LIMITS:
        if name not in fields:
            raise AuditFieldError(f"audit entry is missing the {name!r} field")
        snapshot[name] = _check_one(name, fields[name])

    _check_timestamp(snapshot["timestamp"])
    if not _ACTION.match(snapshot["action"]):
        raise AuditFieldError(f"audit action must be upper snake case, got {snapshot['action']!r}")
    return snapshot
