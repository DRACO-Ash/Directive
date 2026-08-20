"""Boundary validation for audit fields, applied before anything is hashed.

Caps and character rules belong here, at the append boundary, and not on read. An audit
entry is immutable and chained, so an over-collected or malformed field cannot later be
corrected or erased without breaking every hash after it. That makes the boundary the
only place a limit can be added, and it makes adding one after the first entry is
written the same irreversible change as altering the hash construction.

The character rule is an ALLOWLIST, not a list of known-bad characters. A denylist was
tried first and leaked twice in one review: rejecting Unicode category ``Cc`` missed
U+2028 LINE SEPARATOR and U+2029 PARAGRAPH SEPARATOR, which terminate a line for
``str.splitlines`` and for most log and comma-separated-value consumers, so an actor
could forge the line ``CRITICAL chain verified intact by admin``; and it missed category
``Cf``, which carries zero-width space, soft hyphen and the byte-order mark, each of
which misrepresents a recorded actor. A denylist over Unicode is a losing position, so
audit fields are restricted to printable ASCII. A value outside that set is REJECTED
rather than transliterated, because an entry is evidence and evidence is refused rather
than quietly rewritten.

TBC, re-verify with the ISM: printable ASCII assumes every actor is a user principal
name and every resource is a register name, which holds for the nine registers in the
architecture. A non-ASCII actor would be rejected loudly rather than mangled, which
is the right failure, but the owner should confirm the assumption.

Four classes are therefore rejected: anything outside printable ASCII; anything over its
byte cap, so no single entry can dominate the log; leading or trailing whitespace, which
lets a formula character hide behind a space; and a leading formula character, because
an assessor evidence pack is exported to a spreadsheet where a leading equals sign is
executed.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime

#: Byte caps per field, in FIELD_ORDER order. Generous enough for a real user principal
#: name, a real record reference, and a real user-agent string, small enough that no
#: single entry can dominate the log.
FIELD_LIMITS: dict[str, int] = {
    "timestamp": 32,
    "actor": 320,
    "action": 64,
    "resource": 128,
    "resource_id": 128,
    "outcome": 16,
    "source_ip": 45,
    "user_agent": 512,
    "fields_changed": 128,
    "old_state": 32,
    "new_state": 32,
}

#: The fields every entry must carry. The rest are per-category and may be empty: an
#: authentication event has no `fields_changed`, and a task completion has no
#: `user_agent`. Empty is recorded as empty rather than omitted, so the digest covers a
#: fixed field set (see `hashing.FIELD_ORDER`).
REQUIRED_FIELDS = ("timestamp", "actor", "action", "resource", "resource_id")

#: `outcome` exists for the success or failure AUD-001 requires on an authentication
#: event. A closed set, so it cannot drift into free text.
OUTCOMES = frozenset({"SUCCESS", "FAILURE"})

#: An enumerated workflow state: a task status, an incident phase, a role name. Upper
#: snake case and short.
#:
#: What this rule does, stated precisely, because it was over-claimed. It REJECTS THE
#: COMMON SHAPES of record content: anything with a space, lower case, an `@`, or over 32
#: characters, which covers a free-text sentence, an email address, and a formatted name
#: or address. It does NOT make record content impossible: `HIGGINS`, `ASHLEY_HIGGINS`
#: and `SW1A1AA` all satisfy it. A single upper-case token can be a surname.
#:
#: So the guarantee is a large reduction in surface plus caller discipline, not an
#: impossibility, and the documents say that now rather than the stronger thing they used
#: to say. AUD-001 asks for the old and new value of a changed field, and for a task
#: status or an incident phase that is exactly right; for an incident's content it would
#: put personal data into a log that is immutable by design, where no correction and no
#: Article 17 erasure can reach it. Record content changes are therefore reported as field
#: NAMES in `fields_changed`, never as values.
#:
#: The control that WOULD be structural is a closed vocabulary of permitted states, the
#: way `OUTCOMES` is closed. It is not defined here because the real state set is not yet
#: knowable: the v1 prototype yields `open`, `pending`, `closed`, `done`, `On Track`,
#: `At Risk` and `Planned`, and inventing the rest would breach the no-invention rule.
#: Define it with the records module, which is when the vocabulary becomes real, and note
#: that a cap or a closed set is cheaper before the first entry is written than after.
#: TBC, re-verify the state vocabulary with the ISM.
_STATE = re.compile(r"\A[A-Z][A-Z0-9_]{0,31}\Z")

#: A comma-separated list of field names. Names only, for the reason above. Capped hard
#: at 128 bytes by FIELD_LIMITS: a change touches a handful of fields, and the previous
#: 512-byte cap accepted a whole free-text sentence spelled in snake case.
_FIELD_NAMES = re.compile(
    r"\A[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*(,[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*)*\Z"
)

#: Printable ASCII, space through tilde, MINUS the double quote. An allowlist, because a
#: denylist over Unicode leaks: see the module docstring.
#:
#: The double quote is excluded because the evidence pack is exported to a spreadsheet. A
#: value containing one can terminate its own comma-separated field and land a formula in
#: the next cell, which is the harm the leading-character guard below exists to prevent and
#: could not see. No field here has a legitimate use for it: not a user principal name, an
#: address, an action, a register name, a state, or a list of field names.
_PRINTABLE_ASCII = re.compile(r"\A[\x20-\x21\x23-\x7e]+\Z")

#: A character a spreadsheet treats as the start of a formula.
_FORMULA_LEAD = frozenset("=+-@")

#: RFC 3339 in UTC, which is the only timestamp form accepted. A local offset would let
#: two entries claim an order the chain contradicts. The calendar is checked separately:
#: a pattern alone accepts month 13 and day 40.
_TIMESTAMP = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z\Z")

#: An action name. Upper snake case, so the vocabulary stays a closed, greppable set.
#: The full vocabulary is not yet defined; this constrains the shape, not the list.
#: TBC, re-verify the action vocabulary against AUD-001.
_ACTION = re.compile(r"\A[A-Z][A-Z0-9_]{1,63}\Z")

#: A signing-key identifier. Recorded on every entry, so it is held to the same bar:
#: it reaches the digest without passing through the field rules above.
KEY_ID_PATTERN = re.compile(r"\A[A-Za-z0-9_-]{1,32}\Z")


class AuditFieldError(ValueError):
    """Raised when a field is not fit to be recorded. Always reject, never coerce."""


def check_key_id(value: str) -> str:
    """Validate a signing-key identifier, or raise :class:`AuditFieldError`."""
    if not isinstance(value, str) or not KEY_ID_PATTERN.match(value):
        raise AuditFieldError(
            f"the signing key identifier must be 1 to 32 characters of letters, digits, "
            f"underscore or hyphen, got {value!r}"
        )
    return value


def _check_one(name: str, value: object) -> str:
    """Validate one field and return it, or raise :class:`AuditFieldError`."""
    if not isinstance(value, str):
        raise AuditFieldError(f"audit field {name!r} must be a string, got {type(value).__name__}")
    if not value:
        if name in REQUIRED_FIELDS:
            raise AuditFieldError(f"audit field {name!r} must not be blank")
        return ""
    if value != value.strip():
        raise AuditFieldError(
            f"audit field {name!r} has leading or trailing whitespace, which can hide a "
            f"formula character from the export guard"
        )
    limit = FIELD_LIMITS[name]
    encoded = len(value.encode("utf-8"))
    if encoded > limit:
        raise AuditFieldError(f"audit field {name!r} is {encoded} bytes, over its cap of {limit}")

    if not _PRINTABLE_ASCII.match(value):
        raise AuditFieldError(
            f"audit field {name!r} contains a character outside printable ASCII, which "
            f"could forge a log line or misrepresent the recorded value"
        )
    if value[0] in _FORMULA_LEAD:
        raise AuditFieldError(
            f"audit field {name!r} starts with {value[0]!r}, which a spreadsheet treats "
            f"as a formula when the evidence pack is exported"
        )
    return value


def _check_timestamp(value: str) -> None:
    """Reject a timestamp that is not RFC 3339 in UTC, and not a real date."""
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
            if name in REQUIRED_FIELDS:
                raise AuditFieldError(f"audit entry is missing the {name!r} field")
            snapshot[name] = ""
            continue
        snapshot[name] = _check_one(name, fields[name])

    _check_timestamp(snapshot["timestamp"])
    if not _ACTION.match(snapshot["action"]):
        raise AuditFieldError(f"audit action must be upper snake case, got {snapshot['action']!r}")
    _check_optional(snapshot)
    return snapshot


def _check_optional(snapshot: dict[str, str]) -> None:
    """Apply the per-field rules that only bind when the field carries a value."""
    if snapshot["outcome"] and snapshot["outcome"] not in OUTCOMES:
        raise AuditFieldError(
            f"audit outcome must be one of {sorted(OUTCOMES)}, got {snapshot['outcome']!r}"
        )
    for name in ("old_state", "new_state"):
        if snapshot[name] and not _STATE.match(snapshot[name]):
            raise AuditFieldError(
                f"audit field {name!r} must be an enumerated state in upper snake case, at "
                f"most 32 characters, got {snapshot[name]!r}. This field cannot carry record "
                f"content: report a content change as a field name in 'fields_changed'."
            )
    if snapshot["fields_changed"] and not _FIELD_NAMES.match(snapshot["fields_changed"]):
        raise AuditFieldError(
            f"audit field 'fields_changed' must be a comma-separated list of lower snake "
            f"case field names, optionally dotted, got {snapshot['fields_changed']!r}. Names "
            f"only: a value would put record content into an immutable log."
        )
