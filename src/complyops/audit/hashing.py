"""Tamper-evident hashing for the compliance audit log (AUD-001).

The control this module provides is a hash CHAIN, not a per-row hash. A per-row hash
over the record's own fields is recomputable by anyone who can edit the row, so it
detects an accidental change and nothing else: an edit is re-stampable and a deletion
is invisible. Chaining each entry to its predecessor makes any edit, reorder, or
deletion break every hash after it, which is what an assessor or the Information
Commissioner's Office can actually be shown.

Two design choices are load-bearing and deliberate.

Length-prefixed encoding. Each field is serialised as its UTF-8 byte length, a colon,
then its bytes. A plain delimiter would let one field absorb another: with a pipe
delimiter, actor ``a|b`` and action ``c`` produce the same payload as actor ``a`` and
action ``b|c``, so two different records would share a hash. Length prefixes remove
that ambiguity by construction.

No truncation. The flight plan mentions a hash truncation policy. Truncation cuts the
work an attacker needs to forge a colliding entry, so this module stores all 64 hex
characters. If a SharePoint column cannot hold 64 characters that is a schema question
for the list owner, not a reason to weaken the hash. TBC, re-verify against AUD-001.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping

#: The fields covered by an entry hash, in the order they are serialised. Changing this
#: tuple or its order breaks every historical hash, so it is an irreversible decision
#: requiring the Managing Director's sign-off per the flight plan.
FIELD_ORDER: tuple[str, ...] = ("timestamp", "actor", "action", "resource", "resource_id")

#: The chain's anchor. The first entry has no predecessor, so it chains to all zeroes.
GENESIS_HASH = "0" * 64

#: SHA-256 rendered as lowercase hexadecimal, stored in full.
HASH_LENGTH = 64

_HEX_HASH = re.compile(r"\A[0-9a-f]{64}\Z")


class AuditHashError(ValueError):
    """Raised when an entry cannot be hashed. Always fail closed, never hash a guess."""


def is_hash(value: str) -> bool:
    """Return whether ``value`` is a full lowercase hexadecimal SHA-256 digest."""
    return bool(_HEX_HASH.match(value))


def _field(fields: Mapping[str, str], name: str) -> str:
    """Return one required field, rejecting an absent, blank, or non-string value."""
    if name not in fields:
        raise AuditHashError(f"audit entry is missing the {name!r} field")
    value = fields[name]
    if not isinstance(value, str):
        raise AuditHashError(f"audit field {name!r} must be a string, got {type(value).__name__}")
    if not value.strip():
        raise AuditHashError(f"audit field {name!r} must not be blank")
    return value


def canonical_payload(fields: Mapping[str, str]) -> bytes:
    """Serialise the covered fields into an unambiguous byte string.

    Each field becomes ``<byte length>:<bytes>``, so no field can absorb another and no
    two distinct records share a payload.
    """
    parts: list[bytes] = []
    for name in FIELD_ORDER:
        encoded = _field(fields, name).encode("utf-8")
        parts.append(str(len(encoded)).encode("ascii"))
        parts.append(b":")
        parts.append(encoded)
    return b"".join(parts)


def entry_hash(previous_hash: str, fields: Mapping[str, str]) -> str:
    """Return the chained SHA-256 for one audit entry.

    The digest covers the previous entry's hash followed by this entry's canonical
    payload, so an edit anywhere invalidates every hash after it.
    """
    if not isinstance(previous_hash, str) or not is_hash(previous_hash):
        raise AuditHashError(
            "previous hash must be 64 lowercase hexadecimal characters; "
            f"use GENESIS_HASH for the first entry, got {previous_hash!r}"
        )
    digest = hashlib.sha256()
    digest.update(previous_hash.encode("ascii"))
    digest.update(canonical_payload(fields))
    return digest.hexdigest()
