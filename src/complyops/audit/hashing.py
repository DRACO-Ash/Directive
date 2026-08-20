"""Tamper-evident hashing for the compliance audit log (AUD-001).

The control is a KEYED hash CHAIN, and each half of that answers a different attack.

Chaining answers the edit. A per-entry hash over the entry's own fields detects an
accidental change and nothing else: an edit is re-stampable and a deletion is
invisible. Chaining each entry to its predecessor means an edit, a reorder, or a
deletion breaks every hash after it.

Keying answers the re-stamp. Chaining alone is only evidence against an attacker who
cannot recompute the chain, and the attacker named in the threat model can: somebody
with item-edit rights on the list, using this documented algorithm. HMAC-SHA256 under a
key held by the server and never written to the list means edit rights are no longer
enough (`keys`).

Neither half answers a wholesale rewrite from the genesis anchor, and nor can they: a
chain is self-consistent by construction. That needs a trusted record of where the log
should end, which is `anchor`, and `verify_chain` refuses to call a run intact unless it
terminates where the anchor says it should.

Two encoding choices are load-bearing.

Length-prefixed fields. Each field is serialised as its UTF-8 byte length, a colon,
then its bytes. A plain delimiter would let one field absorb another: with a pipe
delimiter, actor ``a|b`` and action ``c`` produce the same payload as actor ``a`` and
action ``b|c``, so two different records would share a digest. Length prefixes remove
that ambiguity by construction.

No truncation. Truncation cuts the work an attacker needs to forge a colliding entry,
so all 64 hexadecimal characters are stored. If a list column cannot hold 64
characters, that is a schema question for the list owner, never a reason to weaken the
hash. TBC, re-verify against AUD-001.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Mapping
from typing import TypeGuard

#: The record fields covered by an entry hash, in the order they are serialised.
#: Changing this tuple, its order, or the digest below breaks every historical entry, so
#: it is an irreversible decision requiring the Managing Director's sign-off. A golden
#: test vector pins it, so a change cannot pass the loop silently.
FIELD_ORDER: tuple[str, ...] = ("timestamp", "actor", "action", "resource", "resource_id")

#: The chain's anchor. The first entry has no predecessor, so it chains to all zeroes.
GENESIS_HASH = "0" * 64

#: HMAC-SHA256 rendered as lowercase hexadecimal, stored in full.
HASH_LENGTH = 64

_HEX_HASH = re.compile(r"\A[0-9a-f]{64}\Z")


class AuditHashError(ValueError):
    """Raised when an entry cannot be hashed. Always fail closed, never hash a guess."""


def is_hash(value: object) -> TypeGuard[str]:
    """Return whether ``value`` is a full lowercase hexadecimal digest.

    A type guard, so a caller validating an untrusted document narrows the value at the
    same time as checking it, rather than checking and then asserting the type again.
    """
    return isinstance(value, str) and bool(_HEX_HASH.match(value))


def canonical_payload(fields: Mapping[str, str], key_id: str) -> bytes:
    """Serialise the covered fields and the key identifier unambiguously.

    Each element becomes ``<byte length>:<bytes>``, so no element can absorb another and
    no two distinct records share a payload. The key identifier is covered so a signing
    key cannot be swapped for a weaker one after the fact.

    Expects fields already validated by :func:`complyops.audit.validation.normalise_fields`.
    """
    parts: list[bytes] = []
    for name in (*FIELD_ORDER, "\x00key_id"):
        value = key_id if name == "\x00key_id" else fields.get(name)
        if not isinstance(value, str) or not value:
            raise AuditHashError(f"audit entry is missing the {name.lstrip(chr(0))!r} field")
        encoded = value.encode("utf-8")
        parts.append(f"{len(encoded)}:".encode("ascii"))
        parts.append(encoded)
    return b"".join(parts)


def entry_hash(previous_hash: str, fields: Mapping[str, str], *, key: bytes, key_id: str) -> str:
    """Return the keyed, chained digest for one audit entry.

    The digest covers the previous entry's hash, this entry's canonical payload, and the
    key identifier, under HMAC-SHA256. An edit anywhere invalidates every digest after
    it, and forging one needs the key as well as write access.
    """
    if not is_hash(previous_hash):
        raise AuditHashError(
            "previous hash must be 64 lowercase hexadecimal characters; "
            f"use GENESIS_HASH for the first entry, got {previous_hash!r}"
        )
    if not key:
        raise AuditHashError("no signing key supplied, so the entry cannot be signed")
    message = previous_hash.encode("ascii") + canonical_payload(fields, key_id)
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def hashes_equal(left: str, right: str) -> bool:
    """Compare two digests in constant time, so no comparison leaks by timing."""
    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))
