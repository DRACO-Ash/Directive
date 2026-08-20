"""The audit signing key: loading it, and failing closed without it.

The chain is keyed rather than plain. An unkeyed SHA-256 chain over a documented
construction is only tamper-evident against an attacker who cannot recompute it, and
the attacker this log defends against is named in the threat model: somebody with
item-edit rights on the SharePoint list. That actor can edit a row and recompute every
hash after it, and an unkeyed verifier would report the result as intact.

Keying with HMAC-SHA256 under a key the list editor does not hold removes that, because
re-stamping now needs the key as well as edit rights. The key is delivered on the same
channel as the session key, never written to the list, and never logged.

Each entry records the identifier of the key that signed it, and the identifier is
covered by the digest, so a key cannot be swapped for a weaker one after the fact. That
is also what makes rotation possible: entries signed by a retired key still verify
under that key while new entries use the current one.
"""

from __future__ import annotations

import os

from .. import config

#: The shortest key accepted, in characters. Shorter than this is not a key.
MINIMUM_KEY_LENGTH = 32

#: Used when no identifier is configured. Recorded on every entry it signs.
DEFAULT_KEY_ID = "k1"


class AuditKeyError(RuntimeError):
    """Raised when no usable signing key is available. Never sign without one."""


def key_id() -> str:
    """Return the identifier of the current signing key."""
    return config.env("AUDIT_KEY_ID", DEFAULT_KEY_ID)


def signing_key() -> bytes:
    """Return the current signing key, or fail closed.

    Read from the environment at call time, so a key the platform injects after the
    process starts is still seen. Never returned to a caller outside this package and
    never logged: the diagnostics read-out reports its presence and length only.
    """
    raw = config.env("AUDIT_HMAC_KEY")
    if not raw:
        raise AuditKeyError(
            "AUDIT_HMAC_KEY is not set, so no audit entry can be signed. "
            "The audit chain fails closed rather than writing an unsigned entry."
        )
    if len(raw) < MINIMUM_KEY_LENGTH:
        raise AuditKeyError(
            f"AUDIT_HMAC_KEY is {len(raw)} characters, under the minimum of {MINIMUM_KEY_LENGTH}"
        )
    return raw.encode("utf-8")


def verification_keys() -> dict[str, bytes]:
    """Return every key a stored entry may have been signed with, keyed by identifier.

    Retired keys are supplied as ``AUDIT_RETIRED_KEYS`` in ``id:key`` form, separated by
    semicolons, so history signed before a rotation stays verifiable. A malformed pair
    is skipped rather than guessed at: verification then fails closed on any entry
    naming that identifier, which is the honest outcome.
    """
    keys: dict[str, bytes] = {}
    for pair in config.env("AUDIT_RETIRED_KEYS").split(";"):
        identifier, separator, secret = pair.partition(":")
        if separator and identifier.strip() and len(secret) >= MINIMUM_KEY_LENGTH:
            keys[identifier.strip()] = secret.encode("utf-8")
    if os.environ.get("AUDIT_HMAC_KEY"):
        keys[key_id()] = signing_key()
    return keys
