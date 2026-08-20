"""The audit signing key: loading it, and failing closed without it.

The chain is keyed rather than plain. An unkeyed SHA-256 chain over a documented
construction is only tamper-evident against an attacker who cannot recompute it, and the
attacker this log defends against is named in the threat model: somebody with item-edit
rights on the SharePoint list. That actor can edit a row and recompute every hash after
it, and an unkeyed verifier would report the result as intact.

Keying with HMAC-SHA256 under a key the list editor does not hold removes that, because
re-stamping now needs the key as well as edit rights. The key is delivered on the same
channel as the session key, never written to the list, and never logged.

The key must be REAL key material, not a passphrase. Every stored row is a message and
its tag, and the list is readable by more people than hold the key, so a low-entropy
operator passphrase such as ``Password1234567890Password123456`` falls to an offline
attack and hands back full re-stamping power over the primary asset. A minimum character
count cannot express that, so the value is required to decode, as hexadecimal or base64,
to at least 32 bytes.

Each entry records the identifier of the key that signed it, and the identifier is
covered by the digest, so a key cannot be swapped for a weaker one after the fact. That
is also what makes rotation possible: entries signed by a retired key still verify under
that key while new entries use the current one. A retired key is retired because it may
have leaked, so `chain.verify_log` additionally requires the log to END on an entry
signed by the anchor's key, which stops a leaked retired key being used to re-sign the
whole log.
"""

from __future__ import annotations

import base64
import binascii
import os

from .. import config
from .validation import AuditFieldError, check_key_id

#: The shortest key accepted, in DECODED BYTES. A character count cannot express key
#: strength: a 32-character passphrase is not 32 bytes of entropy.
MINIMUM_KEY_BYTES = 32

#: Used when no identifier is configured. Recorded on every entry it signs.
DEFAULT_KEY_ID = "k1"

#: How to produce a usable key. Quoted in the error, so the fix needs no documentation.
KEY_GENERATION_COMMAND = "openssl rand -hex 32"


class AuditKeyError(RuntimeError):
    """Raised when no usable signing key is available. Never sign without one."""


def key_id() -> str:
    """Return the identifier of the current signing key, validated."""
    return check_key_id(config.env("AUDIT_KEY_ID", DEFAULT_KEY_ID))


def _decode(raw: str) -> bytes | None:
    """Return ``raw`` decoded from hexadecimal or base64, or ``None`` if it is neither."""
    try:
        return bytes.fromhex(raw)
    except ValueError:
        pass
    try:
        return base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        return None


def _read_secret(name: str) -> str:
    """Read a secret WITHOUT rewriting it.

    Deliberately not `config.normalise`, which strips surrounding quotes and every
    control character from anywhere in the value. Applied to key material that silently
    changes the key: a padded 41-character value became 37, so the app signed under a key
    the operator's own record does not reproduce, and an assessor re-verifying with the
    documented key would see a broken chain over clean evidence. A malformed secret is
    rejected loudly instead.
    """
    # A trailing newline is tolerated because the operator console adds one routinely.
    # Nothing else is: quotes and interior whitespace or control characters are rejected
    # rather than stripped.
    raw = os.environ.get(name, "").strip("\r\n")
    if raw.startswith(('"', "'")) or raw.endswith(('"', "'")):
        raise AuditKeyError(
            f"{name} is wrapped in quotes. It is used verbatim and is never rewritten, so "
            f"remove the quotes rather than relying on them being stripped."
        )
    if raw != raw.strip() or any(character < " " or character == "\x7f" for character in raw):
        raise AuditKeyError(
            f"{name} contains whitespace or control characters. It is used verbatim and "
            f"is never rewritten, so fix the value rather than relying on trimming."
        )
    return raw


def signing_key() -> bytes:
    """Return the current signing key, or fail closed.

    Read from the environment at call time, so a key the platform injects after the
    process starts is still seen. Never returned to a caller outside this package and
    never logged: the diagnostics read-out reports its presence and length band only.
    """
    raw = _read_secret("AUDIT_HMAC_KEY")
    if not raw:
        raise AuditKeyError(
            "AUDIT_HMAC_KEY is not set, so no audit entry can be signed. The audit chain "
            f"fails closed rather than writing an unsigned entry. Generate one with "
            f"`{KEY_GENERATION_COMMAND}`."
        )
    decoded = _decode(raw)
    if decoded is None or len(decoded) < MINIMUM_KEY_BYTES:
        # The configured length is deliberately absent from this message: an exact length
        # is an oracle on a credential, which is why the diagnostics read-out bands it.
        raise AuditKeyError(
            f"AUDIT_HMAC_KEY must be real key material: hexadecimal or base64 decoding to "
            f"at least {MINIMUM_KEY_BYTES} bytes, not a passphrase. Generate one with "
            f"`{KEY_GENERATION_COMMAND}`."
        )
    return decoded


def verification_keys() -> dict[str, bytes]:
    """Return every key a stored entry may have been signed with, keyed by identifier.

    Retired keys are supplied as ``AUDIT_RETIRED_KEYS`` in ``id:key`` form, separated by
    semicolons, so history signed before a rotation stays verifiable. A malformed pair is
    skipped rather than guessed at: verification then fails closed on any entry naming
    that identifier, which is the honest outcome.
    """
    result: dict[str, bytes] = {}
    # Read leniently: this is a LIST, so an empty or whitespace-only value simply yields
    # no pairs. Each individual key is still held to the same bar as the current one, and
    # a pair that fails any of those checks is skipped rather than guessed at.
    for pair in os.environ.get("AUDIT_RETIRED_KEYS", "").split(";"):
        identifier, separator, secret = pair.partition(":")
        if not separator:
            continue
        decoded = _decode(secret)
        if decoded is None or len(decoded) < MINIMUM_KEY_BYTES:
            continue
        try:
            result[check_key_id(identifier.strip())] = decoded
        except AuditFieldError:
            continue
    if os.environ.get("AUDIT_HMAC_KEY"):
        result[key_id()] = signing_key()
    return result
