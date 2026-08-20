"""The audit signing key: loading it, and failing closed without it.

The chain is keyed rather than plain. An unkeyed SHA-256 chain over a documented
construction is only tamper-evident against an attacker who cannot recompute it, and the
attacker this log defends against is named in the threat model: somebody with write
access to the stored log. That actor can edit a row and recompute every hash after it,
and an unkeyed verifier would report the result as intact.

Keying with HMAC-SHA256 under a key that actor does not hold removes that, because
re-stamping needs the key as well as write access. The key is delivered on the same
channel as the session key, never written alongside the log, and never logged.

The key must be real key material, and "real" is an entropy claim, not a length claim.
Every stored row is a message and its tag, and the log is readable by more people than
hold the key, because an exported evidence pack reaches an assessor, so a low-entropy
value falls to an offline attack and hands back full re-stamping power over the primary
asset. A character floor cannot express that: a
32-character passphrase was refused while the same passphrase re-spelt in the base64
alphabet at 44 characters was accepted, and `"deadbeef" * 8` decodes to 32 perfectly
shaped bytes drawn from four distinct values. So the decoded material is required to
carry a minimum number of distinct byte values, and a decode that is wholly printable
text is refused outright.

EVERY part of this configuration is read verbatim and rejected rather than rewritten:
the key, its identifier, and the retired-key list. They used to have three different
read rules, which meant an operator's recorded identifier could differ from the one
inside the digest, so independent re-verification of clean evidence would fail.
"""

from __future__ import annotations

import base64
import binascii
import os

from .validation import AuditFieldError, check_key_id

#: The shortest key accepted, in DECODED BYTES.
MINIMUM_KEY_BYTES = 32

#: The fewest distinct byte values acceptable in the decoded key. Random material of 32
#: bytes carries about 30 distinct values, and the chance of fewer than this is
#: vanishingly small, so the floor rejects structured input without rejecting real keys.
MINIMUM_DISTINCT_BYTES = 20

#: Used when no identifier is configured. Recorded on every entry it signs.
DEFAULT_KEY_ID = "k1"

#: How to produce a usable key. Quoted in the error, so the fix needs no documentation.
KEY_GENERATION_COMMAND = "openssl rand -hex 32"

#: The printable ASCII range. Key material that is wholly printable is text, not a key.
PRINTABLE_LOW = 0x20
PRINTABLE_HIGH = 0x7E


class AuditKeyError(RuntimeError):
    """Raised when no usable signing key is available. Never sign without one."""


def read_verbatim(name: str) -> str:
    r"""Return an environment value with no rewriting, or raise.

    Deliberately not `config.normalise`, which strips surrounding quotes and every
    control character from anywhere in the value. Applied to key configuration that
    silently changes it: a padded 41-character key became 37, and an identifier of
    ``k1\\x01k2`` became ``k1k2``, so the application signed under a key or an identifier
    the operator's own record does not reproduce. An assessor re-verifying from the
    documented values would then see a broken chain over clean evidence.

    A trailing newline is tolerated, because the operator console adds one routinely.
    Nothing else is.
    """
    raw = os.environ.get(name, "").strip("\r\n")
    if raw.startswith(('"', "'")) or raw.endswith(('"', "'")):
        raise AuditKeyError(
            f"{name} is wrapped in quotes. It is used verbatim and is never rewritten, so "
            f"remove the quotes rather than relying on them being stripped."
        )
    if raw != raw.strip() or any(character < " " or character == "\x7f" for character in raw):
        raise AuditKeyError(
            f"{name} contains whitespace or control characters. It is used verbatim and is "
            f"never rewritten, so fix the value rather than relying on trimming."
        )
    return raw


def key_id() -> str:
    """Return the identifier of the current signing key, read verbatim and validated."""
    raw = read_verbatim("AUDIT_KEY_ID")
    if not raw:
        return DEFAULT_KEY_ID
    try:
        return check_key_id(raw)
    except AuditFieldError as error:
        raise AuditKeyError(f"AUDIT_KEY_ID is not usable: {error}") from error


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


def _is_strong(material: bytes) -> bool:
    """Return whether the decoded material looks like a key rather than a passphrase."""
    if len(material) < MINIMUM_KEY_BYTES:
        return False
    if len(set(material)) < MINIMUM_DISTINCT_BYTES:
        return False
    # Wholly printable text decoded into the right length is a passphrase in disguise.
    return not all(PRINTABLE_LOW <= byte <= PRINTABLE_HIGH for byte in material)


def _key_from(name: str, raw: str) -> bytes:
    """Decode and strength-check one key value, or raise."""
    material = _decode(raw)
    if material is None or not _is_strong(material):
        # The configured length is deliberately absent from this message: an exact length
        # is an oracle on a credential, which is why the diagnostics read-out bands it.
        raise AuditKeyError(
            f"{name} must be real key material: hexadecimal or base64 decoding to at least "
            f"{MINIMUM_KEY_BYTES} bytes carrying at least {MINIMUM_DISTINCT_BYTES} distinct "
            f"byte values, and not printable text. A passphrase is refused however it is "
            f"encoded. Generate one with `{KEY_GENERATION_COMMAND}`."
        )
    return material


def signing_key() -> bytes:
    """Return the current signing key, or fail closed.

    Read from the environment at call time, so a key the platform injects after the
    process starts is still seen. Never returned to a caller outside this package and
    never logged: the diagnostics read-out reports its presence, band, and usability only.
    """
    raw = read_verbatim("AUDIT_HMAC_KEY")
    if not raw:
        raise AuditKeyError(
            "AUDIT_HMAC_KEY is not set, so no audit entry can be signed. The audit chain "
            f"fails closed rather than writing an unsigned entry. Generate one with "
            f"`{KEY_GENERATION_COMMAND}`."
        )
    return _key_from("AUDIT_HMAC_KEY", raw)


def verification_keys() -> dict[str, bytes]:
    """Return every key a stored entry may have been signed with, keyed by identifier.

    Retired keys are supplied as ``AUDIT_RETIRED_KEYS`` in ``id:key`` form, separated by
    semicolons, so history signed before a rotation stays verifiable.

    A malformed pair RAISES rather than being skipped. Skipping it silently produced the
    verdict "chain broken: no verification key is available for key id 'k0'" over
    evidence nobody had touched, which is indistinguishable from real tampering: a
    quoting mistake on the one variable that keeps history verifiable read as an attack.
    A configuration fault must announce itself as a configuration fault.
    """
    result: dict[str, bytes] = {}
    for position, pair in enumerate(read_verbatim("AUDIT_RETIRED_KEYS").split(";"), start=1):
        if not pair:
            continue
        # The pair IS the secret, so no branch below may echo it, and none may echo the
        # identifier either, since a mistyped separator makes the whole key the identifier.
        # This message used to interpolate the raw pair, so an operator who pasted the key
        # without its prefix, or typed a space for the colon, put full key material into an
        # exception that the first caller to log it would write to the container log. The
        # module already omits even the LENGTH of a key from an error for the same reason.
        identifier, separator, secret = pair.partition(":")
        if not separator:
            raise AuditKeyError(
                f"AUDIT_RETIRED_KEYS entry {position} is not an `id:key` pair. Separate "
                f"pairs with a semicolon. The value is not repeated here because it may be "
                f"key material."
            )
        try:
            checked = check_key_id(identifier)
        except AuditFieldError:
            raise AuditKeyError(
                f"AUDIT_RETIRED_KEYS entry {position} has an unusable identifier: it must "
                f"be 1 to 32 characters of letters, digits, underscore or hyphen. The value "
                f"is not repeated here because it may be key material."
            ) from None
        result[checked] = _key_from(f"AUDIT_RETIRED_KEYS entry {position}", secret)

    if os.environ.get("AUDIT_HMAC_KEY"):
        result[key_id()] = signing_key()
    return result


def key_is_usable() -> bool:
    """Return whether the configured signing key would actually be accepted.

    The diagnostics read-out needs this because presence and a length band cannot tell a
    usable key from one this module refuses: a quoted key, a padded key, and a passphrase
    all render as present at the same band as a correct key, so an operator who made the
    exact mistake the deployment notes warn about saw a read-out saying all was well and
    a dead audit path. A boolean leaks nothing beyond the fact of the refusal.
    """
    try:
        signing_key()
    except AuditKeyError:
        return False
    return True
