"""Time-based one-time passwords, RFC 6238, on the standard library alone.

The second factor for a local sign-in. Written here rather than taken from a package for
one reason that is specific to this build: the shipped image installs nine pinned
components and every one of them is attack surface the container scan reads and a human
re-pins when an advisory lands. The whole of RFC 6238 that this application needs is a
counter, an HMAC and a truncation, which is forty lines. A dependency would be more code
in the image than the algorithm is.

That reasoning only holds because this is a STANDARD with published test vectors. The
vectors from RFC 6238 Appendix B are asserted in `tests/test_totp.py`, so the
implementation is held against the specification rather than against its own output, which
is the difference between writing an algorithm and inventing one. Nothing here is novel
cryptography: the primitive is `hmac` from the standard library.

SHA-1 is the hash, deliberately. It is the default every authenticator application
implements, and a secret that only works in some of them is a support problem rather than a
security improvement. Its use here is as a message authentication code over a counter, not
as a collision-resistant digest, and HMAC-SHA1 is unbroken for that purpose. RFC 6238
section 1.2 names SHA-1 as the default for exactly this reason.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import struct
import time

#: Seconds in one step. Thirty is the RFC 6238 default and what every authenticator app
#: assumes unless told otherwise. Changing it silently invalidates every enrolled device.
STEP_SECONDS = 30

#: How many digits the person types. Six is the universal default.
DIGITS = 6

#: How many steps either side of now are accepted. One step each way covers a slow typist
#: and a phone whose clock drifts, at the cost of a three-step window an attacker may aim
#: at. Wider windows are how a one-time password stops being one.
DRIFT_STEPS = 1

#: The shared secret's length in bytes. RFC 4226 section 4 requires at least 128 bits and
#: recommends 160, which is 20 bytes and the length every authenticator app expects.
SECRET_BYTES = 20


class TotpError(ValueError):
    """Raised when a secret cannot be read. Never raised for a wrong code."""


def new_secret(random_bytes: bytes | None = None) -> str:
    """Return a fresh base32 secret, in the form an authenticator app accepts.

    Base32 because that is what the `otpauth://` URI scheme carries and what every app
    reads from a QR code or accepts typed. The padding is stripped because most apps
    refuse a secret containing `=`.
    """
    material = random_bytes if random_bytes is not None else _random(SECRET_BYTES)
    if len(material) < SECRET_BYTES:
        raise TotpError(f"a secret needs at least {SECRET_BYTES} bytes of real randomness")
    return base64.b32encode(material).decode("ascii").rstrip("=")


def _random(count: int) -> bytes:
    """Return cryptographically strong bytes. Separated so a test can supply its own."""
    import secrets  # noqa: PLC0415 - imported here so the module reads as pure otherwise

    return secrets.token_bytes(count)


def _decode(secret: str) -> bytes:
    """Return the raw secret, or raise. Padding is restored before decoding."""
    cleaned = secret.strip().replace(" ", "").upper()
    if not cleaned:
        raise TotpError("the secret is empty")
    padded = cleaned + "=" * (-len(cleaned) % 8)
    try:
        return base64.b32decode(padded, casefold=False)
    except (binascii.Error, ValueError) as error:
        raise TotpError("the secret is not valid base32") from error


def code_at(secret: str, counter: int, *, digits: int = DIGITS) -> str:
    """Return the code for one counter value. RFC 4226 section 5.3.

    The truncation masks the top bit of the four bytes it selects, which is the step the
    RFC spells out and the one an implementation written from memory tends to drop: without
    it the value is sometimes read as negative and the code is wrong about half the time on
    a signed-integer platform.
    """
    digest = hmac.new(_decode(secret), struct.pack(">Q", counter), "sha1").digest()
    offset = digest[-1] & 0x0F
    chunk = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(chunk % (10**digits)).zfill(digits)


def code_now(secret: str, *, now: float | None = None, digits: int = DIGITS) -> str:
    """Return the code for the current step. For tests and for enrolment confirmation."""
    moment = time.time() if now is None else now
    return code_at(secret, int(moment // STEP_SECONDS), digits=digits)


def verify(secret: str, supplied: str, *, now: float | None = None) -> bool:
    """Return whether ``supplied`` is a valid code, within the drift window.

    Returns a verdict for every input including a hostile one. A malformed secret is the
    one case that raises, because it is a configuration fault rather than a wrong code and
    reporting it as "wrong code" would send an operator looking at the wrong thing.

    The comparison is constant-time. A code is a six-digit secret for thirty seconds, and a
    comparison that returns early on the first wrong digit leaks how many digits were right.
    """
    candidate = (supplied or "").strip().replace(" ", "")
    #: ASCII digits by allowlist, NOT `str.isdigit`. `isdigit` is true of the Arabic-Indic
    #: digits and of several other Unicode numerals, and `hmac.compare_digest` raises
    #: TypeError on a non-ASCII string, so `isdigit` turned a wrong code into a traceback.
    #: Found by the test below rather than in production. This is the third place in this
    #: application where a Unicode-aware numeric check was the wrong one, after the date
    #: grammar and the identifier grammar, and the answer is the same every time: name the
    #: ten characters that are allowed.
    if len(candidate) != DIGITS or not all(character in "0123456789" for character in candidate):
        return False
    moment = time.time() if now is None else now
    step = int(moment // STEP_SECONDS)
    #: Every step in the window is checked, and the loop does NOT stop at the first match.
    #: Short-circuiting would make a code from the current step verify faster than one from
    #: the edge of the window, which is a timing signal about which step matched.
    matched = False
    for drift in range(-DRIFT_STEPS, DRIFT_STEPS + 1):
        if hmac.compare_digest(code_at(secret, step + drift), candidate):
            matched = True
    return matched


def provisioning_uri(secret: str, *, actor: str, issuer: str) -> str:
    """Return the `otpauth://` URI an authenticator app reads to enrol.

    Rendered as text for the person to type or scan. The secret is in it, so it is shown
    once at enrolment, never stored in that form, and never written to a log.
    """
    from urllib.parse import quote  # noqa: PLC0415 - only this function needs it

    label = quote(f"{issuer}:{actor}", safe="")
    query = (
        f"secret={quote(secret, safe='')}"
        f"&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
    return f"otpauth://totp/{label}?{query}"
