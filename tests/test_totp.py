"""The one-time password implementation, held against RFC 6238 rather than against itself.

An algorithm written from a specification is only as good as the vectors it is checked
with. These are the published ones from RFC 6238 Appendix B, so a change to the counter,
the truncation or the hash turns this file red rather than silently issuing codes no
authenticator app agrees with.
"""

from __future__ import annotations

import base64

import pytest

from directive import totp

#: RFC 6238 Appendix B uses the ASCII secret "12345678901234567890". The RFC prints it as
#: that string; this module takes base32, which is what an authenticator app is given.
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode("ascii").rstrip("=")

#: RFC 6238 Appendix B, the SHA-1 rows. Unix time, then the expected 8-digit code.
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize(("moment", "expected"), RFC_VECTORS)
def test_the_rfc_6238_vectors_reproduce(moment: int, expected: str) -> None:
    """The specification's own published answers, at eight digits as the RFC prints them."""
    assert totp.code_now(RFC_SECRET, now=moment, digits=8) == expected


def test_a_six_digit_code_is_the_last_six_of_the_eight_digit_one() -> None:
    """Six digits is the same truncation modulo a smaller power of ten, not a new algorithm.

    Worth pinning because the application issues six and the vectors above prove eight: if
    the two disagreed, the vectors would be testing a code path the product never uses.
    """
    for moment, expected in RFC_VECTORS:
        assert totp.code_now(RFC_SECRET, now=moment) == expected[-6:]


def test_a_secret_round_trips_through_base32() -> None:
    """What `new_secret` emits is what `_decode` reads back."""
    material = bytes(range(totp.SECRET_BYTES))
    secret = totp.new_secret(material)

    assert "=" not in secret, "padding breaks most authenticator apps"
    assert totp._decode(secret) == material


def test_a_secret_is_long_enough_to_be_a_secret() -> None:
    """RFC 4226 section 4 requires 128 bits and recommends 160. Short material is refused."""
    with pytest.raises(totp.TotpError, match="real randomness"):
        totp.new_secret(b"too short")


def test_a_generated_secret_is_the_recommended_length() -> None:
    """The default path, not the test-supplied one."""
    assert len(totp._decode(totp.new_secret())) == totp.SECRET_BYTES


def test_two_generated_secrets_differ() -> None:
    """A fixed secret would make every enrolled device interchangeable."""
    assert totp.new_secret() != totp.new_secret()


def test_the_current_code_verifies() -> None:
    moment = 1762600000.0
    assert totp.verify(RFC_SECRET, totp.code_now(RFC_SECRET, now=moment), now=moment)


@pytest.mark.parametrize("drift", [-1, 0, 1])
def test_a_code_within_the_drift_window_is_accepted(drift: int) -> None:
    """One step either side, for a slow typist and a phone whose clock has wandered."""
    moment = 1762600000.0
    code = totp.code_now(RFC_SECRET, now=moment + drift * totp.STEP_SECONDS)

    assert totp.verify(RFC_SECRET, code, now=moment)


@pytest.mark.parametrize("drift", [-2, 2, 10, -10])
def test_a_code_outside_the_drift_window_is_refused(drift: int) -> None:
    """The window is the whole control. A code that never expires is not one-time."""
    moment = 1762600000.0
    code = totp.code_now(RFC_SECRET, now=moment + drift * totp.STEP_SECONDS)

    assert not totp.verify(RFC_SECRET, code, now=moment)


@pytest.mark.parametrize(
    "supplied",
    [
        "",
        "   ",
        "12345",
        "1234567",
        "abcdef",
        "12 34 56",
        "12345a",
        None,
        #: Arabic-Indic digits, built from code points rather than written literally: the
        #: analyser refuses an ambiguous character in source, and it is right to, since a
        #: reader cannot tell these from ASCII zeros by eye. That is the whole reason this
        #: case exists.
        "\u0660" * 6,
        "\u06f1\u06f2\u06f3\u06f4\u06f5\u06f6",
    ],
)
def test_a_malformed_code_is_a_verdict_and_never_an_exception(supplied: object) -> None:
    """Hostile input gets False, not a traceback.

    The Arabic-Indic digits are in this list on purpose: `str.isdigit` is true of them and
    `int()` parses them, which is the same class of defect this project has already fixed
    twice in its register grammars. Here the comparison is against an ASCII code, so they
    cannot match, and the test pins that rather than assuming it.
    """
    assert totp.verify(RFC_SECRET, supplied) is False  # type: ignore[arg-type]


def test_a_malformed_secret_raises_rather_than_reading_as_a_wrong_code() -> None:
    """A broken secret is a configuration fault rather than a wrong code.

    Reporting it as a wrong code sends an operator to look at the person's phone instead of
    at the stored value.
    """
    with pytest.raises(totp.TotpError, match="valid base32"):
        totp.verify("not!base32!", "123456")


def test_the_provisioning_uri_carries_what_an_app_needs() -> None:
    """The enrolment string. Shown once, stored never."""
    secret = totp.new_secret(bytes(range(20)))

    uri = totp.provisioning_uri(secret, actor="ash.higgins@bluestaq.uk", issuer="Directive")

    assert uri.startswith("otpauth://totp/Directive%3Aash.higgins%40bluestaq.uk?")
    assert f"secret={secret}" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri
