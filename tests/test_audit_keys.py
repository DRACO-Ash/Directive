"""Key tests: the chain refuses to sign without a key, and rotation stays verifiable."""

from __future__ import annotations

import pytest

from complyops.audit import keys
from complyops.audit.validation import AuditFieldError


def test_signing_fails_closed_when_no_key_is_configured() -> None:
    """No key means no entry, never an unsigned entry."""
    with pytest.raises(keys.AuditKeyError, match="AUDIT_HMAC_KEY is not set"):
        keys.signing_key()


def test_a_passphrase_is_refused_however_long(monkeypatch: pytest.MonkeyPatch) -> None:
    """A character count cannot express key strength.

    Every stored row is a message and its tag, and the list is readable by more people
    than hold the key, so a low-entropy passphrase falls to an offline attack and returns
    full re-stamping power over the audit log.
    """
    monkeypatch.setenv("AUDIT_HMAC_KEY", "Password1234567890Password123456")
    with pytest.raises(keys.AuditKeyError, match="real key material"):
        keys.signing_key()


def test_the_error_names_the_generation_command_but_never_the_configured_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exact length is an oracle on a credential, which is why bands exist."""
    monkeypatch.setenv("AUDIT_HMAC_KEY", "Password1234567890Password1234567")
    with pytest.raises(keys.AuditKeyError) as raised:
        keys.signing_key()
    assert keys.KEY_GENERATION_COMMAND in str(raised.value)
    assert "33" not in str(raised.value)


@pytest.mark.parametrize("encoding", ["hex", "base64"])
def test_real_key_material_is_accepted_in_either_encoding(
    monkeypatch: pytest.MonkeyPatch, encoding: str
) -> None:
    import base64  # noqa: PLC0415 - needed only here

    material = bytes(range(32))
    value = material.hex() if encoding == "hex" else base64.b64encode(material).decode("ascii")
    monkeypatch.setenv("AUDIT_HMAC_KEY", value)
    assert keys.signing_key() == material


def test_the_byte_minimum_is_enforced_at_the_boundary_in_both_directions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    at_limit = bytes(range(keys.MINIMUM_KEY_BYTES))
    monkeypatch.setenv("AUDIT_HMAC_KEY", at_limit.hex())
    assert keys.signing_key() == at_limit

    monkeypatch.setenv("AUDIT_HMAC_KEY", at_limit[:-1].hex())
    with pytest.raises(keys.AuditKeyError, match="real key material"):
        keys.signing_key()


def test_a_key_is_never_rewritten_to_something_the_operator_cannot_reproduce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`config.normalise` strips quotes and interior control characters.

    Applied to key material that silently changes the key, so the app signs under a key
    the operator's own record does not reproduce and an assessor re-verifying with the
    documented key sees a broken chain over clean evidence. Reject loudly instead.
    """
    material = bytes(range(32)).hex()
    monkeypatch.setenv("AUDIT_HMAC_KEY", f'"{material}"')
    with pytest.raises(keys.AuditKeyError, match="wrapped in quotes"):
        keys.signing_key()

    monkeypatch.setenv("AUDIT_HMAC_KEY", material[:10] + "\t" + material[10:])
    with pytest.raises(keys.AuditKeyError, match="never rewritten"):
        keys.signing_key()


def test_a_trailing_newline_is_tolerated_because_the_console_adds_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    material = bytes(range(32))
    monkeypatch.setenv("AUDIT_HMAC_KEY", f"{material.hex()}\n")
    assert keys.signing_key() == material


def test_the_key_identifier_defaults_and_can_be_set(monkeypatch: pytest.MonkeyPatch) -> None:
    assert keys.key_id() == keys.DEFAULT_KEY_ID
    monkeypatch.setenv("AUDIT_KEY_ID", "k7")
    assert keys.key_id() == "k7"


@pytest.mark.parametrize("hostile", ["=cmd|' /c calc'!A1", "k" * 33, "k 1", "k:1", ""])
def test_a_hostile_key_identifier_is_refused(monkeypatch: pytest.MonkeyPatch, hostile: str) -> None:
    """The identifier reaches the digest and every stored row, so it is held to the rules."""
    monkeypatch.setenv("AUDIT_KEY_ID", hostile)
    if hostile == "":
        assert keys.key_id() == keys.DEFAULT_KEY_ID
        return
    with pytest.raises(AuditFieldError, match="signing key identifier"):
        keys.key_id()


def test_verification_keys_carry_the_current_key(monkeypatch: pytest.MonkeyPatch) -> None:
    current = bytes(range(32))
    monkeypatch.setenv("AUDIT_HMAC_KEY", current.hex())
    monkeypatch.setenv("AUDIT_KEY_ID", "k9")
    assert keys.verification_keys() == {"k9": current}


def test_retired_keys_keep_history_verifiable_across_a_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current, retired = bytes(range(32)), bytes(range(32, 64))
    monkeypatch.setenv("AUDIT_HMAC_KEY", current.hex())
    monkeypatch.setenv("AUDIT_KEY_ID", "k2")
    monkeypatch.setenv("AUDIT_RETIRED_KEYS", f"k1:{retired.hex()}")
    assert keys.verification_keys() == {"k1": retired, "k2": current}


@pytest.mark.parametrize(
    "malformed",
    [
        "k1",
        ":00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "k1:tooshort",
        "k1:Password1234567890Password123456",
        "k 1:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        "",
        "   ",
    ],
)
def test_a_malformed_retired_pair_is_skipped_rather_than_guessed(
    monkeypatch: pytest.MonkeyPatch, malformed: str
) -> None:
    """A skipped pair makes verification fail closed on entries naming that key."""
    monkeypatch.setenv("AUDIT_RETIRED_KEYS", malformed)
    assert keys.verification_keys() == {}


def test_verification_keys_are_empty_when_nothing_is_configured() -> None:
    assert keys.verification_keys() == {}
