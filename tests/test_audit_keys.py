"""Key tests: the chain refuses to sign without a key, and rotation stays verifiable."""

from __future__ import annotations

import pytest

from complyops.audit import keys


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
    with pytest.raises(keys.AuditKeyError, match="AUDIT_KEY_ID is not usable"):
        keys.key_id()


def test_verification_keys_carry_the_current_key(monkeypatch: pytest.MonkeyPatch) -> None:
    current = bytes(range(32))
    monkeypatch.setenv("AUDIT_HMAC_KEY", current.hex())
    monkeypatch.setenv("AUDIT_KEY_ID", "k9")
    assert keys.verification_keys() == {"k9": current}


def test_retired_keys_keep_history_verifiable_across_a_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = bytes(range(32))
    retired = bytes(range(16)) + bytes(range(240, 256))
    monkeypatch.setenv("AUDIT_HMAC_KEY", current.hex())
    monkeypatch.setenv("AUDIT_KEY_ID", "k2")
    monkeypatch.setenv("AUDIT_RETIRED_KEYS", f"k1:{retired.hex()}")
    assert keys.verification_keys() == {"k1": retired, "k2": current}


GOOD_KEY_HEX = (bytes(range(16)) + bytes(range(240, 256))).hex()


@pytest.mark.parametrize(
    ("malformed", "fragment"),
    [
        ("k1", "not an `id:key` pair"),
        (f":{GOOD_KEY_HEX}", "unusable identifier"),
        ("k1:tooshort", "real key material"),
        ("k1:Password1234567890Password123456", "real key material"),
        (f"k 1:{GOOD_KEY_HEX}", "unusable identifier"),
    ],
)
def test_a_malformed_retired_pair_raises_rather_than_being_skipped(
    monkeypatch: pytest.MonkeyPatch, malformed: str, fragment: str
) -> None:
    """Skipping a pair silently made a quoting mistake read as tampering.

    The resulting verdict was "chain broken: no verification key is available", which is
    indistinguishable from a real attack over evidence nobody touched. A configuration
    fault must announce itself as one.
    """
    monkeypatch.setenv("AUDIT_RETIRED_KEYS", malformed)
    with pytest.raises(keys.AuditKeyError, match=fragment):
        keys.verification_keys()


def test_an_empty_retired_list_yields_no_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_RETIRED_KEYS", "")
    assert keys.verification_keys() == {}


def test_a_whitespace_only_retired_list_is_refused_rather_than_read_as_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Read verbatim means a value that is not what it looks like is a fault, not a default."""
    monkeypatch.setenv("AUDIT_RETIRED_KEYS", "   ")
    with pytest.raises(keys.AuditKeyError, match="whitespace"):
        keys.verification_keys()


def test_a_quoted_retired_list_is_refused_loudly(monkeypatch: pytest.MonkeyPatch) -> None:
    """The mistake the deployment notes warn about must not degrade into a tamper alarm."""
    monkeypatch.setenv("AUDIT_RETIRED_KEYS", f'"k0:{GOOD_KEY_HEX}"')
    with pytest.raises(keys.AuditKeyError, match="wrapped in quotes"):
        keys.verification_keys()


@pytest.mark.parametrize(
    ("label", "value"),
    [
        ("quoted", '"{key}"'),
        ("space padded", " {key} "),
        ("interior control character", "{key}"),
    ],
)
def test_the_key_identifier_is_read_verbatim_and_never_rewritten(
    monkeypatch: pytest.MonkeyPatch, label: str, value: str
) -> None:
    r"""The identifier reaches the digest, so a rewritten one cannot be reproduced.

    It used to pass through the console-noise normaliser: `"k1"` signed as `k1` and
    `k1\x01k2` signed as `k1k2`, so an operator's recorded identifier differed from the
    one inside the digest and independent re-verification of clean evidence would fail.
    """
    raw = "k1\x01k2" if label == "interior control character" else value.format(key="k1")
    monkeypatch.setenv("AUDIT_KEY_ID", raw)
    with pytest.raises(keys.AuditKeyError):
        keys.key_id()
    assert label


def test_verification_keys_are_empty_when_nothing_is_configured() -> None:
    assert keys.verification_keys() == {}


def test_key_usability_is_reported_as_a_boolean(monkeypatch: pytest.MonkeyPatch) -> None:
    """Presence and a length band cannot tell a usable key from one this module refuses.

    A quoted key, a padded key and a passphrase all render as present at the same band as
    a correct key, so the operator who made the exact mistake the deployment notes warn
    about saw a read-out saying all was well and a dead audit path.
    """
    assert keys.key_is_usable() is False

    good = bytes(range(32)).hex()
    monkeypatch.setenv("AUDIT_HMAC_KEY", good)
    assert keys.key_is_usable() is True

    monkeypatch.setenv("AUDIT_HMAC_KEY", f'"{good}"')
    assert keys.key_is_usable() is False

    monkeypatch.setenv("AUDIT_HMAC_KEY", "Password1234567890Password123456")
    assert keys.key_is_usable() is False


@pytest.mark.parametrize(
    ("label", "material"),
    [
        ("under the byte minimum", bytes(range(31))),
        ("too few distinct values", bytes([1, 2, 3, 4] * 8)),
        ("wholly printable text", bytes(range(0x41, 0x61))),
    ],
)
def test_each_strength_rule_rejects_independently(
    monkeypatch: pytest.MonkeyPatch, label: str, material: bytes
) -> None:
    """Three separate rules, each of which must reject on its own."""
    monkeypatch.setenv("AUDIT_HMAC_KEY", material.hex())
    with pytest.raises(keys.AuditKeyError, match="real key material"):
        keys.signing_key()
    assert label


def test_the_distinct_byte_floor_is_enforced_at_the_boundary_in_both_directions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A floor of N must accept N and reject N minus one, or it asserts nothing."""
    floor = keys.MINIMUM_DISTINCT_BYTES
    at_floor = bytes(range(floor)) + bytes([0] * (keys.MINIMUM_KEY_BYTES - floor))
    assert len(set(at_floor)) == floor
    monkeypatch.setenv("AUDIT_HMAC_KEY", at_floor.hex())
    assert keys.signing_key() == at_floor

    below = bytes(range(floor - 1)) + bytes([0] * (keys.MINIMUM_KEY_BYTES - floor + 1))
    assert len(set(below)) == floor - 1
    monkeypatch.setenv("AUDIT_HMAC_KEY", below.hex())
    with pytest.raises(keys.AuditKeyError, match="real key material"):
        keys.signing_key()
