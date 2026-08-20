"""Key tests: the chain refuses to sign without a key, and rotation stays verifiable."""

from __future__ import annotations

import pytest

from complyops.audit import keys


def test_signing_fails_closed_when_no_key_is_configured() -> None:
    """No key means no entry, never an unsigned entry."""
    with pytest.raises(keys.AuditKeyError, match="AUDIT_HMAC_KEY is not set"):
        keys.signing_key()


def test_a_key_under_the_minimum_length_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_HMAC_KEY", "a" * (keys.MINIMUM_KEY_LENGTH - 1))
    with pytest.raises(keys.AuditKeyError, match="under the minimum"):
        keys.signing_key()


def test_a_key_at_the_minimum_length_is_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    """The boundary in both directions, or the minimum asserts nothing."""
    monkeypatch.setenv("AUDIT_HMAC_KEY", "a" * keys.MINIMUM_KEY_LENGTH)
    assert keys.signing_key() == b"a" * keys.MINIMUM_KEY_LENGTH


def test_the_key_identifier_defaults_and_can_be_set(monkeypatch: pytest.MonkeyPatch) -> None:
    assert keys.key_id() == keys.DEFAULT_KEY_ID
    monkeypatch.setenv("AUDIT_KEY_ID", "k7")
    assert keys.key_id() == "k7"


def test_verification_keys_carry_the_current_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUDIT_HMAC_KEY", "c" * 40)
    monkeypatch.setenv("AUDIT_KEY_ID", "k9")
    assert keys.verification_keys() == {"k9": b"c" * 40}


def test_retired_keys_keep_history_verifiable_across_a_rotation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUDIT_HMAC_KEY", "n" * 40)
    monkeypatch.setenv("AUDIT_KEY_ID", "k2")
    monkeypatch.setenv("AUDIT_RETIRED_KEYS", f"k1:{'o' * 40}")
    assert keys.verification_keys() == {"k1": b"o" * 40, "k2": b"n" * 40}


@pytest.mark.parametrize("malformed", ["k1", ":short", "k1:tooshort", "", "   "])
def test_a_malformed_retired_pair_is_skipped_rather_than_guessed(
    monkeypatch: pytest.MonkeyPatch, malformed: str
) -> None:
    """A skipped pair makes verification fail closed on entries naming that key."""
    monkeypatch.setenv("AUDIT_RETIRED_KEYS", malformed)
    assert keys.verification_keys() == {}


def test_verification_keys_are_empty_when_nothing_is_configured() -> None:
    assert keys.verification_keys() == {}
