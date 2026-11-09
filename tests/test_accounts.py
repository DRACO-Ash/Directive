"""The credential store: hashing, lockout, recovery codes, and what must never be stored.

`test_local_sign_in.py` drives these through HTTP. This file holds the module itself,
because several of its properties are not reachable from a route: the stored format, the
behaviour under a corrupted record, and the concurrency bound that keeps a sign-in flood
from starving the liveness probe of threads.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from directive import accounts

GOOD = "a-password-of-real-length"  # a test value, opens nothing


# ============================ usernames ============================


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Ash.Higgins@Bluestaq.UK", "ash.higgins@bluestaq.uk"),
        ("  ash@bluestaq.uk  ", "ash@bluestaq.uk"),
        ("A_B-C.d+e@f", "a_b-c.d+e@f"),
    ],
)
def test_a_username_is_normalised(raw: str, expected: str) -> None:
    """Lower-cased and trimmed, so one person cannot become two accounts.

    Two accounts for one person is how a disabled account survives: the leaver is disabled
    as `Ash.Higgins@` and signs in as `ash.higgins@`.
    """
    assert accounts.normalise_username(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "ash higgins",
        "ash\they",
        "ash/../etc",
        "ash\u0000",
        "ashé",
        42,
        None,
        b"x",
        #: The LEADING characters, added after a gate found the docstring below true of the
        #: byte cap and false of the characters. Each of these was accepted for six
        #: releases, and each produced an account that no audit entry about it could name:
        #: six of six Administration entries recorded `unrecordable`, `ACCOUNT_LOCKED` was
        #: dropped outright, and the account could never sign in. `=` was already refused
        #: by the character allowlist; it is here so the set reads complete.
        "-ash@bluestaq.uk",
        "+ash@bluestaq.uk",
        "@ash.bluestaq.uk",
        "=ash@bluestaq.uk",
    ],
)
def test_an_unusable_username_is_refused(raw: object) -> None:
    """An allowlist of characters, not a pattern over Unicode.

    A username becomes an `actor` and a `resource_id` on an audit entry, and the audit
    boundary takes printable ASCII only AND refuses a leading formula character. A name the
    log cannot carry is a sign-in that cannot be attributed, so it is refused here where a
    person can be told why.
    """
    with pytest.raises(accounts.AccountError):
        accounts.normalise_username(raw)


def test_the_username_rule_and_the_audit_rule_are_one_definition() -> None:
    """Imported, not mirrored, so the two cannot drift apart again.

    They did drift, for six releases, and the cost is in `normalise_username`'s comment.
    This asserts the shared object rather than the behaviour, because behaviour alone would
    be satisfied by a second copy of the same characters.
    """
    from directive.audit import validation  # noqa: PLC0415 - only this test needs it

    assert accounts.FORMULA_LEAD is validation.FORMULA_LEAD


def test_a_username_may_not_exceed_the_audit_field_it_must_fit() -> None:
    """The binding cap is `resource_id` at 128 bytes, not `actor` at 320."""
    with pytest.raises(accounts.AccountError, match="at most"):
        accounts.normalise_username("a" * (accounts.MAXIMUM_USERNAME + 1))


# ============================ passwords ============================


def test_a_password_round_trips() -> None:
    stored = accounts.hash_password(GOOD)

    assert accounts.verify_password(stored, GOOD)
    assert not accounts.verify_password(stored, GOOD + "x")


def test_the_stored_form_carries_its_own_parameters() -> None:
    """Which is what lets the cost be raised later without invalidating every account."""
    stored = accounts.hash_password(GOOD)
    scheme, parameters, salt, digest = stored.split("$")

    assert scheme == "scrypt"
    assert parameters == f"n={accounts.SCRYPT_N},r={accounts.SCRYPT_R},p={accounts.SCRYPT_P}"
    assert salt and digest
    assert GOOD not in stored


def test_two_hashes_of_one_password_differ() -> None:
    """A per-password salt. Identical hashes would say who shares a password."""
    assert accounts.hash_password(GOOD) != accounts.hash_password(GOOD)


def test_a_hash_made_under_weaker_parameters_still_verifies_and_is_flagged() -> None:
    """The upgrade path, and the reason the parameters are stored rather than assumed."""
    salt = b"0123456789abcdef"
    weak = "$".join(
        (
            "scrypt",
            "n=16384,r=8,p=1",
            __import__("base64").b64encode(salt).decode(),
            __import__("base64")
            .b64encode(accounts._scrypt(GOOD, salt, n=16384, r=8, p=1))
            .decode(),
        )
    )

    assert accounts.verify_password(weak, GOOD)
    assert accounts.needs_rehash(weak)
    assert not accounts.needs_rehash(accounts.hash_password(GOOD))


@pytest.mark.parametrize(
    "stored",
    ["", "not-a-hash", "scrypt$n=x,r=8,p=1$aa$bb", "argon2$n=1$aa$bb", "scrypt$$$", "a$b$c$d$e"],
)
def test_an_unreadable_stored_password_is_a_verdict_and_never_an_exception(stored: str) -> None:
    """A corrupted record must refuse the sign-in, not take the process down.

    An operator then finds it through the refusal and the diagnostics rather than through a
    crash loop, which is the same reasoning the storage probe uses.
    """
    assert accounts.verify_password(stored, GOOD) is False


@pytest.mark.parametrize("supplied", [None, 42, b"bytes", "", []])
def test_a_non_string_password_is_refused_rather_than_coerced(supplied: object) -> None:
    assert accounts.verify_password(accounts.hash_password(GOOD), supplied) is False


@pytest.mark.parametrize("password", ["", "short", "a" * 11])
def test_a_password_under_the_floor_is_refused(password: str) -> None:
    with pytest.raises(accounts.AccountError, match="at least"):
        accounts.check_password_rules(password)


def test_an_absurdly_long_password_is_refused() -> None:
    """The hash accepts whatever it is given, so the sign-in form must bound it."""
    with pytest.raises(accounts.AccountError, match="too long"):
        accounts.check_password_rules("a" * (accounts.MAXIMUM_PASSWORD + 1))


def test_the_decoy_spends_real_effort_rather_than_sleeping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`absorb_timing` must do the HASHING work, not wait for a constant.

    A timed sleep is a constant an attacker subtracts; real hashing tracks the machine.

    Counted rather than timed, and asserted rather than merely called. The version of this
    test that shipped first called `absorb_timing()` with no assertion on it at all, so
    replacing its whole body with `return` left all 1547 tests green: a security gate
    proved it by mutation. It was a test named for a property it did not hold, which is the
    exact failure this project's own record says it repeated over five releases. A count
    into `_scrypt` is deterministic where a timing band would be flaky on a loaded runner,
    and it fails for the one reason that matters: no hashing happened.
    """
    calls: list[int] = []
    real = accounts._scrypt

    def counted(*args: object, **kwargs: object) -> bytes:
        calls.append(1)
        return real(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(accounts, "_scrypt", counted)
    accounts.absorb_timing()

    assert calls, "absorb_timing spent no hashing effort, so it is a sleep by another name"


def test_the_decoy_matches_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """And the effort it spends is wasted on purpose: no supplied value can match it."""
    assert accounts.verify_password(accounts._DECOY, GOOD) is False
    assert accounts.verify_password(accounts._DECOY, "") is False


def test_a_busy_hash_is_not_a_wrong_password(monkeypatch: pytest.MonkeyPatch) -> None:
    """The distinction the sign-in route depends on, held at its source.

    `verify_password` used to swallow the busy case and return False, so a capacity event
    was indistinguishable from a wrong credential and spent the account's lockout budget.
    It must RAISE, and it must raise something a caller can tell apart from an unreadable
    stored value, which still returns a verdict.
    """
    stored = accounts.hash_password(GOOD)

    def busy(*args: object, **kwargs: object) -> bytes:
        raise accounts.ServiceBusyError("no slot")

    monkeypatch.setattr(accounts, "_scrypt", busy)

    with pytest.raises(accounts.ServiceBusyError):
        accounts.verify_password(stored, GOOD)


def test_an_unreadable_stored_value_is_still_a_verdict() -> None:
    """The other half of the pair above: this one must NOT raise."""
    assert accounts.verify_password("not-a-stored-password", GOOD) is False
    assert accounts.verify_password("scrypt$n=notanumber,r=8,p=1$aaaa$bbbb", GOOD) is False


def test_absorb_timing_swallows_the_busy_case(monkeypatch: pytest.MonkeyPatch) -> None:
    """Raising here would make an absent account answer differently under load.

    Which is the enumeration oracle `absorb_timing` exists to close, so the one place the
    busy signal must NOT propagate is this one.
    """

    def busy(*args: object, **kwargs: object) -> bytes:
        raise accounts.ServiceBusyError("no slot")

    monkeypatch.setattr(accounts, "_scrypt", busy)

    accounts.absorb_timing()


# ============================ recovery codes ============================


def test_recovery_codes_are_issued_hashed_and_spent_once() -> None:
    codes, hashes = accounts.new_recovery_codes()
    account = {"recovery": list(hashes)}

    assert len(codes) == accounts.RECOVERY_CODES == len(set(codes))
    assert all(code not in "".join(hashes) for code in codes)
    assert accounts.spend_recovery_code(account, codes[0])
    assert len(account["recovery"]) == accounts.RECOVERY_CODES - 1
    assert not accounts.spend_recovery_code(account, codes[0])


@pytest.mark.parametrize("supplied", ["", "   ", None, 42, "not-a-real-code"])
def test_a_wrong_recovery_code_spends_nothing(supplied: object) -> None:
    _, hashes = accounts.new_recovery_codes()
    account = {"recovery": list(hashes)}

    assert accounts.spend_recovery_code(account, supplied) is False
    assert len(account["recovery"]) == accounts.RECOVERY_CODES


# ============================ lockout ============================


def test_an_account_locks_after_the_stated_number_of_failures() -> None:
    account = accounts.new_account("a@b.uk", GOOD)

    locked = [accounts.record_failure(account, now=0.0) for _ in range(accounts.MAXIMUM_FAILURES)]

    assert locked[-1] is True
    assert locked[:-1] == [False] * (accounts.MAXIMUM_FAILURES - 1)
    assert accounts.is_locked(account, now=0.0)
    assert not accounts.is_locked(account, now=accounts.LOCKOUT_SECONDS + 1)


def test_the_lock_is_time_bounded_and_not_permanent() -> None:
    """A permanent lock makes guessing a cheap way to deny a colleague access."""
    account = accounts.new_account("a@b.uk", GOOD)
    for _ in range(accounts.MAXIMUM_FAILURES):
        accounts.record_failure(account, now=0.0)

    assert accounts.may_sign_in(account, now=0.0) is False
    assert accounts.may_sign_in(account, now=accounts.LOCKOUT_SECONDS + 1) is True


@pytest.mark.parametrize("corrupt", ["later", None, [], {"a": 1}])
def test_an_unreadable_lock_field_reads_as_locked(corrupt: object) -> None:
    """Failing closed on a field an attacker would want to corrupt."""
    assert accounts.is_locked({"locked_until": corrupt}) is True


def test_a_disabled_account_cannot_sign_in() -> None:
    account = accounts.new_account("a@b.uk", GOOD)
    accounts.set_state(account, accounts.DISABLED)

    assert accounts.may_sign_in(account) is False


def test_may_sign_in_refuses_a_missing_account() -> None:
    assert accounts.may_sign_in(None) is False


# ============================ the file ============================


def test_an_absent_file_is_no_accounts(tmp_path: Path) -> None:
    assert accounts.load(str(tmp_path)) == []


def test_a_corrupt_file_raises_rather_than_reading_as_no_accounts(tmp_path: Path) -> None:
    """The sharpest edge in this module.

    An unreadable account list reading as "no accounts" would let the bootstrap path create
    a fresh administrator over a store that still holds real ones.
    """
    target = accounts.accounts_path(str(tmp_path))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{not json", encoding="utf-8")

    with pytest.raises(accounts.AccountError, match="could not be read"):
        accounts.load(str(tmp_path))


def test_a_list_that_is_not_a_list_is_refused(tmp_path: Path) -> None:
    target = accounts.accounts_path(str(tmp_path))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text('{"username": "a@b.uk"}', encoding="utf-8")

    with pytest.raises(accounts.AccountError, match="not a list"):
        accounts.load(str(tmp_path))


def test_a_saved_list_round_trips_and_is_owner_only(tmp_path: Path) -> None:
    rows = [accounts.new_account("a@b.uk", GOOD)]

    accounts.save(str(tmp_path), rows)

    assert accounts.load(str(tmp_path))[0]["username"] == "a@b.uk"
    assert accounts.accounts_path(str(tmp_path)).stat().st_mode & 0o077 == 0


def test_the_account_file_is_not_under_the_registers_directory(tmp_path: Path) -> None:
    """One directory separates a credential store from a disclosure.

    The evidence export globs `records/*.json`. An account file placed there would be
    swept into the pack an assessor receives, carrying every hash and every factor secret.
    """
    accounts.save(str(tmp_path), [accounts.new_account("a@b.uk", GOOD)])

    stored = accounts.accounts_path(str(tmp_path))

    assert stored.parent.name == accounts.ACCOUNTS_DIRNAME
    assert "records" not in stored.parts
    #: The export globs `DATA_DIR/records/*.json`. Nothing the account store writes may land
    #: there, or a password hash would leave the volume inside an exported register.
    assert list((tmp_path / "records").glob("*.json")) == []


def test_a_new_account_stores_no_plaintext(tmp_path: Path) -> None:
    accounts.save(str(tmp_path), [accounts.new_account("a@b.uk", GOOD)])

    raw = accounts.accounts_path(str(tmp_path)).read_text(encoding="utf-8")

    assert GOOD not in raw
    assert json.loads(raw)[0]["must_change_password"] is True


# ============================ roles ============================


def test_an_unknown_role_is_refused() -> None:
    with pytest.raises(accounts.AccountError, match="not a role"):
        accounts.new_account("a@b.uk", GOOD, role="SUPERUSER")


def test_the_enabled_administrators_are_counted() -> None:
    rows = [
        accounts.new_account("one@b.uk", GOOD, role=accounts.ADMIN),
        accounts.new_account("two@b.uk", GOOD, role=accounts.ADMIN),
        accounts.new_account("three@b.uk", GOOD),
    ]
    accounts.set_state(rows[1], accounts.DISABLED)

    assert [row["username"] for row in accounts.active_admins(rows)] == ["one@b.uk"]


def test_redacted_is_an_allowlist_and_carries_no_secret() -> None:
    """A denylist is one new field away from leaking it, and the next field is a secret."""
    account = accounts.new_account("a@b.uk", GOOD, role=accounts.ADMIN)
    accounts.begin_enrolment(account, token=accounts.new_enrolment_token())
    account["a_future_secret"] = "must not appear"  # noqa: S105 - the point of the test

    shown = accounts.redacted(account)

    assert set(shown) == {
        "username",
        "role",
        "state",
        "enrolled",
        "must_change_password",
        "locked",
        "recovery_remaining",
        "created",
        "updated",
    }
    assert "must not appear" not in json.dumps(shown)
    assert "scrypt" not in json.dumps(shown)


# ============================ the second factor ============================


def test_enrolment_is_two_steps_and_the_pending_secret_grants_nothing() -> None:
    """A secret shown but not confirmed cannot be used to sign in."""
    from directive import totp  # noqa: PLC0415 - only this test needs it

    account = accounts.new_account("a@b.uk", GOOD)
    token = accounts.new_enrolment_token()
    secret = accounts.begin_enrolment(account, token=token)

    assert not accounts.is_enrolled(account)
    assert not accounts.verify_code(account, totp.code_now(secret))

    codes = accounts.finish_enrolment(account, totp.code_now(secret), token=token)

    assert codes is not None
    assert accounts.is_enrolled(account)
    # And NOT the confirming code again: enrolment spends it. A later step's code works,
    # which is what says the factor is live rather than that every code is refused.
    assert not accounts.verify_code(account, totp.code_now(secret))
    later = time.time() + totp.STEP_SECONDS * 2
    assert accounts.verify_code(account, totp.code_now(secret, now=later), now=later)


# ============================ a one-time code is one-time ============================


def test_a_code_cannot_be_spent_twice() -> None:
    """RFC 6238 section 5.2, the one normative MUST NOT in the specification.

    This shipped broken: nothing recorded the counter, so one six-digit code signed in an
    unlimited number of fresh sessions for the ninety seconds the drift window spans, and a
    security gate demonstrated it three times over. The sibling control already had the
    property, which is what makes the omission a plain gap rather than a judgement call: a
    recovery code works once and there was no equivalent here.
    """
    from directive import totp  # noqa: PLC0415 - only this test needs it

    account = accounts.new_account("a@b.uk", GOOD)
    token = accounts.new_enrolment_token()
    secret = accounts.begin_enrolment(account, token=token)
    accounts.finish_enrolment(account, totp.code_now(secret), token=token)
    moment = time.time() + totp.STEP_SECONDS * 4
    code = totp.code_now(secret, now=moment)

    assert accounts.verify_code(account, code, now=moment) is True
    assert accounts.verify_code(account, code, now=moment) is False
    assert accounts.verify_code(account, code, now=moment + 1) is False


def test_a_code_from_earlier_in_the_window_is_refused_after_a_later_one() -> None:
    """Strictly greater, not merely different.

    The drift window spans three steps, so after a code from step N is accepted, the code
    for step N-1 is still arithmetically valid and still inside the window. A comparison
    that only refused an EQUAL counter would have let it through, which is a replay by
    another name.
    """
    from directive import totp  # noqa: PLC0415 - only this test needs it

    account = accounts.new_account("a@b.uk", GOOD)
    token = accounts.new_enrolment_token()
    secret = accounts.begin_enrolment(account, token=token)
    accounts.finish_enrolment(account, totp.code_now(secret), token=token)
    moment = time.time() + totp.STEP_SECONDS * 4
    earlier = totp.code_now(secret, now=moment - totp.STEP_SECONDS)

    assert accounts.verify_code(account, totp.code_now(secret, now=moment), now=moment) is True
    assert accounts.verify_code(account, earlier, now=moment) is False


def test_an_unreadable_counter_refuses_every_code() -> None:
    """Fails CLOSED. This is the field an attacker holding the volume would corrupt.

    Reading a bad counter as "never" would turn one corrupt value into an unlimited replay
    window, which is the opposite of what the field is for.
    """
    from directive import totp  # noqa: PLC0415 - only this test needs it

    account = accounts.new_account("a@b.uk", GOOD)
    token = accounts.new_enrolment_token()
    secret = accounts.begin_enrolment(account, token=token)
    accounts.finish_enrolment(account, totp.code_now(secret), token=token)
    account["totp_last_step"] = "not a number"

    moment = time.time() + totp.STEP_SECONDS * 4
    assert accounts.verify_code(account, totp.code_now(secret, now=moment), now=moment) is False
    assert accounts.last_step(account) == accounts.FAR_FUTURE_STEP


def test_resetting_the_factor_resets_the_counter() -> None:
    """The counter goes with the secret.

    A new secret produces unrelated codes, so a counter held against the old one would
    refuse good codes from the new device until the clock caught up with it, and on a
    corrupt value never.
    """
    from directive import totp  # noqa: PLC0415 - only this test needs it

    account = accounts.new_account("a@b.uk", GOOD)
    token = accounts.new_enrolment_token()
    secret = accounts.begin_enrolment(account, token=token)
    accounts.finish_enrolment(account, totp.code_now(secret), token=token)
    accounts.reset_factor(account)

    assert account["totp_last_step"] == accounts.NO_STEP

    fresh_token = accounts.new_enrolment_token()
    fresh = accounts.begin_enrolment(account, token=fresh_token)
    assert accounts.finish_enrolment(account, totp.code_now(fresh), token=fresh_token) is not None


def test_enrolment_with_a_wrong_code_confirms_nothing() -> None:
    account = accounts.new_account("a@b.uk", GOOD)
    token = accounts.new_enrolment_token()
    accounts.begin_enrolment(account, token=token)

    assert accounts.finish_enrolment(account, "000000", token=token) is None
    assert not accounts.is_enrolled(account)


def test_a_reset_factor_forces_re_enrolment_and_drops_recovery_codes() -> None:
    from directive import totp  # noqa: PLC0415 - only this test needs it

    account = accounts.new_account("a@b.uk", GOOD)
    token = accounts.new_enrolment_token()
    secret = accounts.begin_enrolment(account, token=token)
    accounts.finish_enrolment(account, totp.code_now(secret), token=token)

    accounts.reset_factor(account)

    assert not accounts.is_enrolled(account)
    assert account["recovery"] == []


def test_a_corrupted_factor_secret_refuses_rather_than_raising() -> None:
    assert accounts.verify_code({"totp_secret": "not!base32!"}, "123456") is False


def test_two_sign_ins_get_different_unguessable_enrolment_tokens() -> None:
    """A unique token that is SHORT is still guessable, which the route test cannot see.

    The route-level test refuses a second session the live secret, and a one-byte token
    would satisfy it while being guessable in a few hundred attempts. So the length is
    asserted here, at the source, alongside the uniqueness.

    Minted by `new_enrolment_token` rather than by `begin_enrolment`, because the token has
    to exist before the enrolment page can be loaded: created inside the page, it could
    never be in a replayed cookie and every replay minted a secret and wrote the credential
    store. See that function's own docstring for the measurement.
    """
    first = accounts.new_enrolment_token()
    second = accounts.new_enrolment_token()

    assert first != second, "two sign-ins shared a token"
    assert len(first) >= 43, f"a {len(first)}-character token is guessable"


def test_an_enrolment_secret_is_owned_by_the_token_it_was_minted_with() -> None:
    """The caller supplies the token, so the account records WHICH sign-in owns the secret."""
    account = accounts.new_account("a@b.uk", GOOD)
    mine, theirs = accounts.new_enrolment_token(), accounts.new_enrolment_token()

    secret = accounts.begin_enrolment(account, token=mine)

    assert accounts.pending_secret_for(account, mine) == secret
    assert accounts.pending_secret_for(account, theirs) == ""
    assert account["totp_pending_token"] == mine
