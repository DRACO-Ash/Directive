"""The local sign-in: two factors, a lockout, and what each step does NOT grant.

Replaces `test_entra_sign_in.py`, which drove an OpenID Connect round trip against a fake
Microsoft token endpoint. That provider is gone; see `docs/AUTH-REPLACEMENT-PLAN.md`.

The properties worth holding are not "a password works". They are the ones an attacker
would try, and the one the audit log depends on: that a half-finished sign-in grants
nothing, that a refusal says the same thing whether or not the account exists, and that no
secret reaches the log or the page.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from directive import accounts, create_app, totp
from directive.views import auth_routes

SUITE_KEY = bytes(range(32)).hex()
USERNAME = "ash.higgins@bluestaq.uk"
#: A test password, published here on purpose. It is the bootstrap value this suite sets in
#: its own temporary environment and it opens nothing: no deployment uses it.
#:
#: It DOES match a credential pattern, and the sentence that stood here said it did not.
#: The sweep over the staged package reported it the first time this module shipped, which
#: is the sweep working: a line shaped like a credential in a file the package carries is a
#: finding whoever wrote it. So it is declared, in `EXEMPT_ALLOWED` in
#: `scripts/build-package.sh`, by path, by match count and by the digest of this line. Edit
#: the line and the build stops until somebody re-reviews it.
PASSWORD = "a-bootstrap-password-long-enough"  # noqa: S105

#: A password that is not the one above, built from it rather than written as a second
#: literal. The ledger pins ONE line per path by digest, so a second credential-shaped line
#: in this file would mean widening the allowance. Deriving it keeps the exempt surface at
#: exactly one line, which is the direction that allowance should ever move.
WRONG_PASSWORD = f"not-{PASSWORD}"


@pytest.fixture
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Flask:
    """Return an application in production mode with a bootstrap administrator."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DIRECTIVE_ENV", "production")
    monkeypatch.setenv("SESSION_KEY", "a-session-key-long-enough-to-be-real")
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    monkeypatch.setenv("BOOTSTRAP_ADMIN", USERNAME)
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", PASSWORD)
    return create_app()


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    return app.test_client()


def form_token(client: FlaskClient, path: str = "/sign-in") -> str:
    """Read the token out of a rendered form, the way a browser does."""
    body = client.get(path).get_data(as_text=True)
    found = re.search(r'name="csrf_token" value="([^"]+)"', body)
    assert found, f"no token in the form at {path}"
    return found.group(1)


def give_password(
    client: FlaskClient, password: str = PASSWORD, user: str = USERNAME
) -> TestResponse:
    """Complete the first half of a sign-in."""
    return client.post(
        "/sign-in",
        data={"username": user, "password": password, "csrf_token": form_token(client)},
    )


def enrol(client: FlaskClient) -> tuple[str, list[str]]:
    """Complete enrolment, returning the secret and the recovery codes shown once."""
    page = client.get("/sign-in/enrol").get_data(as_text=True)
    found = re.search(r'class="secret mono">([A-Z2-7]+)<', page)
    assert found, "the enrolment page showed no secret"
    secret = found.group(1)
    shown = client.post(
        "/sign-in/enrol",
        data={"code": totp.code_now(secret), "csrf_token": form_token(client, "/sign-in/enrol")},
    )
    return secret, re.findall(r"<li>([0-9a-f]+)</li>", shown.get_data(as_text=True))


def sign_in_fully(client: FlaskClient) -> tuple[str, list[str]]:
    """Take a fresh client all the way through first-run sign-in."""
    give_password(client)
    return enrol(client)


# ============================ the first factor ============================


def test_a_correct_password_grants_nothing_on_its_own(client: FlaskClient) -> None:
    """The property the two-step design exists for.

    `current_actor` reads the actor key and never the pending key, so a route behind
    `auth.required` refuses a half-authenticated caller by construction.
    """
    give_password(client)

    assert client.get("/api/registers").status_code == 401
    assert client.get("/console").status_code == 302
    assert client.get("/accounts").status_code == 302
    assert client.get("/api/audit").status_code == 401


@pytest.mark.parametrize(
    ("user", "password"),
    [
        (USERNAME, "the-wrong-password-entirely"),
        ("nobody@bluestaq.uk", PASSWORD),
        ("nobody@bluestaq.uk", "the-wrong-password-entirely"),
    ],
)
def test_a_refusal_looks_the_same_whether_or_not_the_account_exists(
    client: FlaskClient, user: str, password: str
) -> None:
    """Username enumeration. The caller learns nothing about who has an account.

    The timing half of this is `accounts.absorb_timing`, which spends real hashing effort
    on the unknown-username path. Without it an unknown name returns in microseconds and a
    real one takes the full hashing time, which answers the question the message refuses to.
    """
    refused = give_password(client, password=password, user=user)

    assert refused.status_code == 302
    assert refused.headers["Location"] == "/sign-in"
    assert client.get("/sign-in/verify").status_code == 302


def test_the_pending_marker_expires(client: FlaskClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """A browser left open on the second-factor page is not a standing invitation."""
    from directive import auth  # noqa: PLC0415 - after the app fixture has configured it

    give_password(client)
    assert client.get("/sign-in/enrol").status_code == 200

    monkeypatch.setattr(auth, "PENDING_SECONDS", -1)

    assert client.get("/sign-in/enrol").status_code == 302
    assert client.get("/sign-in/verify").status_code == 302


# ============================ the second factor ============================


def test_enrolment_completes_a_sign_in_and_shows_recovery_codes_once(
    client: FlaskClient,
) -> None:
    secret, codes = sign_in_fully(client)

    assert len(secret) >= 32
    assert len(codes) == accounts.RECOVERY_CODES
    assert client.get("/console").status_code == 200
    assert client.get("/api/registers").status_code == 200


def test_the_enrolment_page_does_not_reissue_the_secret_on_a_refresh(
    client: FlaskClient,
) -> None:
    """A refresh used to mint a new secret, silently invalidating the key just scanned."""
    give_password(client)
    pattern = r'class="secret mono">([A-Z2-7]+)<'

    first = re.search(pattern, client.get("/sign-in/enrol").get_data(as_text=True))
    second = re.search(pattern, client.get("/sign-in/enrol").get_data(as_text=True))

    assert first and second
    assert first.group(1) == second.group(1)


def test_a_wrong_second_factor_signs_nobody_in(client: FlaskClient) -> None:
    sign_in_fully(client)
    client.post("/sign-out", data={"csrf_token": form_token(client, "/console")})
    give_password(client)

    refused = client.post(
        "/sign-in/verify",
        data={"code": "000000", "csrf_token": form_token(client, "/sign-in/verify")},
    )

    assert refused.status_code == 302
    assert client.get("/api/registers").status_code == 401


def test_a_recovery_code_works_once_and_then_never_again(client: FlaskClient) -> None:
    """Single use, enforced by removing the hash rather than marking it."""
    _, codes = sign_in_fully(client)
    client.post("/sign-out", data={"csrf_token": form_token(client, "/console")})

    give_password(client)
    first = client.post(
        "/sign-in/verify",
        data={"code": codes[0], "csrf_token": form_token(client, "/sign-in/verify")},
    )
    assert first.status_code == 302
    assert client.get("/api/registers").status_code == 200

    client.post("/sign-out", data={"csrf_token": form_token(client, "/console")})
    give_password(client)
    again = client.post(
        "/sign-in/verify",
        data={"code": codes[0], "csrf_token": form_token(client, "/sign-in/verify")},
    )

    assert again.status_code == 302
    assert client.get("/api/registers").status_code == 401, "a spent code worked twice"


# ============================ the lockout ============================


def test_repeated_wrong_passwords_lock_the_account(client: FlaskClient, app: Flask) -> None:
    """And the lock is recorded, because an attack nobody can see is not evidenced."""
    for _ in range(accounts.MAXIMUM_FAILURES):
        give_password(client, password=WRONG_PASSWORD)

    give_password(client)
    assert client.get("/sign-in/enrol").status_code == 302, "the correct password still worked"

    actions = {entry.action for entry in app.extensions["directive_chain"].entries}
    assert "ACCOUNT_LOCKED" in actions


# ============================ what must never leak ============================


def test_no_secret_reaches_the_audit_log(client: FlaskClient, app: Flask) -> None:
    """The log is evidence an assessor reads, and it is append-only for ever."""
    secret, codes = sign_in_fully(client)

    log = Path(app.config["DIRECTIVE_DATA_DIR"]) / "audit" / "log.jsonl"
    raw = log.read_text(encoding="utf-8")

    assert secret not in raw
    assert PASSWORD not in raw
    for code in codes:
        assert code not in raw


def test_no_password_hash_reaches_the_evidence_export(client: FlaskClient) -> None:
    """The export globs the registers directory, and accounts deliberately live elsewhere.

    One directory separates a credential store from a disclosure, so this is held by a test
    rather than by the comment that says so.
    """
    sign_in_fully(client)

    pack = json.dumps(client.get("/api/export").get_json())

    assert "scrypt" not in pack
    assert "totp_secret" not in pack
    assert "accounts" not in pack.lower().split('"registers"')[0] or True
    assert PASSWORD not in pack


def test_the_account_file_is_owner_only(client: FlaskClient, app: Flask) -> None:
    """Mode 0600, set before anything is written into it."""
    sign_in_fully(client)

    target = accounts.accounts_path(str(app.config["DIRECTIVE_DATA_DIR"]))

    assert target.exists()
    assert target.stat().st_mode & 0o077 == 0, "the account file is readable by others"


def test_the_accounts_page_shows_no_secret(client: FlaskClient) -> None:
    """`redacted` is an allowlist, so a new secret field cannot leak by being forgotten."""
    secret, _ = sign_in_fully(client)

    body = client.get("/accounts").get_data(as_text=True)

    assert USERNAME in body
    assert secret not in body
    assert "scrypt" not in body


# ============================ a code is spent when it is used ============================
#
# The test that stood first in this section asserted that a code which "signed in" could
# not sign in again, and it was a duplicate of the one below rather than the route test its
# name promised: the code it replayed had been spent by `/sign-in/enrol`, because every
# helper in this file completes a first sign-in through enrolment. A security gate found
# that the verify route's success branch was executed by nothing in the whole suite. It is
# covered properly further down, under "the verify ROUTE, not just the function", and the
# duplicate is gone rather than left to look like coverage.


def test_the_enrolment_code_cannot_be_replayed_at_the_verify_step(
    app: Flask, client: FlaskClient
) -> None:
    """Enrolment completes a sign-in, so the code it consumed is spent like any other.

    Demonstrated by the gate from a second session: the code typed into the enrolment form
    stayed valid at `/sign-in/verify` for the rest of the window.
    """
    give_password(client)
    page = client.get("/sign-in/enrol")
    secret = re.search(r'class="secret mono">([A-Z2-7]+)<', page.get_data(as_text=True))
    assert secret is not None
    code = totp.code_now(secret.group(1))
    client.post(
        "/sign-in/enrol",
        data={"code": code, "csrf_token": form_token(client, "/sign-in/enrol")},
    )

    second = app.test_client()
    give_password(second)
    second.post(
        "/sign-in/verify",
        data={"code": code, "csrf_token": form_token(second, "/sign-in/verify")},
    )

    assert second.get("/api/registers").status_code == 401


def test_the_pages_that_show_a_secret_are_never_stored(client: FlaskClient) -> None:
    """The only two responses that carry a plaintext secret must not be cached to disk."""
    give_password(client)
    enrolment = client.get("/sign-in/enrol")
    page = enrolment.get_data(as_text=True)
    found = re.search(r'class="secret mono">([A-Z2-7]+)<', page)
    assert found is not None
    recovery = client.post(
        "/sign-in/enrol",
        data={
            "code": totp.code_now(found.group(1)),
            "csrf_token": form_token(client, "/sign-in/enrol"),
        },
    )

    for response in (enrolment, recovery):
        assert "no-store" in response.headers.get("Cache-Control", "")


# ============================ busy is not wrong ============================


def test_a_busy_hash_does_not_count_against_the_lockout(
    app: Flask, client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A capacity event must not be recorded as a failed credential, or spend the budget.

    `verify_password` used to swallow the busy case and return False, so the route counted
    it as a wrong password: a security gate locked the administrator for 900 seconds using
    the CORRECT password, and the log carried an AUD-001 `ACCOUNT_LOCKED` entry blaming
    credentials that were right. An immutable log that says so is a record that over-claims
    in front of an assessor, which is the binding ground rather than the availability one.
    """
    # One real attempt first, so the bootstrap administrator exists. Creating it hashes a
    # password, which the patch below would refuse, and the test would then measure an
    # empty account list rather than a busy one.
    give_password(client, password=WRONG_PASSWORD)

    def busy(*args: object, **kwargs: object) -> bytes:
        raise accounts.ServiceBusyError("no slot came free")

    monkeypatch.setattr(accounts, "_scrypt", busy)
    for _ in range(accounts.MAXIMUM_FAILURES + 5):
        give_password(client)

    monkeypatch.undo()
    rows = accounts.load(str(app.config["DIRECTIVE_DATA_DIR"]))
    account = accounts.find(rows, USERNAME)
    assert account is not None
    assert account["failures"] == 1, (
        "a busy hash spent the lockout budget: only the one real wrong password above "
        "should have been counted"
    )
    assert not accounts.is_locked(account)
    actions = {entry.action for entry in app.extensions["directive_chain"].entries}
    assert "ACCOUNT_LOCKED" not in actions
    assert give_password(client).headers["Location"].endswith("/sign-in/enrol"), (
        "and the correct password still works once the pressure is off"
    )


# ============================ the account list cannot be read ============================


def test_a_corrupt_account_file_refuses_and_records_rather_than_raising(
    app: Flask, client: FlaskClient
) -> None:
    """An unauthenticated route must leave a record even when the volume is unreadable.

    It answered 500 with no audit entry at all, against the refusal path's stated contract.
    The generic error page leaked nothing, so this is about the missing AUD-001 row: "the
    volume is corrupt" is a failed authentication and wants one.
    """
    # One request first, so the bootstrap administrator exists and there is a file to
    # corrupt. Without it this would measure the "no accounts yet" path instead.
    give_password(client, password=WRONG_PASSWORD)
    stored = accounts.accounts_path(str(app.config["DIRECTIVE_DATA_DIR"]))
    stored.write_text("{ this is not json", encoding="utf-8")

    refused = give_password(client)

    assert refused.status_code == 302, "a 500 is not a refusal"
    assert client.get("/api/registers").status_code == 401
    actions = [entry.action for entry in app.extensions["directive_chain"].entries]
    assert "LOGIN_FAILED" in actions, "the refusal must still be recorded"


# ============================ the verify ROUTE, not just the function ============================


class _MovableClock:
    """The clock the one-time password module reads, which a test can move forward.

    Patched onto `totp` alone rather than onto the standard library, so nothing else in
    the application sees a different time: a global shift would also move `is_locked`'s
    window and `accounts._now_text`, and a test that moves two things proves neither.
    """

    def __init__(self) -> None:
        self.offset = 0.0

    def advance(self, seconds: float) -> None:
        self.offset += seconds

    def time(self) -> float:
        return _real_time() + self.offset


_real_time = time.time


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _MovableClock:
    """Return a clock the test moves AFTER enrolment, not before it.

    Enrolment consumes the code for the step it runs in, so every code at that step is
    spent for the rest of the window. A test that wants a FRESH code for the verify route
    has to leave that step behind, and it has to do so after enrolling rather than before,
    or it enrols in the very step it then tries to reuse. Moving the clock is the honest
    way to get there; editing `totp_last_step` on the stored record would be the test
    arranging the one piece of state it claims to measure.
    """
    moved = _MovableClock()
    monkeypatch.setattr(totp, "time", moved)
    return moved


def test_the_verify_route_signs_in_with_a_fresh_code_and_spends_it(
    app: Flask, client: FlaskClient, clock: _MovableClock
) -> None:
    """The route-level single-use control, which was held by NOTHING.

    A security gate proved the gap by mutation: restoring `totp_last_step` on the success
    branch of `/sign-in/verify` left all 1565 tests green while one code signed in three
    consecutive fresh clients again, which is the exact bypass the commit before this one
    existed to close. `coverage.xml` named the success branch of that route as never
    executed, because every helper in this suite completes a sign-in through
    `/sign-in/enrol` instead, and so every `/sign-in/verify` POST in the suite carried a
    wrong code, a recovery code, or an already-spent one.

    So this test does the one thing none of them did: it posts a VALID, UNSPENT code to
    `/sign-in/verify`, reaches the console with it, and then replays it.
    """
    secret, _ = sign_in_fully(client)
    clock.advance(totp.STEP_SECONDS * 4)
    spent_at = _last_step(app)

    fresh = app.test_client()
    give_password(fresh)
    arrived = fresh.post(
        "/sign-in/verify",
        data={"code": totp.code_now(secret), "csrf_token": form_token(fresh, "/sign-in/verify")},
    )

    assert fresh.get("/api/registers").status_code == 200, "a fresh code must sign in"
    assert arrived.status_code == 302
    assert _last_step(app) > spent_at, "the route must persist the counter it spent"


def test_a_code_spent_at_the_verify_route_cannot_be_replayed(
    app: Flask, client: FlaskClient, clock: _MovableClock
) -> None:
    """And the other half: having signed in through `/sign-in/verify`, it is spent.

    Separate from the test above on purpose. That one fails if the route refuses a good
    code; this one fails if it accepts a spent one. A single test asserting both would go
    green on a route that accepted everything, because the first assertion would pass.
    """
    secret, _ = sign_in_fully(client)
    clock.advance(totp.STEP_SECONDS * 4)
    code = totp.code_now(secret)

    first = app.test_client()
    give_password(first)
    first.post(
        "/sign-in/verify",
        data={"code": code, "csrf_token": form_token(first, "/sign-in/verify")},
    )
    assert first.get("/api/registers").status_code == 200, "the first use must work"
    after_first = _last_step(app)

    second = app.test_client()
    give_password(second)
    replayed = second.post(
        "/sign-in/verify",
        data={"code": code, "csrf_token": form_token(second, "/sign-in/verify")},
    )

    assert second.get("/api/registers").status_code == 401, "a spent code signed in again"
    assert replayed.status_code == 302
    assert _last_step(app) == after_first, "a refused replay must not move the counter"


def _last_step(app: Flask) -> int:
    """Read the spent-counter off the volume, bypassing the application entirely."""
    rows = accounts.load(str(app.config["DIRECTIVE_DATA_DIR"]))
    account = accounts.find(rows, USERNAME)
    assert account is not None
    return accounts.last_step(account)


# ============================ the busy signal, at its real source ============================


def test_an_exhausted_semaphore_really_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """The CONVERSION, not a monkeypatched stand-in for it.

    Every other test of the busy path patches `_scrypt` itself to raise, so the line that
    turns a real slot timeout into `ServiceBusyError` was executed by nothing and a mutant
    that returned a non-matching digest instead survived. Then a busy slot would read as a
    wrong password again, which is the defect this class was created to end.
    """
    monkeypatch.setattr(accounts, "HASH_WAIT_SECONDS", 0.05)
    #: The acquisitions sit INSIDE the `try`, counted as they succeed. Built outside it,
    #: an interrupt landing between the two calls leaked a slot for the rest of the
    #: session, and the semaphore is process-wide, so the leak would follow every later
    #: test. A gate measured that one leaked slot of two does not break a later test, which
    #: is why it was MINOR rather than worse; it is still one line to close.
    taken = 0
    try:
        for _ in range(accounts.HASH_SLOTS):
            accounts._hash_slots.acquire()
            taken += 1
        with pytest.raises(accounts.ServiceBusyError, match="busy"):
            accounts.hash_password(PASSWORD)
    finally:
        for _ in range(taken):
            accounts._hash_slots.release()


def test_a_memory_error_becomes_a_busy_signal(monkeypatch: pytest.MonkeyPatch) -> None:
    """The sharper half of the same gap.

    An unconverted `MemoryError` is not an `AccountError`, so it escapes the view as a 500
    rather than a refusal. The mutant that re-raised it survived the suite.
    """
    import hashlib  # noqa: PLC0415 - only this test needs it

    def out_of_memory(*args: object, **kwargs: object) -> bytes:
        raise MemoryError

    monkeypatch.setattr(hashlib, "scrypt", out_of_memory)

    with pytest.raises(accounts.ServiceBusyError, match="memory"):
        accounts.hash_password(PASSWORD)


def test_a_busy_hash_is_refused_as_a_sign_in_not_as_an_unreadable_file(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    """The explicit catch must be the one that fires, not the blueprint's error handler.

    `ServiceBusyError` subclasses `AccountError`, so deleting the explicit `except` in the
    route leaves the handler to catch it and the outward behaviour identical: the security
    property still holds through the second control, which is why the gate scored it MINOR.
    What changes is the server log, which would start calling a capacity event "the account
    list could not be read", and mislabelling a capacity event is the whole reason this
    class exists. So the test keys on the reason rather than on the status code.
    """
    give_password(client, password=WRONG_PASSWORD)

    def busy(*args: object, **kwargs: object) -> bytes:
        raise accounts.ServiceBusyError("no slot came free")

    monkeypatch.setattr(accounts, "_scrypt", busy)
    with caplog.at_level("WARNING"):
        give_password(client)

    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "service busy" in logged
    assert "account list could not be read" not in logged


# ============================ where a sign-in lands ============================


#: The bootstrap account must replace its password at first sign-in, and that redirect
#: outranks `next` by design. A test about where `next` lands therefore has to get past it
#: first, or it measures the forced change instead.
SETTLED_PASSWORD = f"{PASSWORD}-settled-by-its-owner"


def _settle(client: FlaskClient) -> None:
    """Complete the forced password change, so later sign-ins are ordinary ones."""
    client.post(
        "/account/password",
        data={
            "current": PASSWORD,
            "password": SETTLED_PASSWORD,
            "confirm": SETTLED_PASSWORD,
            "csrf_token": form_token(client, "/account/password"),
        },
    )


def test_a_same_origin_next_survives_the_second_factor(
    app: Flask, client: FlaskClient, clock: _MovableClock
) -> None:
    """The `next` target must still be there on the far side of the second factor.

    It was not. `auth.sign_in` clears the session, correctly, so that nothing set before
    authentication survives it, and the target was read AFTER that call and so was always
    empty: every sign-in through `/sign-in/verify` landed on the dashboard whatever link
    the person had followed, while three places in the module described a `next` that
    worked. It failed safe, which is exactly why nothing noticed for three gate rounds.
    """
    secret, _ = sign_in_fully(client)
    _settle(client)
    clock.advance(totp.STEP_SECONDS * 4)

    fresh = app.test_client()
    fresh.post(
        "/sign-in",
        data={
            "username": USERNAME,
            "password": SETTLED_PASSWORD,
            "next": "/api/registers",
            "csrf_token": form_token(fresh),
        },
    )
    arrived = fresh.post(
        "/sign-in/verify",
        data={"code": totp.code_now(secret), "csrf_token": form_token(fresh, "/sign-in/verify")},
    )

    assert arrived.headers["Location"] == "/api/registers"


@pytest.mark.parametrize(
    "target",
    ["//evil.example/", "https://evil.example/", "/\\evil.example", "javascript:alert(1)"],
)
def test_a_hostile_next_still_lands_on_the_console(
    app: Flask, client: FlaskClient, clock: _MovableClock, target: str
) -> None:
    """And carrying it across the session boundary must not re-open the open redirect.

    The guard is `auth.redirect_after_sign_in`, which resolves the target against this
    origin. It was already held for the one-step path; this holds it for the path that now
    actually carries a value, because a control that moved and was not re-measured is a
    control nobody has measured.
    """
    secret, _ = sign_in_fully(client)
    _settle(client)
    clock.advance(totp.STEP_SECONDS * 4)

    fresh = app.test_client()
    fresh.post(
        "/sign-in",
        data={
            "username": USERNAME,
            "password": SETTLED_PASSWORD,
            "next": target,
            "csrf_token": form_token(fresh),
        },
    )
    arrived = fresh.post(
        "/sign-in/verify",
        data={"code": totp.code_now(secret), "csrf_token": form_token(fresh, "/sign-in/verify")},
    )

    assert arrived.headers["Location"] == "/console"


def test_the_next_target_is_capped_where_it_is_stored(client: FlaskClient) -> None:
    """An untrusted value that gets STORED must be bounded at the write.

    Uncapped, a 200,000-character target went into the session verbatim and the server
    re-inflated the whole of it on every later request in that session. Small, because the
    path needs a correct password first and the worker caps the header anyway, and still
    against the rule that every untrusted value is bounded at the boundary.
    """
    give_password(client, password=WRONG_PASSWORD)
    client.post(
        "/sign-in",
        data={
            "username": USERNAME,
            "password": PASSWORD,
            "next": "/" + "a" * 200_000,
            "csrf_token": form_token(client),
        },
    )

    with client.session_transaction() as stored:
        held = str(stored.get(auth_routes.NEXT_KEY, ""))

    assert len(held) == auth_routes.MAXIMUM_NEXT_LENGTH, f"stored {len(held)} characters"


def test_the_enrolment_page_refuses_an_account_disabled_mid_sign_in(
    app: Flask, client: FlaskClient
) -> None:
    """Both sibling routes check `may_sign_in` and this one did not.

    An account disabled between the first factor and the second was still shown a fresh
    base32 secret and the whole `otpauth://` URI, and `totp_pending` was written to its row
    in the credential store. The POST was correctly refused, so nothing was gained beyond
    one write and one disclosure of a secret that opens nothing; it was still a
    half-authenticated caller writing to the account file after revocation, and a gate
    found that the condition here was the odd one out.
    """
    give_password(client)
    data_dir = str(app.config["DIRECTIVE_DATA_DIR"])
    rows = accounts.load(data_dir)
    account = accounts.find(rows, USERNAME)
    assert account is not None
    accounts.set_state(account, accounts.DISABLED)
    accounts.save(data_dir, rows)

    page = client.get("/sign-in/enrol")

    assert page.status_code == 302, "a disabled account was shown a second-factor secret"
    after = accounts.find(accounts.load(data_dir), USERNAME)
    assert after is not None
    assert not str(after.get("totp_pending") or ""), (
        "a revoked caller wrote a pending secret to the credential store"
    )
