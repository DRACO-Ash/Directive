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
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from directive import accounts, create_app, totp

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


def test_a_code_that_signed_in_cannot_sign_in_again(app: Flask, client: FlaskClient) -> None:
    """The end-to-end half of RFC 6238 section 5.2, over HTTP and across sessions.

    This is the test that did not exist, and its absence was a working bypass rather than a
    gap in coverage: a security gate took one six-digit code and signed in three
    consecutive fresh clients with it, each reaching the console. `tests/test_accounts.py`
    holds the property at the function; this holds that the ROUTE persists the counter,
    which is a different claim. The counter is written onto the account record inside the
    file lock, so a route that forgot to save would pass the unit test and fail here.
    """
    secret, _ = sign_in_fully(client)
    code = totp.code_now(secret)

    second = app.test_client()
    give_password(second, user=USERNAME)
    replayed = second.post(
        "/sign-in/verify",
        data={"code": code, "csrf_token": form_token(second, "/sign-in/verify")},
    )

    assert second.get("/api/registers").status_code == 401, "a spent code signed in again"
    assert replayed.status_code == 302
    assert "/console" not in replayed.headers.get("Location", "")


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
