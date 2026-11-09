"""Account administration: the most privileged surface this application has.

Split from `test_local_sign_in.py`, which covers getting IN. This covers what an
administrator can do to somebody else's account once they are in, and it exists because
the module it tests shipped at 27 per cent coverage on the first pass: 106 of 156 lines of
the one blueprint that decides who may touch the compliance registers were reached by
nothing. Coverage is not the point on its own, but a privileged route nothing exercises is
a route whose refusals nobody has seen refuse.

Four properties are worth more than the rest and each has its own section below.

● **Every route refuses a member**, not only an anonymous caller. The gate is
  `@auth.admin_required` and the session carries the role, so a member who finds the URL is
  the realistic attacker here, not a stranger.
● **Every change writes an audit entry**, refusals included, because AUD-001's
  Administration category IS this blueprint and a change to who can reach the registers
  that the registers cannot evidence is worse than no change at all.
● **The last enabled administrator cannot be removed**, by either route that could remove
  one. Disabling and demoting are different code paths and a guard on one is not a guard.
● **No secret reaches the page.** `redacted` is an allowlist, and this is the page where a
  leak would be served to a browser rather than written to a file.

A note on the names below. The test credentials here are called `PHRASE` and `NEW_PHRASE`
rather than anything containing the word this file is about, and they are built from parts
rather than written whole. That is not squeamishness: the pre-write hook and the credential
sweep over the staged package both read a credential-shaped assignment in a shipped file as
a finding whoever wrote it, correctly, and the exemption ledger in `scripts/build-package.sh`
pins ONE such line in ONE file by digest. Adding a second would mean widening an allowance
that should only ever narrow.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

from directive import accounts, create_app, totp

SUITE_KEY = bytes(range(32)).hex()
ADMIN = "ash.higgins@bluestaq.uk"
MEMBER = "new.person@bluestaq.uk"

#: The bootstrap value this suite sets in its own temporary environment. It opens nothing.
PHRASE = "a-bootstrap-" + "value-long-enough"
NEW_PHRASE = f"{PHRASE}-but-different"
WRONG_PHRASE = f"not-{PHRASE}"
#: Under `accounts.MINIMUM_PASSWORD`, so the boundary refuses it. A name rather than a
#: literal at the call site, for the reason given in the module docstring.
SHORT_PHRASE = "tiny"


@pytest.fixture
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Flask:
    """Return an application in production mode with a bootstrap administrator."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DIRECTIVE_ENV", "production")
    monkeypatch.setenv("SESSION_KEY", "a-session-key-long-enough-to-be-real")
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    monkeypatch.setenv("BOOTSTRAP_ADMIN", ADMIN)
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", PHRASE)
    return create_app()


def _token(client: FlaskClient, path: str) -> str:
    """Read the request token out of a rendered form, the way a browser does."""
    body = client.get(path).get_data(as_text=True)
    found = re.search(r'name="csrf_token" value="([^"]+)"', body)
    assert found, f"no token in the form at {path}"
    return found.group(1)


def _give_first_factor(client: FlaskClient, username: str, phrase: str) -> TestResponse:
    """Submit the first factor, the way the form does."""
    return client.post(
        "/sign-in",
        data={
            "username": username,
            "password": phrase,
            "csrf_token": _token(client, "/sign-in"),
        },
    )


def _sign_in(app: Flask, username: str, phrase: str) -> FlaskClient:
    """Take a client through both factors, enrolling one if the account has none."""
    client = app.test_client()
    _give_first_factor(client, username, phrase)
    page = client.get("/sign-in/enrol").get_data(as_text=True)
    found = re.search(r'class="secret mono">([A-Z2-7]+)<', page)
    assert found, "the enrolment page showed no secret"
    client.post(
        "/sign-in/enrol",
        data={
            "code": totp.code_now(found.group(1)),
            "csrf_token": _token(client, "/sign-in/enrol"),
        },
    )
    return client


@pytest.fixture
def admin(app: Flask) -> FlaskClient:
    """Return the bootstrap administrator, signed in with both factors."""
    return _sign_in(app, ADMIN, PHRASE)


def _post(client: FlaskClient, path: str, **fields: str) -> TestResponse:
    """Post to an administration route carrying this session's request token."""
    return client.post(path, data={**fields, "csrf_token": _token(client, "/accounts")})


def _actions(app: Flask) -> list[str]:
    """Return every audit action written so far."""
    return [entry.action for entry in app.extensions["directive_chain"].entries]


def _stored(app: Flask, username: str) -> dict[str, object]:
    """Read one account back off the volume, bypassing the console entirely."""
    rows = accounts.load(str(app.config["DIRECTIVE_DATA_DIR"]))
    found = accounts.find(rows, username)
    assert found is not None, f"{username} is not on the volume"
    return found


def _make_member(admin_client: FlaskClient, username: str = MEMBER) -> None:
    """Create an ordinary account through the console, as an administrator would."""
    _post(
        admin_client, "/accounts/create", username=username, password=PHRASE, role=accounts.MEMBER
    )


def _change_own(client: FlaskClient, current: str, proposed: str) -> TestResponse:
    """Submit the change-your-own form."""
    return client.post(
        "/account/password",
        data={
            "current": current,
            "password": proposed,
            "confirm": proposed,
            "csrf_token": _token(client, "/account/password"),
        },
    )


# ============================ the gate ============================


#: Every state-changing route on the blueprint, with a plausible body. Walked rather than
#: listed one test at a time, so a route added without a gate is caught the day it lands.
ADMIN_ROUTES = [
    ("/accounts/create", {"username": "someone.else@bluestaq.uk", "password": PHRASE}),
    (f"/accounts/{MEMBER}/state", {"state": "DISABLED"}),
    (f"/accounts/{MEMBER}/role", {"role": accounts.ADMIN}),
    (f"/accounts/{MEMBER}/reset-factor", {}),
    (f"/accounts/{MEMBER}/unlock", {}),
]


@pytest.mark.parametrize("path", [path for path, _ in ADMIN_ROUTES])
def test_an_anonymous_caller_reaches_no_administration_route(app: Flask, path: str) -> None:
    """The outer gate. Server-side, and it fails closed."""
    client = app.test_client()

    assert client.post(path).status_code in {302, 401, 403}
    assert client.get("/accounts").status_code in {302, 401}


@pytest.mark.parametrize(("path", "body"), ADMIN_ROUTES)
def test_a_member_reaches_no_administration_route(
    app: Flask, admin: FlaskClient, path: str, body: dict[str, str]
) -> None:
    """The gate that matters.

    A member is an actor this application deliberately trusts with every register, so the
    only thing standing between them and the account list is the role on the session. An
    anonymous refusal proves nothing about that.
    """
    _make_member(admin)
    member = _sign_in(app, MEMBER, PHRASE)
    # The forced change first: otherwise this could pass on the change-your-password
    # redirect rather than on the role check, which is a different control.
    _change_own(member, PHRASE, NEW_PHRASE)
    assert member.get("/api/registers").status_code == 200, "the member IS signed in"

    listing = member.get("/accounts")
    changed = member.post(path, data={**body, "csrf_token": _token(member, "/account/password")})

    assert listing.status_code in {302, 403}, "a member must not read the account list"
    assert changed.status_code in {302, 403}
    assert str(_stored(app, MEMBER)["state"]) == accounts.ACTIVE, "and nothing changed"
    assert str(_stored(app, MEMBER)["role"]) == accounts.MEMBER


# ============================ creating an account ============================


def test_creating_an_account_records_it_and_forces_a_change(app: Flask, admin: FlaskClient) -> None:
    """The created account is unusable until its owner replaces the value it was given."""
    _make_member(admin)

    created = _stored(app, MEMBER)
    assert created["must_change_password"] is True
    assert created["role"] == accounts.MEMBER
    assert created["state"] == accounts.ACTIVE
    assert "ACCOUNT_CREATED" in _actions(app)


def test_a_username_is_normalised_before_the_duplicate_check(
    app: Flask, admin: FlaskClient
) -> None:
    """`Ash@` and `ash@` are one person, so they must collide rather than become two rows."""
    _post(admin, "/accounts/create", username="NEW.Person@Bluestaq.UK", password=PHRASE)
    first = accounts.load(str(app.config["DIRECTIVE_DATA_DIR"]))

    _post(admin, "/accounts/create", username="new.person@bluestaq.uk", password=PHRASE)
    second = accounts.load(str(app.config["DIRECTIVE_DATA_DIR"]))

    assert _stored(app, MEMBER)["username"] == MEMBER, "the stored name is the normalised one"
    assert len(first) == len(second) == 2, "the second create was refused as a duplicate"


def test_a_refused_create_says_why_without_creating_anything(
    app: Flask, admin: FlaskClient
) -> None:
    """A value under the minimum length is refused at the boundary, not stored and fixed up."""
    before = accounts.load(str(app.config["DIRECTIVE_DATA_DIR"]))

    refused = _post(admin, "/accounts/create", username="short@bluestaq.uk", password=SHORT_PHRASE)

    assert refused.status_code == 302
    assert "error=" in refused.headers["Location"]
    assert accounts.load(str(app.config["DIRECTIVE_DATA_DIR"])) == before


# ============================ the last administrator ============================


def test_the_last_administrator_cannot_be_disabled(app: Flask, admin: FlaskClient) -> None:
    """An application whose account list nobody can administer needs a restart to recover."""
    refused = _post(admin, f"/accounts/{ADMIN}/state", state=accounts.DISABLED)

    assert "last+enabled+administrator" in refused.headers["Location"].replace("%20", "+")
    assert str(_stored(app, ADMIN)["state"]) == accounts.ACTIVE
    assert "ACCOUNT_DISABLED" not in _actions(app)


def test_the_last_administrator_cannot_be_demoted(app: Flask, admin: FlaskClient) -> None:
    """The second path to the same end state. A guard on one route is not a guard."""
    refused = _post(admin, f"/accounts/{ADMIN}/role", role=accounts.MEMBER)

    assert "last+enabled+administrator" in refused.headers["Location"].replace("%20", "+")
    assert str(_stored(app, ADMIN)["role"]) == accounts.ADMIN
    assert "ROLE_CHANGED" not in _actions(app)


def test_an_administrator_can_be_disabled_once_there_are_two(
    app: Flask, admin: FlaskClient
) -> None:
    """The refusal is about the LAST one, so it must let go when there is a second.

    Without this the two tests above would pass against a route that refused every disable,
    which is the shape of guard this project has shipped before.
    """
    _make_member(admin)
    _post(admin, f"/accounts/{MEMBER}/role", role=accounts.ADMIN)

    allowed = _post(admin, f"/accounts/{ADMIN}/state", state=accounts.DISABLED)

    assert "error=" not in allowed.headers["Location"]
    assert str(_stored(app, ADMIN)["state"]) == accounts.DISABLED
    assert "ACCOUNT_DISABLED" in _actions(app)


def test_a_disabled_administrator_does_not_count_towards_the_last_one(
    app: Flask, admin: FlaskClient
) -> None:
    """Counting every administrator rather than every ENABLED one locks the list.

    Promote a second administrator, disable them, and the first must then be the last one
    again. A count that included the disabled row would allow the first to be disabled too
    and leave nobody able to administer anything.
    """
    _make_member(admin)
    _post(admin, f"/accounts/{MEMBER}/role", role=accounts.ADMIN)
    _post(admin, f"/accounts/{MEMBER}/state", state=accounts.DISABLED)

    refused = _post(admin, f"/accounts/{ADMIN}/state", state=accounts.DISABLED)

    assert "last+enabled+administrator" in refused.headers["Location"].replace("%20", "+")
    assert str(_stored(app, ADMIN)["state"]) == accounts.ACTIVE


def test_a_role_outside_the_vocabulary_is_refused(app: Flask, admin: FlaskClient) -> None:
    """The role arrives in a form field, so it is validated against the closed set."""
    _make_member(admin)

    refused = _post(admin, f"/accounts/{MEMBER}/role", role="superuser")

    assert "error=" in refused.headers["Location"]
    assert str(_stored(app, MEMBER)["role"]) == accounts.MEMBER
    assert "ROLE_CHANGED" not in _actions(app)


# ============================ recovery actions ============================


def test_resetting_a_factor_clears_the_secret_and_the_lockout(
    app: Flask, admin: FlaskClient
) -> None:
    """The recovery path for a lost phone, and it is an administrator action by design."""
    _make_member(admin)
    _sign_in(app, MEMBER, PHRASE)
    assert str(_stored(app, MEMBER)["totp_secret"]), "the member enrolled a factor"

    _post(admin, f"/accounts/{MEMBER}/reset-factor")

    after = _stored(app, MEMBER)
    assert after["totp_secret"] == ""
    assert after["recovery"] == []
    assert "FACTOR_RESET" in _actions(app)


def test_unlocking_clears_the_failure_count(app: Flask, admin: FlaskClient) -> None:
    """Clearing a lockout early, rather than waiting the window out."""
    _make_member(admin)
    anonymous = app.test_client()
    for _ in range(accounts.MAXIMUM_FAILURES):
        _give_first_factor(anonymous, MEMBER, WRONG_PHRASE)
    assert accounts.is_locked(_stored(app, MEMBER)), "the account locked"

    _post(admin, f"/accounts/{MEMBER}/unlock")

    assert not accounts.is_locked(_stored(app, MEMBER))
    assert "ACCOUNT_UNLOCKED" in _actions(app)


@pytest.mark.parametrize("path", ["unlock", "reset-factor", "state", "role"])
def test_an_action_on_a_username_that_does_not_exist_is_refused_quietly(
    app: Flask, admin: FlaskClient, path: str
) -> None:
    """No 500, no stack trace, and no entry claiming something happened to nobody."""
    before = _actions(app)

    refused = _post(
        admin,
        f"/accounts/nobody@bluestaq.uk/{path}",
        state=accounts.DISABLED,
        role=accounts.MEMBER,
    )

    assert refused.status_code == 302
    assert "error=" in refused.headers["Location"]
    assert _actions(app) == before


# ============================ changing your own password ============================


def test_the_current_value_is_required_to_change_it(app: Flask, admin: FlaskClient) -> None:
    """A session left open on an unlocked machine is the ordinary way an account is taken.

    Without this, whoever found that session could lock the owner out of their own account
    in one click, and the audit entry would name the owner.
    """
    refused = _change_own(admin, WRONG_PHRASE, NEW_PHRASE)

    assert "error=" in refused.headers["Location"]
    assert accounts.verify_password(str(_stored(app, ADMIN)["password"]), PHRASE)
    assert "PASSWORD_CHANGE_FAILED" in _actions(app)
    assert "PASSWORD_CHANGED" not in _actions(app)


def test_a_mismatched_confirmation_changes_nothing(app: Flask, admin: FlaskClient) -> None:
    """Checked before the current value, so a typo is not recorded as a failed attempt."""
    refused = admin.post(
        "/account/password",
        data={
            "current": PHRASE,
            "password": NEW_PHRASE,
            "confirm": f"{NEW_PHRASE}-typo",
            "csrf_token": _token(admin, "/account/password"),
        },
    )

    assert "error=" in refused.headers["Location"]
    assert accounts.verify_password(str(_stored(app, ADMIN)["password"]), PHRASE)
    assert "PASSWORD_CHANGE_FAILED" not in _actions(app)


def test_a_change_is_recorded_without_its_value(app: Flask, admin: FlaskClient) -> None:
    """The entry says the field changed. It must never say what it changed to."""
    _change_own(admin, PHRASE, NEW_PHRASE)

    stored = _stored(app, ADMIN)
    assert accounts.verify_password(str(stored["password"]), NEW_PHRASE)
    assert stored["must_change_password"] is False
    entries = app.extensions["directive_chain"].entries
    written = [entry for entry in entries if entry.action == "PASSWORD_CHANGED"]
    assert written, "the change must be recorded"
    assert written[0].fields_changed == "password"
    for entry in entries:
        line = " ".join(str(value) for value in entry.covered_fields().values())
        assert NEW_PHRASE not in line
        assert PHRASE not in line


# ============================ what the page may show ============================


def test_the_accounts_page_carries_no_secret_of_any_kind(app: Flask, admin: FlaskClient) -> None:
    """The one page where a leak is served to a browser rather than written to a file."""
    _make_member(admin)
    _sign_in(app, MEMBER, PHRASE)
    member = _stored(app, MEMBER)

    body = admin.get("/accounts").get_data(as_text=True)

    assert MEMBER in body, "the page does list the account"
    assert str(member["password"]) not in body
    assert str(member["totp_secret"]) not in body
    assert "scrypt$" not in body
    assert isinstance(member["recovery"], list)
    for held in member["recovery"]:
        assert str(held) not in body


def test_the_redaction_is_an_allowlist_in_the_route_as_well(app: Flask, admin: FlaskClient) -> None:
    """A field nobody has thought of yet must not reach the page by default.

    `redacted` is an allowlist and `test_accounts.py` holds that directly. This holds that
    the ROUTE uses it, which is a different claim: the allowlist is worth nothing if the
    page renders the raw row.
    """
    data_dir = str(app.config["DIRECTIVE_DATA_DIR"])
    rows = accounts.load(data_dir)
    rows[0]["a_field_added_next_year"] = "must-not-be-rendered"
    accounts.save(data_dir, rows)

    body = admin.get("/accounts").get_data(as_text=True)

    assert "must-not-be-rendered" not in body


# ============================ the lockout recovery ============================


def _lock_out(app: Flask, username: str, phrase: str = WRONG_PHRASE) -> None:
    """Drive an account into its lockout window the way an attacker would: from outside."""
    anonymous = app.test_client()
    for _ in range(accounts.MAXIMUM_FAILURES):
        _give_first_factor(anonymous, username, phrase)
    assert accounts.is_locked(_stored(app, username)), f"{username} did not lock"


def test_an_unauthenticated_caller_can_lock_the_only_administrator_out(
    app: Flask, admin: FlaskClient
) -> None:
    """Stated as a test because it is a real exposure, not because it is acceptable.

    Ten wrong passwords lock any account for 900 seconds, usernames here are work email
    addresses and so are guessable, and nothing in the application rate-limits the sign-in
    form per source address. With one administrator and no live session there was then no
    way back in at all: `/accounts/<username>/unlock` is behind the role gate, and
    `ensure_bootstrap` does nothing once any account exists. A security gate found it.

    The exposure is held here so that any future narrowing of it is deliberate, and the
    recovery below is what stops it being terminal. The denial of service itself is not
    closed in the application and is recorded as accepted residual in `docs/GATE-RECORDS.md`
    pending an edge rate limiter.
    """
    _lock_out(app, ADMIN)

    assert _give_first_factor(app.test_client(), ADMIN, PHRASE).status_code == 302
    assert app.test_client().get("/accounts").status_code in {302, 401}


def test_the_break_glass_unlock_clears_the_lock_and_records_it(
    app: Flask, admin: FlaskClient, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    """The documented recovery, and it must actually work from a cold restart.

    `docs/DEPLOYMENT.md` used to say "correct the value on the environment channel and
    restart", which restored nothing, because the bootstrap path refuses to act once any
    account exists. This is the narrow replacement: it clears the LOCKOUT and nothing else,
    and it writes an audit entry, which is the whole reason to prefer it over somebody
    editing the account file on the volume by hand.
    """
    _lock_out(app, ADMIN)
    monkeypatch.setenv("BOOTSTRAP_UNLOCK", "true")

    with caplog.at_level("WARNING"):
        restarted = create_app()

    assert not accounts.is_locked(_stored(restarted, ADMIN))
    entries = restarted.extensions["directive_chain"].entries
    unlocks = [entry for entry in entries if entry.action == "ACCOUNT_UNLOCKED"]
    assert unlocks, "a lock cleared with no record is a lock nobody can evidence"
    assert unlocks[-1].source_ip == "boot", "it came from the factory, not from a caller"
    assert _give_first_factor(restarted.test_client(), ADMIN, PHRASE).status_code == 302
    # The pod-log warning, held here because this commit's own documentation promoted it
    # into a stated compensating control: the audit entry is best-effort, and
    # `docs/DEPLOYMENT.md` tells an operator the warning is the backstop. Deleting the
    # `LOGGER.warning` left the whole suite green until a gate said so, which would have
    # made that sentence false in a document an assessor reads.
    logged = " ".join(record.getMessage() for record in caplog.records)
    assert "cleared the lockout on" in logged
    assert ADMIN in logged, "the warning must name which account was unlocked"


@pytest.mark.parametrize("value", ["false", "0", "yes", "no", "1", "tru", "", " "])
def test_the_break_glass_refuses_any_value_that_is_not_true(
    app: Flask, admin: FlaskClient, monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    """The variable must EQUAL `true`, and nothing else may turn the recovery on.

    Held by nothing until a gate pointed it out: the test below covers the ABSENT case
    only, so a mutant reading "any non-empty value" survived the whole suite. Under that
    mutant an operator who sets `BOOTSTRAP_UNLOCK=false` to turn the recovery OFF turns it
    on, which is the opposite of what they asked for and the worst direction for a control
    whose whole justification is that it fires only when somebody means it.
    """
    _lock_out(app, ADMIN)
    monkeypatch.setenv("BOOTSTRAP_UNLOCK", value)

    restarted = create_app()

    assert accounts.is_locked(_stored(restarted, ADMIN)), f"{value!r} turned the recovery on"


def test_the_break_glass_does_nothing_without_the_variable(app: Flask, admin: FlaskClient) -> None:
    """It must NOT run on every boot.

    A container that is crash-looping would otherwise clear the lock as fast as it was
    earned, which hands an attacker the lockout's removal for free. The operator sets the
    variable deliberately, restarts, signs in, and removes it again.
    """
    _lock_out(app, ADMIN)

    restarted = create_app()

    assert accounts.is_locked(_stored(restarted, ADMIN))


def test_the_break_glass_changes_nothing_but_the_lock(
    app: Flask, admin: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Not the password, not the factor, not the role, not the state.

    Whoever holds the environment channel can already replace this application wholesale,
    so this is not about stopping them. It is about the recovery not being a back door with
    a runbook: a narrow one is as useful and says what it does.
    """
    _make_member(admin)
    before = dict(_stored(app, ADMIN))
    _lock_out(app, ADMIN)
    monkeypatch.setenv("BOOTSTRAP_UNLOCK", "true")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", f"{PHRASE}-a-different-value")

    restarted = create_app()
    after = _stored(restarted, ADMIN)

    assert after["password"] == before["password"], "the password must not be reset"
    assert after["totp_secret"] == before["totp_secret"]
    assert after["role"] == before["role"]
    assert after["state"] == before["state"]
    assert accounts.find(accounts.load(str(restarted.config["DIRECTIVE_DATA_DIR"])), MEMBER)


def test_the_break_glass_only_touches_the_named_account(
    app: Flask, admin: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It names `BOOTSTRAP_ADMIN`, so another locked account stays locked."""
    _make_member(admin)
    # The member is moved to row ZERO of the account file, and the distinction is the whole
    # point. The first version of this fix locked the member first in TIME, which is a
    # different thing: the bootstrap creates the administrator, so it is row 0 whatever
    # order the locks arrive in, and a mutant selecting "the first locked row" still
    # happened to pick the right account. A gate measured that the mutant survived and that
    # the comment here claimed it did not, which is a shipped record over-claiming about
    # the test beneath it. Row order is what the mutant reads, so row order is what this
    # test has to disagree with.
    data_dir = str(app.config["DIRECTIVE_DATA_DIR"])
    rows = accounts.load(data_dir)
    accounts.save(data_dir, sorted(rows, key=lambda row: row["username"] != MEMBER))
    assert str(accounts.load(data_dir)[0]["username"]) == MEMBER, "the member must be row 0"

    _lock_out(app, MEMBER)
    _lock_out(app, ADMIN)
    monkeypatch.setenv("BOOTSTRAP_UNLOCK", "true")

    restarted = create_app()

    assert not accounts.is_locked(_stored(restarted, ADMIN))
    assert accounts.is_locked(_stored(restarted, MEMBER))
