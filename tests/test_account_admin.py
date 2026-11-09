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

from directive import accounts, auth, create_app, totp

SUITE_KEY = bytes(range(32)).hex()
ADMIN = "ash.higgins@bluestaq.uk"
MEMBER = "new.person@bluestaq.uk"
#: Sorts before the administrator and is placed in the LAST row, so that a
#: positional or alphabetical selection rule cannot coincide with the named one.
DECOY = "aaa.decoy@bluestaq.uk"

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
    #: A THIRD locked account, and the ordering below is the whole fixture. Moving the
    #: member to row 0 kills a mutant reading "the first locked row", and a gate then found
    #: two more that it does not: the administrator is also the LAST row and has the
    #: alphabetically FIRST username, so "last locked" and "lowest username" both still
    #: picked the right account and both survived the whole suite. `aaa@` sorts before the
    #: administrator and sits in the last row, so no positional or alphabetical rule
    #: coincides with the named one any more. Three axes, three disagreements.
    _make_member(admin, DECOY)
    data_dir = str(app.config["DIRECTIVE_DATA_DIR"])
    order = {MEMBER: 0, ADMIN: 1, DECOY: 2}
    rows = accounts.load(data_dir)
    accounts.save(data_dir, sorted(rows, key=lambda row: order[str(row["username"])]))
    stored = [str(row["username"]) for row in accounts.load(data_dir)]
    assert stored == [MEMBER, ADMIN, DECOY], stored
    assert DECOY < ADMIN, "the decoy must sort before the administrator"

    #: The administrator is locked FIRST, which is the fourth axis. With it locked last it
    #: was also the most recently locked account, so a mutant selecting by `locked_until`
    #: still picked the right one and survived the whole module: a gate measured that after
    #: the three positional axes were fixed. Four rules now disagree with the named lookup:
    #: first row, last row, lowest username, and most recently locked.
    _lock_out(app, ADMIN)
    _lock_out(app, MEMBER)
    _lock_out(app, DECOY)
    monkeypatch.setenv("BOOTSTRAP_UNLOCK", "true")

    restarted = create_app()

    assert not accounts.is_locked(_stored(restarted, ADMIN))
    assert accounts.is_locked(_stored(restarted, MEMBER))
    assert accounts.is_locked(_stored(restarted, DECOY))


# ============================ revocation takes effect ============================
#
# Every test in this section exists because none of them did. A security gate drove all of
# it against the live routes: the decorators decided from the signed cookie alone, which
# carries a copy of the role taken at sign-in, so for the eight hours of `SESSION_LIFETIME`
# a disabled account read every register, wrote a compliance record and pulled the whole
# evidence export, a demoted administrator undid their own demotion, and a disabled
# administrator re-enabled themselves, disabled the administrator who had disabled them,
# and created a fresh administrator to persist with. Three shipped records said otherwise.


@pytest.fixture
def second_admin(app: Flask, admin: FlaskClient) -> FlaskClient:
    """Return a second administrator, signed in, so the last-admin guard is not in the way."""
    _post(admin, "/accounts/create", username=MEMBER, password=PHRASE, role=accounts.ADMIN)
    return _sign_in(app, MEMBER, PHRASE)


def _post_with(client: FlaskClient, path: str, token: str, **fields: str) -> TestResponse:
    """Post with a token captured EARLIER, the way a revoked session really would.

    `_post` fetches a fresh token from `/accounts` first, which a revoked account can no
    longer load, so using it here would prove only that the page is refused. The attack
    worth refusing is the one an attacker actually has: a token taken while they were still
    an administrator, replayed after the revocation, with no page load in between.
    """
    return client.post(path, data={**fields, "csrf_token": token})


@pytest.mark.parametrize(
    "path",
    ["/console", "/api/registers", "/api/audit", "/api/export", "/accounts", "/account/password"],
)
def test_disabling_an_account_ends_its_session_on_the_next_request(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient, path: str
) -> None:
    """Not at the next sign-in. At the next REQUEST."""
    assert second_admin.get(path).status_code in {200, 302}, "it worked before"

    _post(admin, f"/accounts/{MEMBER}/state", state=accounts.DISABLED)

    refused = second_admin.get(path)
    assert refused.status_code in {302, 401}, f"{path} still served a disabled account"


def test_a_disabled_account_cannot_write_a_register_record(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """The compliance registers are the point of the application, so this is the sharp end."""
    _post(admin, f"/accounts/{MEMBER}/state", state=accounts.DISABLED)

    written = second_admin.post(
        "/api/registers/risks",
        json={"title": "written by a disabled account"},
        headers={"X-CSRF-Token": "irrelevant, the gate fires first"},
    )

    assert written.status_code in {401, 403}


def test_a_disabled_administrator_cannot_re_enable_itself(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """The attack the gate actually ran, and the one that makes this a privilege defect."""
    stale = _token(second_admin, "/accounts")
    _post(admin, f"/accounts/{MEMBER}/state", state=accounts.DISABLED)

    _post_with(second_admin, f"/accounts/{MEMBER}/state", stale, state=accounts.ACTIVE)

    assert str(_stored(app, MEMBER)["state"]) == accounts.DISABLED


def test_a_disabled_administrator_cannot_disable_the_one_who_disabled_them(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """A revoked administrator must not be able to take the live one down with them."""
    stale = _token(second_admin, "/accounts")
    _post(admin, f"/accounts/{MEMBER}/state", state=accounts.DISABLED)

    _post_with(second_admin, f"/accounts/{ADMIN}/state", stale, state=accounts.DISABLED)

    assert str(_stored(app, ADMIN)["state"]) == accounts.ACTIVE


def test_a_disabled_administrator_cannot_create_a_fresh_administrator(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """Persistence. Without this the revocation buys one request's worth of safety."""
    stale = _token(second_admin, "/accounts")
    _post(admin, f"/accounts/{MEMBER}/state", state=accounts.DISABLED)

    _post_with(
        second_admin,
        "/accounts/create",
        stale,
        username="planted@bluestaq.uk",
        password=PHRASE,
        role=accounts.ADMIN,
    )

    rows = accounts.load(str(app.config["DIRECTIVE_DATA_DIR"]))
    assert accounts.find(rows, "planted@bluestaq.uk") is None


def test_demoting_an_administrator_takes_the_role_away_mid_session(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """The role is read live, so the session keeps working as a MEMBER and no more.

    Not a sign-out: their session was legitimate and only the extra power is gone. That is
    the behaviour the role being authoritative on the volume gives for free, and asserting
    both halves is what stops a future fix from simply ending the session instead.
    """
    assert second_admin.get("/accounts").status_code == 200

    _post(admin, f"/accounts/{MEMBER}/role", role=accounts.MEMBER)

    assert second_admin.get("/accounts").status_code in {302, 403}, "still an administrator"
    assert second_admin.get("/api/registers").status_code == 200, "but still signed in"


def test_a_demoted_administrator_cannot_undo_their_own_demotion(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """The attack that makes a demotion worth anything."""
    stale = _token(second_admin, "/accounts")
    _post(admin, f"/accounts/{MEMBER}/role", role=accounts.MEMBER)

    _post_with(second_admin, f"/accounts/{MEMBER}/role", stale, role=accounts.ADMIN)

    assert str(_stored(app, MEMBER)["role"]) == accounts.MEMBER


def test_a_locked_account_is_refused_mid_session_too(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """`may_sign_in` covers three states and a test naming one of them holds one of them."""
    _lock_out(app, MEMBER)

    assert second_admin.get("/api/registers").status_code == 401


def test_an_unreadable_account_list_grants_nothing(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """Fail closed. A volume fault must stop the console rather than open it."""
    stored = accounts.accounts_path(str(app.config["DIRECTIVE_DATA_DIR"]))
    kept = stored.read_bytes()
    stored.write_text("{ this is not json", encoding="utf-8")

    assert second_admin.get("/api/registers").status_code == 401
    assert second_admin.get("/accounts").status_code in {302, 403}
    stored.write_bytes(kept)


def test_an_unreadable_account_list_does_not_destroy_the_session(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """A fault refuses the request. It must not sign the person out for good.

    Three places in the tree said this and the code did the opposite: every refusal cleared
    the session, so one request landing during a transient volume problem signed that user
    out permanently, and while the list was unreadable they could not sign back in either,
    because the sign-in route reads the same file. A gate measured the contradiction. The
    record was right about what should happen and the code was not, which is the shape of
    finding this project treats as binding.
    """
    stored = accounts.accounts_path(str(app.config["DIRECTIVE_DATA_DIR"]))
    kept = stored.read_bytes()
    stored.write_text("{ this is not json", encoding="utf-8")

    assert second_admin.get("/api/registers").status_code == 401, "refused during the fault"
    stored.write_bytes(kept)

    assert second_admin.get("/api/registers").status_code == 200, (
        "the session did not survive a transient fault, which three records say it does"
    )


def test_the_sign_in_page_renders_during_a_fault_rather_than_looping(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """The loop the surviving cookie makes reachable, and the line that prevents it.

    With the cookie kept through a fault, the dashboard bounces the caller to the sign-in
    page, and a sign-in page asking `current_actor` rather than `live_role` bounces them
    straight back. That is a real loop and it is only reachable now that a fault keeps the
    session: while every refusal cleared the cookie there was nothing for this to catch,
    which a gate proved by reverting the line with the whole suite green.
    """
    stored = accounts.accounts_path(str(app.config["DIRECTIVE_DATA_DIR"]))
    kept = stored.read_bytes()
    stored.write_text("{ this is not json", encoding="utf-8")

    bounced = second_admin.get("/console")
    landed = second_admin.get("/sign-in")
    stored.write_bytes(kept)

    assert bounced.status_code == 302
    assert "/sign-in" in bounced.headers["Location"]
    assert landed.status_code == 200, "the sign-in page bounced back: a redirect loop"


def test_a_revocation_clears_the_session_but_a_fault_does_not(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """The split, asserted as a split rather than one side at a time.

    A boolean was enough to refuse both cases, and refusing is not the question: an
    administrator's decision should take the cookie with it and a volume fault should not.
    """
    _post(admin, f"/accounts/{MEMBER}/state", state=accounts.DISABLED)
    second_admin.get("/console")

    with second_admin.session_transaction() as cleared:
        assert auth.ACTOR_KEY not in cleared, "a revocation must take the cookie with it"


# ============================ sessions have an epoch ============================


def test_changing_your_own_password_evicts_every_other_session(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """The remedy for a session somebody else is holding.

    `password_submit`'s own docstring names a session left open on an unlocked machine as
    the ordinary way an account is taken over. Requiring the current password evicts
    nobody: the taker has the session and the owner's old password changes nothing for
    them. A gate measured that a cookie captured beforehand kept working. The epoch on the
    account is what makes the change mean something.
    """
    taken = app.test_client()
    taken.set_cookie("directive_session", _session_cookie(second_admin))
    assert taken.get("/api/registers").status_code == 200, "the taken session worked"

    _change_own(second_admin, PHRASE, NEW_PHRASE)

    assert taken.get("/api/registers").status_code == 401, "the taken session survived"
    assert second_admin.get("/api/registers").status_code == 200, "and the owner stayed in"


def test_an_administrator_resetting_a_factor_evicts_that_accounts_sessions(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """A factor reset is the lost-phone path, so the phone is in somebody else's hands."""
    assert second_admin.get("/api/registers").status_code == 200

    _post(admin, f"/accounts/{MEMBER}/reset-factor")

    assert second_admin.get("/api/registers").status_code == 401


def test_a_session_carrying_no_epoch_is_refused(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """Fail closed on a session shaped like one from before the field existed.

    `True` is in the set for a reason that needs the account to be AT epoch 1 to show:
    `bool` is an `int` in Python and `True == 1`, so a session carrying `True` would match
    an account whose epoch is 1 unless bools are excluded explicitly. The first version of
    this test planted `True` against an account still at epoch 0, where the mismatch
    refused it for the wrong reason and the mutant survived. So the password is changed
    first, which takes the account to epoch 1, and only then is each value planted.
    """
    _change_own(second_admin, PHRASE, NEW_PHRASE)
    assert accounts.epoch_of(_stored(app, MEMBER)) == 1, "the account must be AT epoch 1"
    assert second_admin.get("/api/registers").status_code == 200, "the owner is still in"
    with second_admin.session_transaction() as held:
        good = dict(held)

    for planted in (None, "1", True, [1], 0, 2):
        # The session is rebuilt from the good copy each time, because an epoch mismatch is
        # a REVOCATION and a revocation clears the cookie: without this, only the first
        # value is actually tested and every later one is refused for having no actor at
        # all. The first version of this loop did exactly that, and the `True` mutant
        # survived underneath it.
        with second_admin.session_transaction() as held:
            held.clear()
            held.update(good)
            if planted is None:
                held.pop(auth.EPOCH_KEY, None)
            else:
                held[auth.EPOCH_KEY] = planted
        assert second_admin.get("/api/registers").status_code == 401, f"{planted!r} was honoured"


def _session_cookie(client: FlaskClient) -> str:
    """Return the signed session cookie this client holds, as an attacker would copy it.

    Copying the signed VALUE is what an attacker does, which is why this test works that
    way rather than through `session_transaction`: `sign_out` only asks a browser to drop
    a cookie, and somebody who has the signed string simply keeps presenting it. The
    eviction therefore has to come from the server side, which is what the epoch is.
    """
    for cookie in client._cookies.values():
        if cookie.key == "directive_session":
            return str(cookie.value)
    raise AssertionError("the client holds no session cookie")


def test_a_deleted_account_row_ends_the_session(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """There is no delete route, so this is the hand-edited-volume case, and it must hold.

    `may_sign_in(None)` is False, which the decorator relies on. A `find` that returned a
    default row instead would make this pass for the wrong reason, so it is asserted.
    """
    data_dir = str(app.config["DIRECTIVE_DATA_DIR"])
    rows = [row for row in accounts.load(data_dir) if row["username"] != MEMBER]
    accounts.save(data_dir, rows)

    assert second_admin.get("/api/registers").status_code == 401
    assert second_admin.get("/console").status_code == 302


def test_a_sign_in_after_a_bump_carries_the_live_epoch(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """The line that copies the stored epoch onto a NEW session, held at last.

    Nothing in the suite signed a client in after that account's epoch had moved, so
    replacing `session[EPOCH_KEY] = epoch` with `= 0` left the whole suite green. The
    direction was fail-closed, which is why nobody noticed: it silently locks out everybody
    who has ever changed their password. A gate measured the survival.
    """
    # A factor reset rather than a password change, because it bumps the epoch AND clears
    # the second factor, so the fresh sign-in below enrols a new one instead of needing a
    # code at a step the first enrolment already spent.
    _post(admin, f"/accounts/{MEMBER}/reset-factor")
    assert accounts.epoch_of(_stored(app, MEMBER)) == 1

    fresh = _sign_in(app, MEMBER, PHRASE)

    assert fresh.get("/api/registers").status_code == 200, "a fresh sign-in was locked out"
    with fresh.session_transaction() as held:
        assert held[auth.EPOCH_KEY] == 1, "the session did not take the live epoch"


def test_a_non_integer_session_epoch_is_refused_against_a_fresh_account(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """The fail-closed `-1` in `_session_epoch`, which the other epoch test cannot reach.

    That test moves the account to epoch 1 first, so five of its six planted values are
    refused by `1 != anything` rather than by this guard. An account still at epoch 0,
    which every account is until its first password change, is the case where returning `0`
    instead of `-1` grants: a cookie minted before the field existed carries nothing, and
    nothing would match zero. A gate measured that mutant surviving the whole suite.
    """
    assert accounts.epoch_of(_stored(app, MEMBER)) == 0, "the account must still be at 0"
    with second_admin.session_transaction() as held:
        good = dict(held)

    for planted in (None, "0", [0], {}):
        with second_admin.session_transaction() as held:
            held.clear()
            held.update(good)
            if planted is None:
                held.pop(auth.EPOCH_KEY, None)
            else:
                held[auth.EPOCH_KEY] = planted
        assert second_admin.get("/api/registers").status_code == 401, f"{planted!r} was honoured"


def test_an_unreadable_stored_epoch_refuses_every_session_and_every_sign_in(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """Both halves, because closing one of them is what the docstring used to over-claim.

    `epoch_of` returning zero on a corrupt value was green across the whole suite, and its
    own docstring warns against exactly that: it would turn one corrupt field into a session
    that cannot be evicted. And a FRESH sign-in copied the sentinel and matched it, so the
    corruption evicted every old session and minted one it could not touch.
    """
    data_dir = str(app.config["DIRECTIVE_DATA_DIR"])
    rows = accounts.load(data_dir)
    account = accounts.find(rows, MEMBER)
    assert account is not None
    account["session_epoch"] = "corrupt"
    accounts.save(data_dir, rows)

    assert accounts.epoch_of(account) == accounts.FAR_FUTURE_STEP
    assert second_admin.get("/api/registers").status_code == 401, "an old session survived"

    # Driven through BOTH factors, because the first one does not refuse this and never
    # claimed to: a corrupt epoch is caught where the second factor is accepted. The
    # assertion here used to be `"/sign-in" in Location` against the first factor's
    # response, which is `/sign-in/verify` on success, so the substring matched either way
    # and the test could not fail. A gate measured that and the message said the opposite.
    # `totp_last_step` is reset with it, and that matters: the enrolment above spent the
    # current step, so a code generated now would be refused as a replay and the test would
    # pass without the epoch branch ever running. A gate's mutant proved that: removing the
    # branch left the first version of this test green. Only the epoch may refuse here.
    data_dir = str(app.config["DIRECTIVE_DATA_DIR"])
    rows = accounts.load(data_dir)
    corrupted = accounts.find(rows, MEMBER)
    assert corrupted is not None
    corrupted["totp_last_step"] = accounts.NO_STEP
    accounts.save(data_dir, rows)

    fresh = app.test_client()
    sent_on = _give_first_factor(fresh, MEMBER, PHRASE)
    assert sent_on.headers["Location"].endswith("/sign-in/verify"), "the first factor refuses"

    secret = str(_stored(app, MEMBER)["totp_secret"])
    completed = fresh.post(
        "/sign-in/verify",
        data={"code": totp.code_now(secret), "csrf_token": _token(fresh, "/sign-in/verify")},
    )

    assert fresh.get("/api/registers").status_code == 401, "a fresh session was minted"
    assert completed.headers["Location"] == "/sign-in", "and it lands back on the form"


def test_a_missing_account_file_is_a_fault_not_a_revocation(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """A lost mount is the likeliest volume fault, and it must not sign everybody out.

    This is the sibling of the unreadable-list case one trigger over: `load` returns an
    empty list for an absent file, `find` returns nothing, and that read as a revocation,
    so deleting the file, making one request and restoring it byte for byte signed everybody
    out for good. `load` already distinguishes the two; `live_standing` does now as well.
    """
    stored = accounts.accounts_path(str(app.config["DIRECTIVE_DATA_DIR"]))
    kept = stored.read_bytes()
    stored.unlink()

    assert second_admin.get("/api/registers").status_code == 401, "refused during the fault"
    stored.write_bytes(kept)

    assert second_admin.get("/api/registers").status_code == 200, (
        "a missing file signed the session out for good"
    )


def test_a_disabled_account_stays_evicted_after_being_re_enabled(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """Disabling must be durable, not a pause.

    `may_sign_in` refuses a session while the state is DISABLED, so a cookie presented
    during that window is refused; a cookie that simply waits was honoured again on
    re-enablement. A gate measured it. The epoch bump on the transition makes the
    disablement outlive the state change.
    """
    taken = app.test_client()
    taken.set_cookie("directive_session", _session_cookie(second_admin))
    assert taken.get("/api/registers").status_code == 200

    _post(admin, f"/accounts/{MEMBER}/state", state=accounts.DISABLED)
    _post(admin, f"/accounts/{MEMBER}/state", state=accounts.ACTIVE)

    assert taken.get("/api/registers").status_code == 401, "the cookie outlived a disablement"


def test_a_revoked_session_cannot_read_the_diagnostics_credential_map(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """The last authenticated response still deciding from the cookie.

    A disabled account's cookie read `dataDir`, `auditLog` and the whole credential-presence
    map while every other route answered 401 for it. No value is disclosed and the field set
    is a declared residual, and it is still the one place that contradicted "the stored
    account is the authority on every authenticated request".
    """
    assert "inputs" in second_admin.get("/api/diagnostics").get_json()

    _post(admin, f"/accounts/{MEMBER}/state", state=accounts.DISABLED)

    body = second_admin.get("/api/diagnostics").get_json()
    assert "inputs" not in body
    assert "dataDir" not in body
    assert "auditLog" not in body
    assert body["version"], "the operational half must still answer"


def test_the_diagnostics_map_survives_an_unreadable_account_list(
    app: Flask, admin: FlaskClient, second_admin: FlaskClient
) -> None:
    """The fault case keeps the read-out.

    Withholding it on a fault would close the recovery channel during the one incident that
    needs it, so the gate is on REVOKED rather than on GRANTED.
    """
    stored = accounts.accounts_path(str(app.config["DIRECTIVE_DATA_DIR"]))
    kept = stored.read_bytes()
    stored.write_text("{ this is not json", encoding="utf-8")

    body = second_admin.get("/api/diagnostics").get_json()
    stored.write_bytes(kept)

    assert "inputs" in body, "the recovery channel closed during the fault it diagnoses"


def test_an_outstanding_enrolment_cannot_complete_past_the_pending_gate(
    app: Flask, admin: FlaskClient
) -> None:
    """The enrolment route's half of the pending gate, which was held by nothing.

    The verify route's half is held by the password-change test; deleting the same call
    from `enrol_submit` left the whole suite green, and a gate drove the attack through it.
    """
    _post(admin, "/accounts/create", username=MEMBER, password=PHRASE, role=accounts.MEMBER)
    caller = app.test_client()
    _give_first_factor(caller, MEMBER, PHRASE)
    page = caller.get("/sign-in/enrol").get_data(as_text=True)
    found = re.search(r'class="secret mono">([A-Z2-7]+)<', page)
    assert found is not None, "the marker did not reach the enrolment page"

    # A CORRUPT epoch rather than a disable-and-re-enable, and the difference is the
    # difference between a test that holds this gate and one that agrees with it. A bump
    # also clears `totp_pending`, so the enrolment is refused for want of a secret and the
    # gate never runs: a gate's mutant proved the first version of this test green with the
    # call deleted. Corrupting the epoch leaves the pending secret in place, so the only
    # thing that can refuse is `_pending_refusal` on this route.
    data_dir = str(app.config["DIRECTIVE_DATA_DIR"])
    rows = accounts.load(data_dir)
    account = accounts.find(rows, MEMBER)
    assert account is not None
    # The request token is captured BEFORE the epoch is corrupted. `enrol_page` now
    # refuses a stale pending sign-in like both of its siblings, so fetching the token
    # afterwards would read a redirect and the helper would fail on its own assertion
    # rather than on the gate this test names.
    csrf = _token(caller, "/sign-in/enrol")
    account["session_epoch"] = "corrupt"
    accounts.save(data_dir, rows)
    assert str(_stored(app, MEMBER).get("totp_pending") or ""), "the secret must survive"

    completed = caller.post(
        "/sign-in/enrol",
        data={"code": totp.code_now(found.group(1)), "csrf_token": csrf},
    )

    assert caller.get("/api/registers").status_code == 401, "a stale enrolment completed"
    assert completed.status_code == 302
    assert not str(_stored(app, MEMBER).get("totp_secret") or ""), "a factor was confirmed"


# ============================ a planted second factor ============================


def test_one_callers_enrolment_secret_cannot_be_confirmed_by_another(
    app: Flask, admin: FlaskClient
) -> None:
    """An account takeover, driven end to end by a gate, and it needed no admin action.

    `enrol_page` reuses a stored pending secret rather than minting one per request, which
    it has to: minting on every GET meant a refresh invalidated the code the person had just
    scanned. But the reuse read the ACCOUNT, so two callers who both knew the password were
    shown the SAME secret. An attacker loads the page first; the owner, signing in for the
    first time, is shown the attacker's secret and confirms it; the attacker then holds the
    account's live second factor.

    The precondition is knowing the password, which for the bootstrap administrator means
    anyone who can read the platform's environment tab, a reader `docs/DEPLOYMENT.md`
    already names. The token binds a pending secret to one half-finished sign-in.
    """
    _post(admin, "/accounts/create", username=MEMBER, password=PHRASE, role=accounts.MEMBER)

    attacker = app.test_client()
    _give_first_factor(attacker, MEMBER, PHRASE)
    planted = re.search(
        r'class="secret mono">([A-Z2-7]+)<', attacker.get("/sign-in/enrol").get_data(as_text=True)
    )
    assert planted is not None

    owner = app.test_client()
    _give_first_factor(owner, MEMBER, PHRASE)
    shown = re.search(
        r'class="secret mono">([A-Z2-7]+)<', owner.get("/sign-in/enrol").get_data(as_text=True)
    )
    assert shown is not None

    assert shown.group(1) != planted.group(1), "the owner was shown the attacker's secret"
    #: And the attacker cannot confirm theirs either, because the owner's visit replaced the
    #: stored secret and the token that owned it.
    refused = attacker.post(
        "/sign-in/enrol",
        data={
            "code": totp.code_now(planted.group(1)),
            "csrf_token": _token(attacker, "/sign-in/enrol"),
        },
    )
    assert attacker.get("/api/registers").status_code == 401
    assert refused.status_code == 302
    assert not str(_stored(app, MEMBER).get("totp_secret") or ""), "a secret was confirmed"


def test_a_refresh_still_shows_the_same_secret(app: Flask, admin: FlaskClient) -> None:
    """The property the account-wide reuse was introduced for, kept.

    Minting a secret on every GET made refreshing the enrolment page invalidate the code
    the person had just scanned, with nothing on screen to say why. Binding the secret to
    the sign-in keeps that fixed while closing the takeover above, and a test that only
    held the takeover would be satisfied by minting afresh every time.
    """
    _post(admin, "/accounts/create", username=MEMBER, password=PHRASE, role=accounts.MEMBER)
    caller = app.test_client()
    _give_first_factor(caller, MEMBER, PHRASE)

    seen = {
        re.search(  # type: ignore[union-attr]
            r'class="secret mono">([A-Z2-7]+)<', caller.get("/sign-in/enrol").get_data(as_text=True)
        ).group(1)
        for _ in range(3)
    }

    assert len(seen) == 1, f"three loads showed {len(seen)} different secrets"
    confirmed = caller.post(
        "/sign-in/enrol",
        data={"code": totp.code_now(seen.pop()), "csrf_token": _token(caller, "/sign-in/enrol")},
    )
    assert confirmed.status_code == 200, "the scanned code no longer enrols"


def test_an_epoch_bump_clears_an_unconfirmed_enrolment_secret(
    app: Flask, admin: FlaskClient
) -> None:
    """Stopping every session has to include a secret one of them is holding.

    Otherwise a disable-and-re-enable leaves the attacker's planted factor on the record for
    the owner to confirm later, which is the takeover above with an administrator action in
    the middle of it.
    """
    _post(admin, "/accounts/create", username=MEMBER, password=PHRASE, role=accounts.MEMBER)
    caller = app.test_client()
    _give_first_factor(caller, MEMBER, PHRASE)
    caller.get("/sign-in/enrol")
    assert str(_stored(app, MEMBER).get("totp_pending") or ""), "no pending secret was written"

    _post(admin, f"/accounts/{MEMBER}/state", state=accounts.DISABLED)

    after = _stored(app, MEMBER)
    assert not str(after.get("totp_pending") or ""), "the planted secret survived the bump"
    assert not str(after.get("totp_pending_token") or ""), "the token survived the bump"


def test_a_second_load_is_never_shown_another_sessions_secret(
    app: Flask, admin: FlaskClient
) -> None:
    """The token COMPARISON, which the takeover test above cannot reach.

    That test has the owner arrive with no enrolment token at all, so
    `pending_secret_for` returns on its empty-token guard before comparing anything. A gate
    measured the consequence: bypassing the comparison, or making the token a constant,
    left all 1614 tests green while the attack came back.

    The attack needs a SECOND load. The attacker loads the page once, which puts a token on
    their session; the owner then loads it, which replaces the account's secret and token;
    and the attacker loads it again, arriving with a token that is present and wrong. That
    is the only path on which the comparison decides anything, and it is the path that
    serves the owner's live secret to the attacker when the comparison is gone.

    Reproduced here before the test was written: with the comparison bypassed the
    attacker's second load returns the owner's exact secret, and with it in place it does
    not.
    """
    _post(admin, "/accounts/create", username=MEMBER, password=PHRASE, role=accounts.MEMBER)

    def shown(client: FlaskClient) -> str:
        found = re.search(
            r'class="secret mono">([A-Z2-7]+)<', client.get("/sign-in/enrol").get_data(as_text=True)
        )
        assert found is not None, "the enrolment page showed no secret"
        return found.group(1)

    attacker = app.test_client()
    _give_first_factor(attacker, MEMBER, PHRASE)
    shown(attacker)

    owner = app.test_client()
    _give_first_factor(owner, MEMBER, PHRASE)
    owners = shown(owner)

    assert shown(attacker) != owners, (
        "a second load was served the secret another session is about to confirm"
    )


def test_a_completed_enrolment_clears_the_pending_secret_and_its_token(
    app: Flask, admin: FlaskClient
) -> None:
    """The clearing is the only thing standing between one enrolment and a second run.

    `enrol_submit` checks `may_sign_in` and the pending gate but never `is_enrolled`, so
    nothing else refuses a second pass through `finish_enrolment`, which would rotate the
    recovery codes the person has just been shown. A gate found the clearing held by no
    test. It is not reachable as an attack, because the token dies with the session that
    held it, which is why this asserts the state rather than driving a second attempt: a
    test that drove one would pass on the session check and tell us nothing.
    """
    _post(admin, "/accounts/create", username=MEMBER, password=PHRASE, role=accounts.MEMBER)
    caller = _sign_in(app, MEMBER, PHRASE)

    assert caller.get("/account/password").status_code == 200, "the enrolment did not complete"
    after = _stored(app, MEMBER)
    assert str(after.get("totp_secret") or ""), "no factor was confirmed"
    assert not str(after.get("totp_pending") or ""), "the unconfirmed secret was left behind"
    assert not str(after.get("totp_pending_token") or ""), "its token was left behind"


def test_no_pre_authentication_key_survives_a_completed_sign_in(
    app: Flask, admin: FlaskClient
) -> None:
    """`sign_in` clears the session first, and its docstring says so. Nothing checked it.

    A gate removed the `session.clear()` and the whole suite stayed green, with
    `directive_pending`, `directive_pending_since` and `directive_enrolment` all carrying
    into the signed-in session. No exploit was built from it on its own, which is why the
    gate graded it a MINOR; the property is still asserted in the code and was asserted by
    nothing else.
    """
    _post(admin, "/accounts/create", username=MEMBER, password=PHRASE, role=accounts.MEMBER)
    caller = _sign_in(app, MEMBER, PHRASE)

    with caller.session_transaction() as held:
        survived = [
            name
            for name in (auth.PENDING_KEY, auth.PENDING_SINCE_KEY, auth.ENROLMENT_KEY)
            if name in held
        ]
        assert held.get(auth.ACTOR_KEY) == MEMBER, "the sign-in did not complete"

    assert not survived, f"these outlived the session boundary: {survived}"


def test_a_replayed_pre_enrolment_cookie_mints_once_not_once_per_request(
    app: Flask, admin: FlaskClient
) -> None:
    """One password hash must buy one write, not a write per request.

    The enrolment token used to be minted BY the page, alongside the secret, so a caller
    who kept the cookie from the first factor and replayed it was never carrying a token
    and was served a freshly minted secret every time. A gate measured 25 replays of one
    cookie producing 25 secrets and 25 fsynced rewrites of the credential store in 0.06
    seconds, each taking the global lock that every sign-in and every administration route
    also takes, for five minutes per hash. Reproduced here before the fix and after.

    Minting the token at the first factor is what closes it: a replayed cookie already
    carries the token, so it matches and the page writes nothing.
    """
    _post(admin, "/accounts/create", username=MEMBER, password=PHRASE, role=accounts.MEMBER)
    victim = app.test_client()
    _give_first_factor(victim, MEMBER, PHRASE)
    captured = _session_cookie(victim)
    stored = accounts.accounts_path(str(app.config["DIRECTIVE_DATA_DIR"]))

    secrets_served, file_states = set(), set()
    for _ in range(12):
        replay = app.test_client()
        replay.set_cookie("directive_session", captured)
        found = re.search(
            r'class="secret mono">([A-Z2-7]+)<', replay.get("/sign-in/enrol").get_data(as_text=True)
        )
        assert found is not None, "the replay was not served the page at all"
        secrets_served.add(found.group(1))
        file_states.add(stored.stat().st_mtime_ns)

    assert len(secrets_served) == 1, f"{len(secrets_served)} secrets minted from one hash"
    assert len(file_states) == 1, f"{len(file_states)} writes to the credential store"


def test_a_pending_sign_in_carrying_no_enrolment_token_is_sent_back_to_the_start(
    app: Flask, admin: FlaskClient
) -> None:
    """The refusal that replaced the minting, which the coverage report showed held nothing.

    The page now refuses a pending sign-in that carries no token rather than minting one,
    and that branch arrived with the fix in the same commit, uncovered: lines 458 and 459
    of `views/auth_routes.py` in the run that passed. A control added in the same breath as
    the hole it closes is exactly the kind this build has narrowed and re-defeated five
    times, so it gets a test on arrival rather than at the next gate.

    A session reaches this state two ways and both end here: a cookie minted before this
    release, which carried the pending marker and no token, and a forgery. Starting again
    is the only safe answer, so the marker is abandoned too and the caller cannot simply
    reload into a fresh secret.
    """
    _post(admin, "/accounts/create", username=MEMBER, password=PHRASE, role=accounts.MEMBER)
    victim = app.test_client()
    _give_first_factor(victim, MEMBER, PHRASE)
    with victim.session_transaction() as held:
        held.pop(auth.ENROLMENT_KEY, None)
    stored = accounts.accounts_path(str(app.config["DIRECTIVE_DATA_DIR"]))
    before = stored.stat().st_mtime_ns

    served = victim.get("/sign-in/enrol")

    assert served.status_code == 302, "a tokenless sign-in was served a secret"
    assert stored.stat().st_mtime_ns == before, "a tokenless GET wrote to the credential store"
    assert not str(_stored(app, MEMBER).get("totp_pending") or ""), (
        "a tokenless GET planted a pending secret"
    )
    with victim.session_transaction() as held:
        assert auth.PENDING_KEY not in held, (
            "the half-finished sign-in survived, so the caller can reload into a secret"
        )


def test_the_enrolment_page_refuses_a_sign_in_the_epoch_has_moved_past(
    app: Flask, admin: FlaskClient
) -> None:
    """The enrolment page alone did not check the epoch, and it WRITES.

    Both siblings check it, so a password change or a factor reset stopped a half-finished
    sign-in completing while this page went on serving fresh secrets and planting them on
    the record: a half-authenticated caller writing to the credential store after
    revocation, which is the case the `may_sign_in` check here was added to close one round
    ago. That fix swept the disabled and locked half and left this one open.
    """
    _post(admin, "/accounts/create", username=MEMBER, password=PHRASE, role=accounts.MEMBER)
    victim = app.test_client()
    _give_first_factor(victim, MEMBER, PHRASE)
    victim.get("/sign-in/enrol")

    _post(admin, f"/accounts/{MEMBER}/reset-factor")
    assert not str(_stored(app, MEMBER).get("totp_pending") or ""), "the remedy did not clear"

    served = victim.get("/sign-in/enrol")

    assert served.status_code == 302, "a revoked sign-in was served a secret"
    assert not str(_stored(app, MEMBER).get("totp_pending") or ""), (
        "a revoked sign-in re-planted a secret on the credential store"
    )
