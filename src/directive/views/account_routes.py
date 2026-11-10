"""Changing your own password, and administering other people's accounts.

Separated from `auth_routes` because these are a different thing: that module decides
whether somebody may start a session, and this one manages the list that decision reads.

**Every route here writes an audit entry, including the refusals that matter.** Account
administration is the most privileged thing this application can do, and AUD-001's
Administration category is exactly this. An account created, disabled, re-enabled, or
given a new role without a record would be a change to who can touch the compliance
registers that the compliance registers cannot evidence.

**The last administrator cannot be removed.** Disabling or demoting the final enabled
administrator is refused, because an application whose account list nobody can administer
needs the bootstrap variables and a restart to recover, and the person who would notice is
the one who just locked themselves out.

That guard only ever governed the LIST. It said nothing about sessions, and for four
security rounds the decorators decided from the signed cookie, so a removed administrator
kept the role until the cookie expired and could simply restore themselves. `auth.live_role`
closes that: the stored account is the authority on every authenticated request. Both halves
are needed and neither is the other, which is why this paragraph now names the second one.

**A password change and a factor reset evict sessions too, through the account's epoch.**
Disabling an account was already enough to end its sessions, because `may_sign_in` refuses
it; the other two were not, and a gate measured a cookie captured beforehand still working
through both. That matters most for `password_submit` below, whose own docstring names a
session left open on an unlocked machine as the ordinary way an account is taken over:
requiring the current password evicted nobody, because the taker has the session and the
owner's old password changes nothing for them. The change evicts them now, and leaves the
owner's own session alone.
"""

from __future__ import annotations

from flask import Blueprint, current_app, redirect, render_template, request, url_for
from werkzeug.wrappers.response import Response

from .. import accounts, auth, csrf
from .auth_routes import record_event

account_bp = Blueprint("account", __name__)

#: Where an administrator is sent after any change, successful or refused.
ADMIN_ENDPOINT = "account.accounts_page"


def _data_dir() -> str:
    """Return the configured data directory."""
    return str(current_app.config["DIRECTIVE_DATA_DIR"])


def _audit(action: str, subject: str, outcome: str = "SUCCESS", fields: str = "") -> None:
    """Write one account-administration entry against the signed-in actor."""
    record_event(
        action,
        auth.audit_actor(),
        outcome,
        resource_id=subject,
        resource="account",
        fields_changed=fields,
    )


# ---------------------------------------------------------------- your own password


@account_bp.get("/account/password")
@auth.required
def password_page() -> str:
    """Show the change-your-own-password form."""
    return render_template(
        "password.html",
        forced=_must_change(),
        error=request.args.get("error", ""),
    )


def _must_change() -> bool:
    """Return whether the signed-in account is required to change its password now."""
    actor = auth.current_actor()
    if not actor or not auth.local_accounts_only():
        return False
    try:
        rows = accounts.load(_data_dir())
    except accounts.AccountError:
        return False
    account = accounts.find(rows, actor)
    return bool(account and account.get("must_change_password"))


@account_bp.post("/account/password")
@auth.required
@csrf.required
def password_submit() -> Response:
    """Change the signed-in actor's own password.

    The current password is required even though the caller is already signed in. A session
    left open on an unlocked machine is the ordinary way an account is taken over, and
    without this the taker could lock the owner out of their own account in one click.
    """
    actor = auth.current_actor() or ""
    if not auth.local_accounts_only():
        return redirect(url_for(auth.DASHBOARD_ENDPOINT))

    current = request.form.get("current") or ""
    proposed = request.form.get("password") or ""
    confirm = request.form.get("confirm") or ""

    if proposed != confirm:
        return _password_error("the two new passwords did not match")

    with accounts.with_lock():
        rows = accounts.load(_data_dir())
        account = accounts.find(rows, actor)
        if account is None:
            return _password_error("that account no longer exists")
        refusal = ""
        try:
            matched = accounts.verify_password(str(account.get("password", "")), current)
        except accounts.ServiceBusyError:
            # Not a wrong password, so not an audit entry that says one. Same reasoning as
            # the sign-in route: a capacity event recorded as a credential failure is a
            # false record in an immutable log.
            refusal = "the service is busy. Try again in a moment"
        else:
            if not matched:
                _audit("PASSWORD_CHANGE_FAILED", actor, "FAILURE")
                refusal = "the current password did not match"
        if refusal:
            return _password_error(refusal)
        try:
            epoch = accounts.set_password(account, proposed)
        except accounts.AccountError as error:
            return _password_error(str(error))
        accounts.save(_data_dir(), rows)
        #: THIS session keeps going; every other session for this account stops. That is
        #: the whole point of the change for somebody who suspects a session was taken: the
        #: current password was already required and the taker has it, so requiring it
        #: again evicted nobody.
        auth.remember_epoch(epoch)

    _audit("PASSWORD_CHANGED", actor, fields="password")
    return redirect(url_for(auth.DASHBOARD_ENDPOINT))


def _password_error(reason: str) -> Response:
    """Send the caller back to the form with a reason they can act on.

    The reason IS shown here, unlike on the sign-in page. The caller is already
    authenticated, so telling them their current password was wrong reveals nothing they do
    not already know, and hiding it would just make the form unusable.
    """
    return redirect(url_for("account.password_page", error=reason))


# ---------------------------------------------------------------- administration


@account_bp.get("/accounts")
@auth.admin_required
def accounts_page() -> str:
    """List every account, with no secret in the response."""
    rows = accounts.load(_data_dir())
    return render_template(
        "accounts.html",
        people=[accounts.redacted(row) for row in sorted(rows, key=_username_of)],
        roles=accounts.ROLES,
        minimum=accounts.MINIMUM_PASSWORD,
        error=request.args.get("error", ""),
        notice=request.args.get("notice", ""),
    )


def _username_of(row: dict[str, object]) -> str:
    return str(row.get("username", ""))


@account_bp.post("/accounts/create")
@auth.admin_required
@csrf.required
def create_account() -> Response:
    """Create an account. It must change its password and enrol a factor at first sign-in."""
    with accounts.with_lock():
        rows = accounts.load(_data_dir())
        try:
            created = accounts.new_account(
                request.form.get("username") or "",
                request.form.get("password") or "",
                role=request.form.get("role") or accounts.MEMBER,
            )
        except accounts.AccountError as error:
            return _admin_error(str(error))
        if accounts.find(rows, created["username"]) is not None:
            # Checked after `new_account` so the username is normalised first: `Ash@` and
            # `ash@` must collide rather than becoming two accounts for one person.
            return _admin_error(f"{created['username']!r} already has an account")
        #: A list display rather than `rows.append(created)`, deliberately. `.append` on a
        #: receiver this module did not visibly construct is what the audit-entry
        #: construction rule fails closed on, and the right answer to that is to stop
        #: appending, not to widen the exemption list that rule reads.
        accounts.save(_data_dir(), [*rows, created])

    _audit("ACCOUNT_CREATED", created["username"], fields="role,state")
    return _admin_notice(f"{created['username']} created. They set their own password at sign-in.")


@account_bp.post("/accounts/<username>/state")
@auth.admin_required
@csrf.required
def set_state(username: str) -> Response:
    """Disable or re-enable an account."""
    wanted = request.form.get("state") or ""
    with accounts.with_lock():
        rows = accounts.load(_data_dir())
        account = _resolve(rows, username)
        if account is None:
            return _admin_error("no such account")
        if wanted == accounts.DISABLED and _is_last_admin(rows, account):
            return _admin_error("that is the last enabled administrator")
        try:
            accounts.set_state(account, wanted)
        except accounts.AccountError as error:
            return _admin_error(str(error))
        if wanted == accounts.DISABLED:
            #: End the account's sessions durably, not only until it is re-enabled.
            #: `may_sign_in` already refuses them while the state is DISABLED, but a cookie
            #: idle across a disable and a later re-enable was honoured again, which a gate
            #: measured. Bumping the epoch makes the disablement outlive the state change.
            accounts.bump_epoch(account)
        accounts.save(_data_dir(), rows)
        subject = str(account["username"])

    _audit(
        "ACCOUNT_DISABLED" if wanted == accounts.DISABLED else "ACCOUNT_ENABLED",
        subject,
        fields="state",
    )
    return _admin_notice(f"{subject} is now {wanted.lower()}.")


@account_bp.post("/accounts/<username>/role")
@auth.admin_required
@csrf.required
def set_role(username: str) -> Response:
    """Change an account's role."""
    wanted = request.form.get("role") or ""
    if wanted not in accounts.ROLES:
        return _admin_error("that is not a role")
    with accounts.with_lock():
        rows = accounts.load(_data_dir())
        account = _resolve(rows, username)
        if account is None:
            return _admin_error("no such account")
        if wanted != accounts.ADMIN and _is_last_admin(rows, account):
            return _admin_error("that is the last enabled administrator")
        account["role"] = wanted
        accounts.save(_data_dir(), rows)
        subject = str(account["username"])

    _audit("ROLE_CHANGED", subject, fields="role")
    return _admin_notice(f"{subject} is now {wanted.lower()}.")


@account_bp.post("/accounts/<username>/reset-factor")
@auth.admin_required
@csrf.required
def reset_factor(username: str) -> Response:
    """Remove somebody's second factor so they can enrol a new device.

    The recovery path for a lost phone. It is deliberately an administrator action rather
    than a self-service one: a self-service factor reset is a way past the second factor.
    """
    with accounts.with_lock():
        rows = accounts.load(_data_dir())
        account = _resolve(rows, username)
        if account is None:
            return _admin_error("no such account")
        accounts.reset_factor(account)
        accounts.clear_failures(account)
        accounts.save(_data_dir(), rows)
        subject = str(account["username"])

    _audit("FACTOR_RESET", subject, fields="totp_secret,recovery")
    return _admin_notice(f"{subject} will enrol a new device at next sign-in.")


@account_bp.post("/accounts/<username>/unlock")
@auth.admin_required
@csrf.required
def unlock(username: str) -> Response:
    """Clear a lockout early, rather than waiting it out."""
    with accounts.with_lock():
        rows = accounts.load(_data_dir())
        account = _resolve(rows, username)
        if account is None:
            return _admin_error("no such account")
        accounts.clear_failures(account)
        accounts.save(_data_dir(), rows)
        subject = str(account["username"])

    _audit("ACCOUNT_UNLOCKED", subject, fields="locked_until,failures")
    return _admin_notice(f"{subject} is unlocked.")


def _resolve(rows: list[dict[str, object]], username: str) -> dict[str, object] | None:
    """Find an account by a username that arrived in a URL, normalising it first."""
    try:
        return accounts.find(rows, accounts.normalise_username(username))
    except accounts.AccountError:
        return None


def _is_last_admin(rows: list[dict[str, object]], account: dict[str, object]) -> bool:
    """Return whether this account is the only enabled administrator left."""
    enabled = accounts.active_admins(rows)
    return len(enabled) <= 1 and any(row is account for row in enabled)


@account_bp.errorhandler(accounts.AccountError)
def _unreadable_account_list(error: accounts.AccountError) -> tuple[str, int]:
    """Answer 503 rather than 500 when the account list cannot be read.

    A different answer from the sign-in blueprint's, deliberately. There the refusal must
    write an AUD-001 row and send the caller back to the form; here the caller is already
    an authenticated administrator, nothing has changed, and the honest answer is that the
    service cannot serve this request right now.

    **Be exact about when this answers, because the first version of this docstring was wrong
    twice.** It is NOT the ordinary answer to a corrupt list. `auth.admin_required` runs
    first and calls `live_standing`, which catches the same `AccountError` and redirects, so
    a signed-in administrator meeting a corrupt list gets `302 /sign-in?next=/accounts`,
    measured, never a 503. What reaches here is the RACE: the list was readable when the
    decorator looked and unreadable when the view did. That window is real, a lost mount is
    the likeliest cause, and without this handler it is a 500 with no explanation.

    The claim that a redirect "would loop", because every error path here goes to
    `/accounts` and `/accounts` cannot be served, was also false: the decorator's redirect
    goes to `/sign-in`, which renders. Both corrections came from an engineering gate that
    drove the case rather than reading the comment.
    """
    current_app.logger.error("account administration unavailable: %s", error)
    return "The account list could not be read. An operator should check the volume.", 503


def _admin_error(reason: str) -> Response:
    return redirect(url_for(ADMIN_ENDPOINT, error=reason))


def _admin_notice(message: str) -> Response:
    return redirect(url_for(ADMIN_ENDPOINT, notice=message))
