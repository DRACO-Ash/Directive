"""Sign-in and sign-out, and the audit entries both produce.

AUD-001 requires an authentication event to record the timestamp, the user principal name,
the source address, the user agent, and success or failure. All five are written here, and
they are the reason `source_ip` and `user_agent` are in the audit field set at all: they are
deliberately collected personal data under legitimate interest per POL-002 section 03, not
an accident to be minimised away.
"""

from __future__ import annotations

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for
from werkzeug.wrappers.response import Response

from .. import accounts, auth, csrf, records, totp
from ..audit import AuditFieldError
from ..audit.validation import recordable
from . import refusals

#: Where every refused or failed sign-in returns the caller. Named once so three
#: copies cannot drift to three different destinations.
SIGN_IN_ENDPOINT = "auth.sign_in_page"

auth_bp = Blueprint("auth", __name__)


def _data_dir() -> str:
    """Return the configured data directory."""
    return str(current_app.config["DIRECTIVE_DATA_DIR"])


#: Where the sign-in keeps the page the caller was heading for, across the second factor.
#: A path only, and it goes through `redirect_after_sign_in`, which refuses anything but a
#: same-site absolute path.
NEXT_KEY = "directive_signin_next"

#: The longest self-asserted actor accepted, well inside the audit field's 320-byte cap.
MAXIMUM_ACTOR_LENGTH = 200


def _client_ip() -> str:
    """Return the caller's address as the audit entry should record it.

    `request.remote_addr` only, never `X-Forwarded-For`: a header a caller can set is not
    evidence, and recording a spoofable value as though it were fact is worse than
    recording the proxy's own address. The platform terminates at a known ingress, so the
    resolved address is what the container actually saw.
    """
    return recordable("source_ip", request.remote_addr or "unknown")


def _user_agent() -> str:
    """Return the caller's user agent, capped to the audit field's limit."""
    return recordable("user_agent", request.headers.get("User-Agent") or "unknown")


def record_event(  # noqa: PLR0913
    action: str,
    actor: str,
    outcome: str,
    *,
    collapsed: int = 0,
    source_ip: str | None = None,
    resource_id: str = "sign-in",
    resource: str = "session",
    fields_changed: str = "",
) -> bool:
    """Write one authentication or administration audit entry.

    Returns whether the ACTOR was recordable. Eight parameters, above the analyser's bound
    of six, and they are not a sign this should be split: each one is a distinct column of
    the AUD-001 event field set, and collapsing any pair of them into a dictionary would
    move the type checking from the call site to runtime on the path that writes evidence.


    The two failure modes are different and conflating them was a real hole. An
    unrecordable ACTOR is a property of this sign-in and will not fix itself: an Entra
    `preferred_username` carrying a non-ASCII character used to be swallowed here, so the
    operator signed in with no AUD-001 authentication record at all, which defeats the
    whole reason authentication stays in this application. That now returns False and the
    caller refuses the sign-in.

    An unavailable LOG is transient infrastructure, and refusing every sign-in during a
    volume fault would lock the operator out of the diagnostics that explain it. The
    sign-in proceeds, loudly logged, and the session can still change nothing: every
    mutating route already fails closed without a chain.
    """
    #: Typed rather than left as the `Any` that `extensions.get` returns, and the type is
    #: load-bearing rather than documentation. The audit-entry pin exempts a receiver that is
    #: annotated `list[...]`, because a list is not the chain; `Any` made that exemption
    #: claimable by writing `written: list[dict[str, str]] = chain`, which mypy accepted and
    #: which then carried a computed key to the boundary unchecked. With the protocol here,
    #: the same line is an assignment error on the type leg of the verification loop.
    chain: records.AppendsAudit | None = current_app.extensions.get("directive_chain")
    if chain is None:
        current_app.logger.error("authentication event not recorded: no audit chain")
        return True
    try:
        chain.append(
            {
                "timestamp": records.now(),
                "actor": actor[:320],
                "action": action,
                "resource": resource,
                "resource_id": recordable("resource_id", resource_id),
                "outcome": outcome,
                "source_ip": recordable("source_ip", source_ip) if source_ip else _client_ip(),
                "user_agent": _user_agent(),
                "fields_changed": fields_changed,
                "old_state": "",
                # A collapsed count rides in `new_state` because it is the only field with
                # room for it under the boundary rules, and it reads correctly there: the
                # entry's state IS "this many more of the same". Upper snake with digits,
                # inside the 32-character cap.
                "new_state": f"REPEATED_{collapsed}" if collapsed else "",
            }
        )
    except AuditFieldError as error:
        current_app.logger.warning("authentication actor is not recordable: %s", error)
        return False
    except Exception:
        current_app.logger.exception("authentication event not recorded")
    return True


@auth_bp.get("/sign-in")
def sign_in_page() -> str | Response:
    """Show the sign-in form."""
    if auth.current_actor():
        return redirect(url_for(auth.DASHBOARD_ENDPOINT))
    return render_template(
        "sign_in.html",
        banner=auth.development_banner(),
        local=auth.local_accounts_only(),
        next_path=request.args.get("next", ""),
    )


@auth_bp.post("/sign-in")
@csrf.required
def sign_in_submit() -> Response:
    """Check a password, then send the caller to the second factor.

    A correct password grants NOTHING here. It sets a pending marker, and `current_actor`
    does not read that marker, so every route behind `auth.required` refuses a caller who
    has got this far and no further.
    """
    if auth.scan_mode():
        # The platform's security scan boots the image with no environment and no account
        # list. It must not be handed a session, and this clause is why it is not.
        return _refuse("the sign-in is refused during the platform security scan")

    if not auth.local_accounts_only():
        return _self_asserted_sign_in()

    auth.ensure_bootstrap(_data_dir())
    try:
        username = accounts.normalise_username(request.form.get("username"))
    except accounts.AccountError:
        # Never the caller's own value in the reason, for the same reason the self-asserted
        # path below passes a fixed placeholder: a refusal message is not a mirror.
        accounts.absorb_timing()
        return _refuse("the submitted username is not usable")

    with accounts.with_lock():
        rows = accounts.load(_data_dir())
        account = accounts.find(rows, username)
        if not accounts.may_sign_in(account):
            # Disabled, locked, or no such account, and the caller is told the same thing in
            # all three cases. The hashing effort is spent anyway: without it, an unknown
            # username returns in microseconds and a real one takes 430 milliseconds, which
            # tells an unauthenticated caller which usernames exist.
            accounts.absorb_timing()
            return _refuse(f"{username!r} cannot sign in: absent, disabled or locked")
        assert account is not None  # noqa: S101 - narrowed by `may_sign_in` above
        stored = str(account.get("password", ""))
        if not accounts.verify_password(stored, request.form.get("password")):
            locked = accounts.record_failure(account)
            accounts.save(_data_dir(), rows)
            if locked:
                record_event("ACCOUNT_LOCKED", username, "FAILURE", resource_id=username)
            return _refuse(f"the password for {username!r} did not match")
        enrolled = accounts.is_enrolled(account)

    auth.begin_second_factor(username)
    session[NEXT_KEY] = request.form.get("next", "")
    return redirect(url_for("auth.enrol_page" if not enrolled else "auth.verify_page"))


def _self_asserted_sign_in() -> Response:
    """Accept a self-asserted actor, in development only.

    Unchanged in substance from the Entra build: the mode exists so the console can be
    driven without a credential store, and every entry it writes is marked self-asserted.
    """
    actor = (request.form.get("username") or request.form.get("actor") or "").strip()
    if not actor or len(actor) > MAXIMUM_ACTOR_LENGTH:
        # A fixed placeholder, never the caller's own value. Passing the raw actor here let
        # a caller suppress their own LOGIN_FAILED entry by submitting one the audit
        # boundary refuses: a leading `=`, `-` or `@`, a non-ASCII character, or a double
        # quote. The refusal path must always leave a record, so it records nothing the
        # caller chose. `_refuse` below already does this.
        return _refuse("the submitted actor is empty or over the length cap")

    auth.sign_in(actor, verified=False)
    if not record_event("LOGIN", auth.audit_actor(), "SUCCESS"):
        auth.sign_out()
        return _refuse("the actor could not be recorded on an audit entry")
    return auth.redirect_after_sign_in(request.form.get("next"))


@auth_bp.get("/sign-in/verify")
def verify_page() -> str | Response:
    """Ask for the one-time code from the authenticator app."""
    username = auth.pending_actor()
    if not username:
        return redirect(url_for(SIGN_IN_ENDPOINT))
    return render_template("verify.html", username=username)


@auth_bp.post("/sign-in/verify")
@csrf.required
def verify_submit() -> Response:
    """Complete a sign-in with the second factor, or with a recovery code."""
    username = auth.pending_actor()
    if not username:
        return _refuse("the second factor was presented with no pending sign-in")

    supplied = (request.form.get("code") or "").strip()
    with accounts.with_lock():
        rows = accounts.load(_data_dir())
        account = accounts.find(rows, username)
        if not accounts.may_sign_in(account):
            auth.abandon_second_factor()
            return _refuse(f"{username!r} cannot sign in: absent, disabled or locked")
        assert account is not None  # noqa: S101 - narrowed by `may_sign_in` above

        used_recovery = False
        if accounts.verify_code(account, supplied):
            pass
        elif accounts.spend_recovery_code(account, supplied):
            used_recovery = True
        else:
            locked = accounts.record_failure(account)
            accounts.save(_data_dir(), rows)
            if locked:
                record_event("ACCOUNT_LOCKED", username, "FAILURE", resource_id=username)
            return _refuse(f"the second factor for {username!r} did not match")

        accounts.clear_failures(account)
        accounts.save(_data_dir(), rows)
        role = str(account.get("role", accounts.MEMBER))
        must_change = bool(account.get("must_change_password"))
        remaining = len(account.get("recovery", []))

    return _complete_sign_in(
        username,
        role=role,
        must_change=must_change,
        recovery_used=used_recovery,
        remaining=remaining,
    )


def _complete_sign_in(
    username: str, *, role: str, must_change: bool, recovery_used: bool, remaining: int
) -> Response:
    """Establish the session and write the LOGIN entry, or refuse and leave nothing behind."""
    auth.sign_in(username, verified=True, role=role)
    if not record_event("LOGIN", auth.audit_actor(), "SUCCESS"):
        # A verified identity this log cannot name is not one this application will accept.
        # AUD-001 requires the user principal name on an authentication event, and an
        # unrecorded sign-in is exactly the attribution gap this application exists to close.
        auth.sign_out()
        return _refuse("the actor could not be recorded on an audit entry")
    if recovery_used:
        record_event("RECOVERY_CODE_USED", auth.audit_actor(), "SUCCESS", resource_id=username)
        current_app.logger.warning(
            "%r signed in with a recovery code; %d remain", username, remaining
        )
    target = session.pop(NEXT_KEY, "")
    if must_change:
        # Straight to the change-password page, which refuses to let anything else happen
        # until it is done. The bootstrap password travelled through a configuration store.
        return redirect(url_for("account.password_page"))
    return auth.redirect_after_sign_in(target)


@auth_bp.get("/sign-in/enrol")
def enrol_page() -> str | Response:
    """Show the second-factor secret, once, for an account that has none."""
    username = auth.pending_actor()
    if not username:
        return redirect(url_for(SIGN_IN_ENDPOINT))
    with accounts.with_lock():
        rows = accounts.load(_data_dir())
        account = accounts.find(rows, username)
        if account is None or accounts.is_enrolled(account):
            return redirect(url_for(SIGN_IN_ENDPOINT))
        #: Reuse a pending secret rather than issuing a new one on every load. This GET
        #: used to mint one each time, so refreshing the page after scanning the key made
        #: the code in the app stop working, with nothing on screen to say why. Idempotent
        #: now: the secret changes only when a fresh sign-in starts enrolment over.
        secret = str(account.get("totp_pending") or "")
        if not secret:
            secret = accounts.begin_enrolment(account)
            accounts.save(_data_dir(), rows)
    return render_template(
        "enrol.html",
        username=username,
        secret=secret,
        uri=totp.provisioning_uri(secret, actor=username, issuer="Directive"),
    )


@auth_bp.post("/sign-in/enrol")
@csrf.required
def enrol_submit() -> Response:
    """Confirm enrolment, then sign the person in and show their recovery codes once."""
    username = auth.pending_actor()
    if not username:
        return _refuse("enrolment was submitted with no pending sign-in")

    with accounts.with_lock():
        rows = accounts.load(_data_dir())
        account = accounts.find(rows, username)
        if not accounts.may_sign_in(account):
            auth.abandon_second_factor()
            return _refuse(f"{username!r} cannot sign in: absent, disabled or locked")
        assert account is not None  # noqa: S101 - narrowed by `may_sign_in` above
        codes = accounts.finish_enrolment(account, request.form.get("code"))
        if codes is None:
            return _refuse(f"the enrolment code for {username!r} did not match")
        accounts.clear_failures(account)
        accounts.save(_data_dir(), rows)
        role = str(account.get("role", accounts.MEMBER))
        must_change = bool(account.get("must_change_password"))

    auth.sign_in(username, verified=True, role=role)
    if not record_event("LOGIN", auth.audit_actor(), "SUCCESS"):
        auth.sign_out()
        return _refuse("the actor could not be recorded on an audit entry")
    record_event("FACTOR_ENROLLED", auth.audit_actor(), "SUCCESS", resource_id=username)
    # The ONLY time these exist in plaintext. They are hashed on the account and this
    # response is the one place they are rendered.
    return render_template(
        "recovery.html",
        codes=codes,
        must_change=must_change,
    )  # type: ignore[return-value]


def _refuse(reason: str) -> Response:
    """Audit a failed sign-in, log why server-side, and send the caller back generically.

    The failure is recorded against a placeholder actor, because the reason this path is
    reached may be that the real one cannot be written at all.

    Repeats from one source address are collapsed. These routes are unauthenticated by
    necessity and every refusal writes one durable fsynced entry, so a bare loop against
    `/auth/callback` could fill the log to its refusal cap and leave the audit path
    unavailable at the next restart. AUD-001 wants the record, so the entries are counted
    rather than dropped, and a count is better evidence than a hundred identical rows.
    """
    current_app.logger.warning("sign-in refused: %s", reason)
    decision = refusals.note(_client_ip())
    if decision.flood is not None:
        # The global overflow of a closed window. No per-address attribution by
        # construction: it is the trade `GLOBAL_ROWS_PER_WINDOW` exists to make, and the
        # addresses are in the platform's ingress log.
        record_event(
            "LOGIN_FAILED_FLOOD",
            "unknown",
            "FAILURE",
            collapsed=decision.flood.refusals,
            source_ip="multiple",
            resource_id=(
                f"addresses-{decision.flood.addresses}"
                if decision.flood.exact
                else f"addresses-atleast-{decision.flood.addresses}"
            ),
        )
    for collapsed in decision.collapsed:
        # One entry per address, not one total. A summary that merged several addresses
        # would collapse the attribution as well as the rows, which is the opposite of what
        # this is for.
        record_event(
            "LOGIN_FAILED_REPEATED",
            "unknown",
            "FAILURE",
            collapsed=collapsed.count,
            source_ip=collapsed.address,
        )
    if not decision.record:
        return redirect(url_for(SIGN_IN_ENDPOINT))
    if not record_event("LOGIN_FAILED", "unknown", "FAILURE"):
        # `recordable` already stops a caller's own headers vetoing this entry and the
        # actor here is a fixed placeholder, so reaching this line means the boundary
        # refused something no caller controls. There is nothing left to substitute, so it
        # is logged at error rather than retried with the same values.
        current_app.logger.error("the sign-in refusal itself could not be recorded")
    return redirect(url_for(SIGN_IN_ENDPOINT))


@auth_bp.post("/sign-out")
@csrf.required
def sign_out() -> Response:
    """End the session."""
    actor = auth.audit_actor()
    if auth.current_actor():
        record_event("LOGOUT", actor, "SUCCESS")
    auth.sign_out()
    return redirect(url_for(SIGN_IN_ENDPOINT))
