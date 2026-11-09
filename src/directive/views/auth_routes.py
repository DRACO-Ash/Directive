"""Sign-in and sign-out, and the audit entries both produce.

AUD-001 requires an authentication event to record the timestamp, the user principal name,
the source address, the user agent, and success or failure. All five are written here, and
they are the reason `source_ip` and `user_agent` are in the audit field set at all: they are
deliberately collected personal data under legitimate interest per POL-002 section 03, not
an accident to be minimised away.
"""

from __future__ import annotations

from typing import Any

from flask import (
    Blueprint,
    current_app,
    has_request_context,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
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

#: The token naming the unconfirmed second-factor secret THIS sign-in was shown. Held on
#: the session; the secret itself stays on the volume, because the session cookie is signed
#: and not encrypted.
ENROLMENT_KEY = "directive_enrolment"

#: The longest self-asserted actor accepted, well inside the audit field's 320-byte cap.
MAXIMUM_ACTOR_LENGTH = 200

#: The cap on the post-sign-in target held across the second factor. Longer than any route
#: this application serves and shorter than anything worth carrying in a cookie.
#:
#: Capped at the WRITE rather than at the read, because the value is stored: uncapped, a
#: 200,000-character `next` went into the session verbatim, and although `itsdangerous`
#: compresses it to a few hundred cookie bytes the server re-inflates the whole of it on
#: every later request in that session. Reachable only after a correct password and bounded
#: by the worker's own header limit, so the amplification is small; it is still an untrusted
#: value crossing a boundary without a bound, which the hard rules do not allow.
MAXIMUM_NEXT_LENGTH = 512


def _client_ip() -> str:
    """Return the caller's address as the audit entry should record it.

    `request.remote_addr` only, never `X-Forwarded-For`: a header a caller can set is not
    evidence, and recording a spoofable value as though it were fact is worse than
    recording the proxy's own address. The platform terminates at a known ingress, so the
    resolved address is what the container actually saw.

    Outside a request it is `boot`, not `unknown`. The break-glass unlock writes an entry
    from the application factory where there is no caller at all, and `unknown` would read
    as "a caller whose address we failed to resolve", which is a different and misleading
    claim. A reader of the log can tell the two apart.
    """
    if not has_request_context():
        return "boot"
    return recordable("source_ip", request.remote_addr or "unknown")


def _user_agent() -> str:
    """Return the caller's user agent, capped to the audit field's limit."""
    if not has_request_context():
        return "boot"
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
    """Show the sign-in form.

    The bounce to the dashboard asks `live_role` rather than `current_actor`, and the
    difference matters in exactly one case: an account list that cannot be read. There the
    session is NOT cleared, deliberately, so a volume fault does not destroy everybody's
    session, and a caller holding a valid cookie would otherwise be bounced here by the
    dashboard and bounced straight back by this line. Asking the same authority both routes
    ask leaves the form rendered instead of a redirect loop.
    """
    if auth.live_role() is not None:
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
        stored = str(account.get("password", ""))
        refusal = ""
        try:
            matched = accounts.verify_password(stored, request.form.get("password"))
        except accounts.ServiceBusyError:
            # Caught BEFORE anything is recorded, and this clause is the whole finding.
            # The busy case used to arrive here as a plain `False`, so a capacity event
            # counted against the lockout budget: ten of them locked the account for 900
            # seconds and wrote an AUD-001 `ACCOUNT_LOCKED` entry blaming credentials that
            # were correct. Nothing about this says the password was wrong, so nothing is
            # written, nothing is saved, and the attempt is not counted.
            refusal = f"the sign-in for {username!r} could not be hashed: service busy"
        else:
            if not matched:
                locked = accounts.record_failure(account)
                accounts.save(_data_dir(), rows)
                if locked:
                    record_event("ACCOUNT_LOCKED", username, "FAILURE", resource_id=username)
                refusal = f"the password for {username!r} did not match"
        if refusal:
            # One exit for both refusals rather than two, to stay inside the analyser's
            # return-statement cap. They do different things on the way here and say
            # different things in the log, which is what matters.
            return _refuse(refusal)
        enrolled = accounts.is_enrolled(account)
        epoch = accounts.epoch_of(account)

    auth.begin_second_factor(username, epoch=epoch)
    session[NEXT_KEY] = request.form.get("next", "")[:MAXIMUM_NEXT_LENGTH]
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

    # Epoch zero, because there is no account record to take one from: the self-asserted
    # path exists so the console can be driven without a credential store, and
    # `live_standing` exempts development from the live check entirely, so nothing compares
    # it. Passed explicitly rather than defaulted, because the parameter has no default.
    auth.sign_in(actor, verified=False, epoch=0)
    if not record_event("LOGIN", auth.audit_actor(), "SUCCESS"):
        auth.sign_out()
        return _refuse("the actor could not be recorded on an audit entry")
    return auth.redirect_after_sign_in(request.form.get("next"))


def _pending_refusal(account: dict[str, Any], username: str) -> str:
    """Return why this half-finished sign-in may not complete, or an empty string.

    One helper for both second-factor routes, because the conditions are the same at each
    and a check written twice is a check that diverges. It also keeps each route inside the
    analyser's return-statement cap.

    `may_sign_in` stays at the call sites rather than moving in here, and that is not an
    oversight: it is a `TypeGuard`, so calling it inline is what narrows `account` from
    `dict | None` for the rest of the handler. Wrapping it would hand the narrowing back and
    put a `cast` or an `assert` in its place, and this module has just removed three such
    asserts for being removable under `-O`.
    """
    if not auth.pending_epoch_matches(account):
        # The password or the second factor changed after this sign-in started. An attacker
        # holding the old password got the marker, the owner then changed the password, and
        # the marker still completed: a gate drove that end to end.
        return f"the sign-in for {username!r} began before a credential change"
    if accounts.epoch_of(account) >= accounts.FAR_FUTURE_STEP:
        # An unreadable `session_epoch` on the stored record. Refuse rather than mint a
        # session carrying the sentinel: `epoch_of` fails closed for the sessions that
        # already existed, and a fresh sign-in would otherwise match it and be the one
        # session a corrupt field could not evict. An administrator fixes the record.
        return f"the stored session epoch for {username!r} is unreadable"
    return ""


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
        blocked = _pending_refusal(account, username)
        if blocked:
            auth.abandon_second_factor()
            return _refuse(blocked)

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
        epoch = accounts.epoch_of(account)

    return _complete_sign_in(
        username,
        role=role,
        must_change=must_change,
        recovery_used=used_recovery,
        remaining=remaining,
        epoch=epoch,
    )


def _complete_sign_in(
    username: str,
    *,
    role: str,
    must_change: bool,
    recovery_used: bool,
    remaining: int,
    epoch: int,
) -> Response:
    """Establish the session and write the LOGIN entry, or refuse and leave nothing behind.

    The post-sign-in target is read BEFORE the session is established, and that ordering is
    the fix for a defect rather than a preference. `auth.sign_in` calls `session.clear()`,
    deliberately, so that nothing set before authentication survives it; the pop below used
    to run after that call and therefore always returned the empty string. Every sign-in
    through the second factor landed on the dashboard whatever link the person followed,
    and three places in this module describe a `next` that could not work. It failed safe,
    which is why nothing noticed.

    Carrying the value across the boundary is safe because it is not trusted on the other
    side: `auth.redirect_after_sign_in` resolves it against this origin and falls back to
    the dashboard. The suite holds that on this path with four hostile payloads and on the
    one-step path with six more; a gate separately drove thirty-three through the live
    routes, scheme-relative, absolute, backslash, tab, encoded-tab, NUL, fullwidth solidus
    and a CRLF header split among them, and found every one landing same-origin. That last
    figure describes a gate run rather than anything a reader of this repository can check,
    which is why the tests are named first: an earlier version of this sentence cited only
    the gate, and a gate pointed out that nothing in the tree supported it.
    """
    target = session.get(NEXT_KEY, "")
    auth.sign_in(username, verified=True, role=role, epoch=epoch)
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
    if must_change:
        # Straight to the change-password page. Be exact about what this is: it LANDS the
        # caller there, and the page says why. It does NOT refuse every other route until
        # the change is done, and the sentence here used to say it did. The session is a
        # full one by this point, so an account that navigates away keeps the password it
        # was given. That is a nudge rather than a gate, and the bootstrap password is the
        # one case where it matters, because that value travelled through the platform's
        # environment: `docs/DEPLOYMENT.md` tells the operator to remove the variable once
        # the first sign-in is done, which is the control that actually bounds it.
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
        #: `may_sign_in`, not merely "exists and is unenrolled". Both sibling routes check
        #: it and this one did not, so an account disabled between the first factor and the
        #: second was still shown a fresh secret and still had `totp_pending` written to its
        #: row in the credential store. The POST was correctly refused, so nothing was
        #: gained beyond one write and one disclosure of a secret that opens nothing; it was
        #: still a half-authenticated caller writing to the account file after revocation.
        if not accounts.may_sign_in(account) or accounts.is_enrolled(account):
            auth.abandon_second_factor()
            return redirect(url_for(SIGN_IN_ENDPOINT))
        #: Reuse a pending secret rather than issuing a new one on every load. This GET
        #: used to mint one each time, so refreshing the page after scanning the key made
        #: the code in the app stop working, with nothing on screen to say why.
        #:
        #: Reused for THIS SIGN-IN only, which is the part that was wrong. The reuse read
        #: the account, so two callers who both knew the password were shown the same
        #: secret, and a gate drove the takeover that follows from it: an attacker loads
        #: this page first, the owner is then shown the attacker's secret, confirms it, and
        #: the attacker holds the account's live second factor. No administrator action is
        #: needed. The token names one half-finished sign-in and lives on the session;
        #: another session gets a fresh secret, and only the holder can confirm one.
        secret = accounts.pending_secret_for(account, session.get(ENROLMENT_KEY))
        if not secret:
            secret, token = accounts.begin_enrolment(account)
            accounts.save(_data_dir(), rows)
            session[ENROLMENT_KEY] = token
    return _never_stored(
        render_template(
            "enrol.html",
            username=username,
            secret=secret,
            uri=totp.provisioning_uri(secret, actor=username, issuer="Directive"),
        )
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
        blocked = _pending_refusal(account, username)
        if blocked:
            auth.abandon_second_factor()
            return _refuse(blocked)
        codes = accounts.finish_enrolment(
            account, request.form.get("code"), token=session.get(ENROLMENT_KEY)
        )
        if codes is None:
            return _refuse(f"the enrolment code for {username!r} did not match")
        accounts.clear_failures(account)
        accounts.save(_data_dir(), rows)
        role = str(account.get("role", accounts.MEMBER))
        must_change = bool(account.get("must_change_password"))
        epoch = accounts.epoch_of(account)

    auth.sign_in(username, verified=True, role=role, epoch=epoch)
    if not record_event("LOGIN", auth.audit_actor(), "SUCCESS"):
        auth.sign_out()
        return _refuse("the actor could not be recorded on an audit entry")
    record_event("FACTOR_ENROLLED", auth.audit_actor(), "SUCCESS", resource_id=username)
    # The ONLY time these exist in plaintext. They are hashed on the account and this
    # response is the one place they are rendered.
    return _never_stored(
        render_template(
            "recovery.html",
            codes=codes,
            must_change=must_change,
        )
    )


def _never_stored(body: str) -> Response:
    """Return a response carrying a plaintext secret, marked so no cache may keep it.

    The two pages this wraps are the only ones that render a secret in plaintext: the
    enrolment page carries the base32 setup key and the whole `otpauth://` URI, and the
    recovery page carries all ten codes. Without this a browser may heuristically write
    the only plaintext copy of somebody's second factor to disk, and the back button
    re-renders it on a shared machine. `no-store` is the one directive that covers both,
    and `Pragma` is there for a proxy old enough to ignore `Cache-Control`.

    Nothing else on this blueprint needs it: the sign-in and verify forms carry a request
    token, which is per-session and short-lived, and the console's own responses carry
    register data that the person is entitled to see again.
    """
    response = make_response(body)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response


@auth_bp.errorhandler(accounts.AccountError)
def _unreadable_account_list(error: accounts.AccountError) -> Response:
    """Turn an account list this process cannot READ into a recorded refusal, never a 500.

    Every route on this blueprint is unauthenticated by necessity and every one of them
    reads the account list. With the file corrupt, `accounts.load` raised out of the view
    and Flask answered 500 with NO audit entry at all, against `_refuse`'s stated contract
    that the refusal path always leaves a record. A security gate demonstrated it. The
    generic 500 page leaked nothing, so this is about the missing evidence rather than
    about disclosure: AUD-001 wants a row for a failed authentication, and "the volume is
    corrupt" is a failed authentication.

    Registered as a handler rather than wrapped around each of the four reads, because a
    `try` per call site is four places to forget and this is one. `ServiceBusyError` is a
    subclass and is caught explicitly upstream, so it never reaches here.

    **The reach of this handler depends on `accounts.load` converting EVERY operating-system
    error, and for one round it did not.** `Path.exists` sat outside that function's `try`,
    and it swallows only a handful of errno values, so EACCES from a restricted mount came
    through as a bare `OSError`, missed this handler, and answered 500 with no audit entry:
    the opposite of what the paragraph above claims, measured by a gate. The class had been
    narrowed to the unparseable-JSON trigger rather than closed. Fixed in `accounts.load`
    rather than here, because a handler can only catch what the layer below it raises.
    """
    current_app.logger.error("sign-in refused: the account list could not be read: %s", error)
    return _refuse("the account list could not be read")


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
