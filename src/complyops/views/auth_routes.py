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

from .. import auth, csrf, records
from ..audit import AuditFieldError
from ..audit.validation import recordable

auth_bp = Blueprint("auth", __name__)

#: Where the sign-in round trip keeps its state. All three are consumed on first use, so a
#: replayed callback has nothing to match against.
STATE_KEY = "complyops_signin_state"
VERIFIER_KEY = "complyops_signin_verifier"
NONCE_KEY = "complyops_signin_nonce"

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


def _record_authentication(action: str, actor: str, outcome: str) -> bool:
    """Write one authentication audit entry. Returns whether the ACTOR was recordable.

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
    chain = current_app.extensions.get("complyops_chain")
    if chain is None:
        current_app.logger.error("authentication event not recorded: no audit chain")
        return True
    try:
        chain.append(
            {
                "timestamp": records.now(),
                "actor": actor[:320],
                "action": action,
                "resource": "session",
                "resource_id": "sign-in",
                "outcome": outcome,
                "source_ip": _client_ip(),
                "user_agent": _user_agent(),
                "fields_changed": "",
                "old_state": "",
                "new_state": "",
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
    """Show the sign-in page, or start the Entra ID round trip when it is configured."""
    if auth.current_actor():
        return redirect(url_for("console.dashboard"))
    if auth.entra_is_configured():
        state = auth.new_state()
        verifier = auth.new_verifier()
        nonce = auth.new_state()
        session[STATE_KEY] = state
        session[VERIFIER_KEY] = verifier
        session[NONCE_KEY] = nonce
        return redirect(
            auth.entra_authorise_url(state, challenge=auth.challenge_for(verifier), nonce=nonce)
        )
    return render_template(
        "sign_in.html",
        banner=auth.development_banner(),
        next_path=request.args.get("next", ""),
    )


@auth_bp.post("/sign-in")
@csrf.required
def sign_in_submit() -> Response:
    """Accept a self-asserted actor, in development only.

    Refuses outright when Entra ID is configured, so this path cannot become a way around
    a real identity provider once one exists.
    """
    if auth.entra_is_configured():
        _record_authentication("LOGIN_FAILED", "unknown", "FAILURE")
        return redirect(url_for("auth.sign_in_page"))

    actor = (request.form.get("actor") or "").strip()
    if not actor or len(actor) > MAXIMUM_ACTOR_LENGTH:
        # A fixed placeholder, never the caller's own value. Passing the raw actor here let
        # a caller suppress their own LOGIN_FAILED entry by submitting one the audit
        # boundary refuses: a leading `=`, `-` or `@`, a non-ASCII character, or a double
        # quote. The refusal path must always leave a record, so it records nothing the
        # caller chose. `_refuse` below already does this.
        return _refuse("the submitted actor is empty or over the length cap")

    auth.sign_in(actor, verified=False)
    if not _record_authentication("LOGIN", auth.audit_actor(), "SUCCESS"):
        auth.sign_out()
        return _refuse("the actor could not be recorded on an audit entry")
    return auth.redirect_after_sign_in(request.form.get("next"))


@auth_bp.get("/auth/callback")
def entra_callback() -> Response:
    """Complete the Entra ID round trip.

    Fails closed at every step, and the caller is told nothing beyond "it did not work":
    which check refused a forged callback is information an attacker would use to build a
    better one. The reason is logged server-side and the failure is audited.

    All three round-trip values are popped before anything is checked, so a replay has
    nothing left to match against even when this request is the one that fails.
    """
    expected_state = session.pop(STATE_KEY, None)
    verifier = session.pop(VERIFIER_KEY, None)
    nonce = session.pop(NONCE_KEY, None)
    code = request.args.get("code", "")

    if not auth.state_matches(expected_state, request.args.get("state")):
        return _refuse("the callback state did not match")
    if not isinstance(verifier, str) or not isinstance(nonce, str) or not code:
        return _refuse("the callback carried no code, or the session lost its round trip")

    try:
        tokens = auth.exchange_code(code, verifier)
        claims = auth.claims_from_id_token(tokens["id_token"], nonce=nonce)
        actor = auth.actor_from_claims(claims)
    except auth.AuthError as error:
        return _refuse(str(error))

    auth.sign_in(actor, verified=True)
    if not _record_authentication("LOGIN", auth.audit_actor(), "SUCCESS"):
        # A verified identity this log cannot name is not one this application will accept.
        # AUD-001 requires the user principal name on an authentication event, and an
        # unrecorded sign-in is exactly the attribution gap in-app authentication exists to
        # close. `preferred_username` carrying a non-ASCII character lands here.
        auth.sign_out()
        return _refuse("the actor could not be recorded on an audit entry")
    return auth.redirect_after_sign_in(None)


def _refuse(reason: str) -> Response:
    """Audit a failed sign-in, log why server-side, and send the caller back generically.

    The failure is recorded against a placeholder actor, because the reason this path is
    reached may be that the real one cannot be written at all.
    """
    current_app.logger.warning("sign-in refused: %s", reason)
    if not _record_authentication("LOGIN_FAILED", "unknown", "FAILURE"):
        # `recordable` already stops a caller's own headers vetoing this entry and the
        # actor here is a fixed placeholder, so reaching this line means the boundary
        # refused something no caller controls. There is nothing left to substitute, so it
        # is logged at error rather than retried with the same values.
        current_app.logger.error("the sign-in refusal itself could not be recorded")
    return redirect(url_for("auth.sign_in_page"))


@auth_bp.post("/sign-out")
@csrf.required
def sign_out() -> Response:
    """End the session."""
    actor = auth.audit_actor()
    if auth.current_actor():
        _record_authentication("LOGOUT", actor, "SUCCESS")
    auth.sign_out()
    return redirect(url_for("auth.sign_in_page"))
