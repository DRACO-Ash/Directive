"""Who is signed in, and how this application decided that.

**This build authenticates against its own account list.** Microsoft Entra ID is not
available to this application: the Bluestaq Ltd tenant cannot be used for it, confirmed by
IT in November 2026. The previous implementation was an OpenID Connect client pointed at
that tenant, and it is gone. See ``docs/AUTH-REPLACEMENT-PLAN.md`` for the options that
were weighed and ``docs/ACCREDITATION-REVIEW.md`` for what that costs in policy terms.

**What replaces it, and what does not change.** The actor on an audit entry still comes
from something this application verified rather than from a header a caller could assert.
Under Entra that was a signed token; here it is a password checked against a stored hash
plus a one-time code checked against a stored secret. The property the audit log depends on
survives the change of mechanism, which was the whole point of preferring this over a
gateway that announces the user in a request header.

**Two factors, and the second is not optional in production.** A compliance system of
record behind a single factor is a worse position than the signed accreditation already
describes. An account with no enrolled second factor cannot complete a sign-in: it is sent
to enrolment and gets no session until that finishes.

**The sign-in has two halves and the first one grants nothing.** A correct password puts a
PENDING marker on the session, never an actor. `current_actor` reads only the actor key, so
every route guarded by `required` refuses a half-authenticated caller by construction
rather than by remembering to check. The marker expires on its own.

Two modes, as before:

● **Production.** `DIRECTIVE_ENV` is anything but `development`. The session cookie is
  `Secure`, `SESSION_KEY` is required, and the only way in is a real account.
● **Local development.** `DIRECTIVE_ENV` is exactly `development`, and a self-asserted
  actor is accepted so the console can be driven without a credential store. Every audit
  entry written that way is marked self-asserted, so evidence produced in development can
  never be mistaken for evidence of a verified identity.

`DIRECTIVE_ENV` must be set to `development` to get the second mode. Anything else, an
unset variable included, is production. The default was `development` once, and it was
documented in neither the environment table nor this docstring, which silently cost the
deployed application its Secure cookie flag and its identity provider.
"""

from __future__ import annotations

import functools
import hmac
import logging
import secrets
import time
from collections.abc import Callable
from datetime import timedelta
from typing import Any

from flask import Flask, redirect, request, session, url_for
from werkzeug.wrappers.response import Response

from . import accounts, config

#: The session keys. `ACTOR_KEY` is the only one `current_actor` reads, which is what makes
#: a half-finished sign-in grant nothing.
ACTOR_KEY = "directive_actor"
VERIFIED_KEY = "directive_verified"
ROLE_KEY = "directive_role"

#: The half-finished sign-in: the password was right and the second factor has not been
#: presented yet. Deliberately a different key from `ACTOR_KEY`.
PENDING_KEY = "directive_pending"
PENDING_SINCE_KEY = "directive_pending_since"

#: How long a half-finished sign-in stays open. Long enough to read a code off a phone,
#: short enough that a borrowed browser is not a standing invitation.
PENDING_SECONDS = 300

#: Appended to an actor that was self-asserted rather than verified.
SELF_ASSERTED_SUFFIX = " (self-asserted)"

#: The console's landing endpoint, and the destination every refused redirect takes.
DASHBOARD_ENDPOINT = "console.dashboard"

#: The value that selects local development. Anything else, including an unset variable,
#: is production.
DEVELOPMENT = "development"

LOGGER = logging.getLogger(__name__)


class AuthNotConfiguredError(RuntimeError):
    """Raised at start-up when production is configured without what it needs."""


def is_production() -> bool:
    """Return whether this process is running in production mode.

    The DEFAULT is production. An unset or misspelt `DIRECTIVE_ENV` gets the strict mode
    rather than the permissive one, which is the only safe direction for a variable whose
    absence would otherwise turn off the Secure cookie flag and the credential requirement.
    """
    return config.env("DIRECTIVE_ENV", "production").strip().lower() != DEVELOPMENT


def scan_mode() -> bool:
    """Return whether this process is the App Store's dynamic security scan.

    The scan runs the image with NO environment variables and expects HTTP on port 8080
    within sixty seconds. It is honoured only when `SESSION_KEY` is absent, so it cannot
    change the behaviour of a real deployment, which always has one. What it relaxes is the
    `SESSION_KEY` refusal and nothing else: the account list is still the only way in, and
    the scan has no account, so it crawls exactly the unauthenticated surface.
    """
    asserted = config.env("APPSTORE_DAST_SCAN").strip().lower() == "true"
    return asserted and not config.env("SESSION_KEY")


def check_startup() -> None:
    """Refuse to boot in production without what production needs.

    One check remains, for `SESSION_KEY`. The Entra check that used to live here is gone
    with Entra, and it is NOT replaced by a check that accounts exist, deliberately. An
    empty account list is recoverable at runtime: nobody can sign in, `/api/diagnostics`
    says how many accounts there are, and an operator fixes it by setting the bootstrap
    variables and restarting. Reading the volume to decide whether to boot would turn a
    storage fault into a crash loop, and the diagnostics read-out is the recovery channel
    for a bad configuration, so nothing in the boot path may prevent boot over it.
    """
    if is_production() and not config.env("SESSION_KEY") and not scan_mode():
        raise AuthNotConfiguredError(
            "SESSION_KEY is not set and DIRECTIVE_ENV is production. Refusing to start with "
            "an ephemeral session key, which would sign every user out on each restart and "
            "differ between workers."
        )


def local_accounts_only() -> bool:
    """Return whether a real credential is required to sign in.

    True in production. In development the self-asserted path is offered instead, and the
    banner says so on every page.
    """
    return is_production()


# ---------------------------------------------------------------- the session


def current_actor() -> str | None:
    """Return the signed-in actor, or ``None``.

    Read from the server-signed session cookie only. Nothing here consults a request header,
    and nothing here reads the PENDING key, so a caller who has given a correct password and
    no second factor is not signed in by any measure this application takes.
    """
    actor = session.get(ACTOR_KEY)
    return actor if isinstance(actor, str) and actor else None


def current_role() -> str:
    """Return the signed-in actor's role, defaulting to the lesser one."""
    role = session.get(ROLE_KEY)
    return role if isinstance(role, str) and role in accounts.ROLES else accounts.MEMBER


def actor_is_verified() -> bool:
    """Return whether the actor was authenticated rather than self-asserted."""
    return bool(session.get(VERIFIED_KEY))


def audit_actor() -> str:
    """Return the actor as it should be recorded on an audit entry.

    A self-asserted actor is marked as such in the entry itself, so evidence produced in
    development can never be mistaken for evidence of a verified identity.
    """
    actor = current_actor() or "unknown"
    return actor if actor_is_verified() else f"{actor}{SELF_ASSERTED_SUFFIX}"


def sign_in(actor: str, *, verified: bool, role: str = accounts.MEMBER) -> None:
    """Record a fully signed-in actor on the session.

    `session.clear()` first, so a pending marker from the first half cannot survive into the
    signed-in session and so no value set before authentication is carried across it.
    """
    session.clear()
    session[ACTOR_KEY] = actor
    session[VERIFIED_KEY] = verified
    session[ROLE_KEY] = role if role in accounts.ROLES else accounts.MEMBER
    session.permanent = True


def begin_second_factor(username: str) -> None:
    """Record that a password was accepted and a second factor is awaited.

    This grants nothing. It names who is halfway through, and when, so the wait can expire.
    """
    session.clear()
    session[PENDING_KEY] = username
    session[PENDING_SINCE_KEY] = time.time()
    session.permanent = False


def pending_actor(*, now: float | None = None) -> str | None:
    """Return who is halfway through a sign-in, or ``None`` if nobody or if it expired."""
    username = session.get(PENDING_KEY)
    if not isinstance(username, str) or not username:
        return None
    started = session.get(PENDING_SINCE_KEY)
    moment = time.time() if now is None else now
    try:
        age = moment - float(started)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if age < 0 or age > PENDING_SECONDS:
        return None
    return username


def abandon_second_factor() -> None:
    """Forget a half-finished sign-in."""
    session.pop(PENDING_KEY, None)
    session.pop(PENDING_SINCE_KEY, None)


def sign_out() -> None:
    """Clear the session."""
    session.clear()


def required[Handler: Callable[..., Any]](handler: Handler) -> Handler:
    """Refuse a request that carries no signed-in actor.

    Fails closed by construction: the decorator returns before the handler runs, so a route
    that forgets to check has already been checked.
    """

    @functools.wraps(handler)
    def guarded(*args: object, **kwargs: object) -> object:
        if current_actor() is None:
            if request.path.startswith("/api/"):
                return {"error": "sign-in required"}, 401
            return redirect(url_for("auth.sign_in_page", next=request.path))
        return handler(*args, **kwargs)

    return guarded  # type: ignore[return-value]


def admin_required[Handler: Callable[..., Any]](handler: Handler) -> Handler:
    """Refuse a request from anyone who is not an administrator.

    The second role this application has ever had. It exists because somebody has to create
    and disable accounts, and giving that power to everyone who can read a register would
    make the account list editable by anyone it lists.

    Stacks on top of `required` rather than replacing it: an anonymous caller gets the
    sign-in redirect, and a signed-in caller without the role gets a flat refusal with no
    hint that an administrative page exists at that address.
    """

    @functools.wraps(handler)
    def guarded(*args: object, **kwargs: object) -> object:
        if current_actor() is None:
            if request.path.startswith("/api/"):
                return {"error": "sign-in required"}, 401
            return redirect(url_for("auth.sign_in_page", next=request.path))
        if current_role() != accounts.ADMIN:
            if request.path.startswith("/api/"):
                return {"error": "not permitted"}, 403
            return redirect(url_for(DASHBOARD_ENDPOINT))
        return handler(*args, **kwargs)

    return guarded  # type: ignore[return-value]


def configure(app: Flask) -> None:
    """Apply the session cookie policy this application needs."""
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Secure in production only, or a local development session over plain HTTP would
        # never be sent back and the app would appear to reject every sign-in.
        SESSION_COOKIE_SECURE=is_production(),
        SESSION_COOKIE_NAME="directive_session",
    )


def signing_secret() -> bytes:
    """Return the session signing key, generating an ephemeral one only outside production.

    An ephemeral key means every restart signs everybody out, which is the right cost in
    development and unacceptable in production, so production requires a real value.
    """
    configured = config.env("SESSION_KEY")
    if configured:
        return configured.encode("utf-8")
    if is_production() and not scan_mode():
        raise AuthNotConfiguredError(
            "SESSION_KEY is not set and DIRECTIVE_ENV is production. Refusing to start with "
            "an ephemeral session key, which would sign every user out on each restart and "
            "differ between workers."
        )
    return secrets.token_bytes(32)


def development_banner() -> str | None:
    """Return the warning to show when identities are self-asserted, or ``None``."""
    if local_accounts_only():
        return None
    return (
        "Development mode: identities here are self-asserted, and every audit entry records "
        "them as such. This mode refuses to run in production."
    )


def constant_time_equal(expected: str | None, received: str | None) -> bool:
    """Compare two strings in constant time, failing closed on either missing.

    Non-ASCII fails closed rather than raising: `compare_digest` raises TypeError on a
    non-ASCII str, and this runs on unauthenticated routes, so an unhandled 500 would also
    skip the LOGIN_FAILED entry the refusal path writes.
    """
    if not expected or not received:
        return False
    if not expected.isascii() or not received.isascii():
        return False
    return hmac.compare_digest(expected, received)


def redirect_after_sign_in(target: str | None) -> Response:
    """Return a redirect to ``target`` when it is a safe local path, else to the console.

    An open redirect would let a phishing link bounce a signed-in user off this origin, so
    only a same-site absolute path is honoured.

    Control characters and backslashes are rejected before the `//` check, and that order
    matters: Werkzeug strips a control character when it serialises the header, so
    `/<TAB>/evil.example` passed the check as a single-slash path and went out as
    `//evil.example`, which is a protocol-relative redirect off this origin.
    """
    #: Every refusal lands on the same safe destination, named once. Three copies of the
    #: endpoint string was three chances for one of them to drift to somewhere else while
    #: still reading like a refusal.
    refused = redirect(url_for(DASHBOARD_ENDPOINT))
    if not target or not target.startswith("/"):
        return refused
    if "\\" in target or any(character < " " or character == "\x7f" for character in target):
        return refused
    if target.startswith("//"):
        return refused
    return redirect(target)


# ---------------------------------------------------------------- the account list


def bootstrap_configured() -> bool:
    """Return whether a first administrator can be created from the environment."""
    return bool(config.env("BOOTSTRAP_ADMIN") and config.env("BOOTSTRAP_ADMIN_PASSWORD"))


def ensure_bootstrap(data_dir: str) -> bool:
    """Create the first administrator from the environment, if there are no accounts.

    Returns whether an account was created. Runs only while the list is EMPTY, so it cannot
    resurrect a disabled administrator or reset a real one: once anybody exists, the
    bootstrap variables do nothing at all.

    The created account must change its password at first sign-in, so the value that
    travelled through the platform's environment is replaced by one only the person knows.
    The operator should then remove `BOOTSTRAP_ADMIN_PASSWORD`; leaving it set is harmless
    while accounts exist, but an unused credential in a configuration store is a credential
    somebody eventually reuses.
    """
    username = config.env("BOOTSTRAP_ADMIN")
    password = config.env("BOOTSTRAP_ADMIN_PASSWORD")
    if not username or not password:
        return False
    with accounts.with_lock():
        rows = accounts.load(data_dir)
        if rows:
            return False
        try:
            created = accounts.new_account(username, password, role=accounts.ADMIN)
        except accounts.AccountError:
            LOGGER.exception("bootstrap administrator not created")
            return False
        accounts.save(data_dir, [created])
    LOGGER.warning(
        "bootstrap: created the first administrator %r from the environment. It must change "
        "its password at first sign-in. Remove BOOTSTRAP_ADMIN_PASSWORD once that is done.",
        created["username"],
    )
    return True


def break_glass_unlock(data_dir: str) -> bool:
    """Clear a lockout on the bootstrap administrator, when the operator asks at boot.

    **This exists because the documented recovery did not work.** An unauthenticated caller
    can lock any account by guessing its password 10 times, usernames here are work email
    addresses and therefore guessable, and 10 guesses every 15 minutes holds a lock open
    indefinitely. `/accounts/<username>/unlock` is behind `admin_required`, so it is
    reachable only from an administrator session that was already open when the lock
    landed. With one administrator and no live session, the application could not be
    administered at all until somebody hand-edited the account file on the volume, and
    `docs/DEPLOYMENT.md` told the operator to correct the environment and restart, which
    `ensure_bootstrap` ignores the moment any account exists. A security gate found it.

    Three things bound what this can do, and each is deliberate.

    ● **It runs only when `BOOTSTRAP_UNLOCK` is set to `true`.** Not on every boot: a
      container that is crash-looping would otherwise clear the lock as fast as the lock
      was earned, which hands the attacker the lockout's removal for free. The operator
      sets the variable, restarts, signs in, and removes it again.
    ● **It clears the LOCKOUT and nothing else.** Not the password, not the second factor,
      not the role, not the state. Whoever holds the environment channel can already
      replace this application wholesale, but a recovery that silently reset a credential
      would be a back door with a runbook, and the narrow one is as useful.
    ● **It writes to the log before it is useful to anybody.** The entry is written by the
      caller, in the application factory, where the audit chain exists.

    Returns whether a lock was actually cleared, so the caller writes an entry only when
    something happened.
    """
    if config.env("BOOTSTRAP_UNLOCK").strip().lower() != "true":
        return False
    username = config.env("BOOTSTRAP_ADMIN")
    if not username:
        return False
    with accounts.with_lock():
        rows = accounts.load(data_dir)
        try:
            account = accounts.find(rows, accounts.normalise_username(username))
        except accounts.AccountError:
            return False
        if account is None or not accounts.is_locked(account):
            return False
        accounts.clear_failures(account)
        accounts.save(data_dir, rows)
    LOGGER.warning(
        "bootstrap: cleared the lockout on %r because BOOTSTRAP_UNLOCK is set. Remove that "
        "variable once the sign-in has succeeded.",
        account["username"],
    )
    return True


def describe(data_dir: str | None = None) -> dict[str, object]:
    """Return the authentication posture, for the diagnostics read-out.

    Counts, never names. The number of accounts tells an operator whether a deployment is
    usable; the list of who they are is not something an unauthenticated caller needs, and
    `/api/diagnostics` splits exactly on that line.
    """
    posture: dict[str, object] = {
        "mode": "local-accounts" if local_accounts_only() else "self-asserted",
        "production": is_production(),
        "actorVerified": actor_is_verified() if current_actor() else False,
        "bootstrapConfigured": bootstrap_configured(),
    }
    if data_dir:
        try:
            rows = accounts.load(data_dir)
        except accounts.AccountError:
            posture["accounts"] = "unreadable"
            posture["administrators"] = "unreadable"
        else:
            posture["accounts"] = len(rows)
            posture["administrators"] = len(accounts.active_admins(rows))
    return posture


#: The flight plan's figure: an eight-hour idle timeout on a signed-in session.
SESSION_LIFETIME = timedelta(hours=8)


def install(app: Flask) -> None:
    """Wire the session policy and the startup check into an application."""
    check_startup()
    app.secret_key = signing_secret()
    app.permanent_session_lifetime = SESSION_LIFETIME
    configure(app)
