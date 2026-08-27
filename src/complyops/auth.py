"""The authentication boundary: who is acting, and may they.

Authentication stays in the application, against Entra ID, rather than being delegated to
the platform gateway. Ash's decision, and the reason is evidential: the actor on an audit
entry comes from a verified token rather than from a header that a caller reaching the pod
directly could simply assert. That is what makes attribution defensible in front of an
assessor, and it satisfies AMD-001 section 10.4 directly.

The gate is SERVER-SIDE and fails closed. There is no client-side flag, no hidden field and
no trusted header anywhere in this module: a browser can only present a session cookie that
this process signed.

Two modes, and the difference between them is enforced, not documented:

● **Configured.** `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` and `REDIRECT_URI` are all set,
  and sign-in goes to Entra ID through the OAuth 2.0 authorisation code flow with Proof Key
  for Code Exchange (PKCE).
● **Local development.** None of them is set and `COMPLYOPS_ENV` is exactly `development`.
  The operator names themselves at sign-in and every audit entry records that the actor was
  self-asserted. Binding to the loopback address is the OPERATOR's responsibility and is
  not enforced here: `wsgi.py` binds `0.0.0.0` because the platform probe requires it, and
  no handler checks `remote_addr`. Said plainly because this list is otherwise a list of
  things the code enforces.

`COMPLYOPS_ENV` must be set to `development` to get the second mode. Anything else, an
unset variable included, is production. That default is deliberate and it is the fail-closed
direction: an unset variable costs a local developer one line, and the other way round it
silently cost the deployed application its Secure cookie flag and its identity provider.

The second mode REFUSES TO START in production. A build that quietly degrades to
"anybody may sign in as anybody" the moment a variable is missing is worse than one that
will not boot, because the failure is invisible until an assessor asks who did something.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from flask import Flask, redirect, request, session, url_for
from werkzeug.wrappers.response import Response

from . import config

#: The session keys this module owns.
ACTOR_KEY = "complyops_actor"
VERIFIED_KEY = "complyops_verified"

#: How a self-asserted actor is marked, on the session and on every audit entry it causes.
SELF_ASSERTED_SUFFIX = " (self-asserted)"


class AuthNotConfiguredError(RuntimeError):
    """Raised when the app would run unauthenticated somewhere it must not."""


def entra_is_configured() -> bool:
    """Return whether every Entra ID value needed for a real sign-in is present."""
    return all(
        config.env(name) for name in ("TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URI")
    )


#: The value that selects local development. Anything else, including an unset variable,
#: is production.
DEVELOPMENT = "development"


def is_production() -> bool:
    """Return whether this process is running in production. Unset means YES.

    The default was `development`, and it was documented in neither the environment table
    nor `.env.example`, so a deploy that followed the documentation exactly ran with
    `SESSION_COOKIE_SECURE` off, Entra ID unenforced and an ephemeral session key, all
    silently. Every one of those guards is a fail-closed control, and a fail-closed control
    whose default is "off" is not one.

    So the default is now production. A missing variable costs a local developer one line
    in their `.env`; the other way round it cost the deployed application its session
    cookie's Secure flag and its identity provider. The failure is loud in both directions:
    unconfigured production refuses to boot with a message naming what to set.
    """
    # The `.strip()` is redundant: `config.env` already normalises through `config.normalise`,
    # which strips whitespace, surrounding quotes and control characters. Kept as belt and
    # braces on a security-posture decision, and noted here because a mutation that removes
    # it survives the suite and would otherwise read as a coverage gap.
    return config.env("COMPLYOPS_ENV", "production").strip().lower() != DEVELOPMENT


def check_startup() -> None:
    """Refuse to boot in production without a real identity provider.

    The one thing this module must never do is degrade quietly. In production, unconfigured
    Entra ID is a hard stop.
    """
    if is_production() and not entra_is_configured():
        raise AuthNotConfiguredError(
            "COMPLYOPS_ENV is production but Entra ID is not configured. Set TENANT_ID, "
            "CLIENT_ID, CLIENT_SECRET and REDIRECT_URI. Refusing to start rather than "
            "accept a self-asserted actor on audit evidence."
        )


def current_actor() -> str | None:
    """Return the signed-in actor, or ``None``.

    Read from the server-signed session cookie only. Nothing here consults a request header.
    """
    actor = session.get(ACTOR_KEY)
    return actor if isinstance(actor, str) and actor else None


def actor_is_verified() -> bool:
    """Return whether the actor came from a verified token rather than self-assertion."""
    return bool(session.get(VERIFIED_KEY))


def audit_actor() -> str:
    """Return the actor as it should be recorded on an audit entry.

    A self-asserted actor is marked as such in the entry itself, so evidence produced in
    development can never be mistaken for evidence of a verified identity.
    """
    actor = current_actor() or "unknown"
    return actor if actor_is_verified() else f"{actor}{SELF_ASSERTED_SUFFIX}"


def sign_in(actor: str, *, verified: bool) -> None:
    """Record a signed-in actor on the session."""
    session.clear()
    session[ACTOR_KEY] = actor
    session[VERIFIED_KEY] = verified
    session.permanent = True


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


def new_state() -> str:
    """Return a fresh cross-site request forgery state value for the sign-in round trip."""
    return secrets.token_urlsafe(32)


def state_matches(expected: str | None, received: str | None) -> bool:
    """Compare two sign-in state values in constant time, failing closed on either missing.

    Non-ASCII fails closed rather than raising: `compare_digest` raises TypeError on a
    non-ASCII str, and this runs on an unauthenticated route, so an unhandled 500 would
    also skip the LOGIN_FAILED entry the refusal path writes.
    """
    if not expected or not received:
        return False
    if not expected.isascii() or not received.isascii():
        return False
    return hmac.compare_digest(expected, received)


def configure(app: Flask) -> None:
    """Apply the session cookie policy this application needs."""
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Secure in production only, or a local development session over plain HTTP would
        # never be sent back and the app would appear to reject every sign-in.
        SESSION_COOKIE_SECURE=is_production(),
        SESSION_COOKIE_NAME="complyops_session",
    )


def signing_secret() -> bytes:
    """Return the session signing key, generating an ephemeral one only outside production.

    An ephemeral key means every restart signs everybody out, which is the right cost in
    development and unacceptable in production, so production requires a real value.
    """
    configured = config.env("SESSION_KEY")
    if configured:
        return configured.encode("utf-8")
    if is_production():
        raise AuthNotConfiguredError(
            "SESSION_KEY is not set and COMPLYOPS_ENV is production. Refusing to start with "
            "an ephemeral session key, which would sign every user out on each restart and "
            "differ between workers."
        )
    return secrets.token_bytes(32)


def development_banner() -> str | None:
    """Return the warning to show when identities are self-asserted, or ``None``."""
    if entra_is_configured():
        return None
    return (
        "Development mode: Entra ID is not configured, so the actor below is self-asserted "
        "and every audit entry records it as such. This mode refuses to start in production."
    )


def redirect_after_sign_in(target: str | None) -> Response:
    """Return a redirect to ``target`` when it is a safe local path, else to the console.

    An open redirect would let a phishing link bounce a signed-in user off this origin, so
    only a same-site absolute path is honoured.

    Control characters and backslashes are rejected before the `//` check, and that order
    matters: Werkzeug strips a control character when it serialises the header, so
    `/<TAB>/evil.example` passed the check as a single-slash path and went out as
    `//evil.example`, which is a protocol-relative redirect off this origin.
    """
    if not target or not target.startswith("/"):
        return redirect(url_for("console.dashboard"))
    if "\\" in target or any(character < " " or character == "\x7f" for character in target):
        return redirect(url_for("console.dashboard"))
    if target.startswith("//"):
        return redirect(url_for("console.dashboard"))
    return redirect(target)


#: The Entra ID host. A constant rather than configuration, so a misconfigured value can
#: never redirect a sign-in or a client secret to somebody else's endpoint.
ENTRA_HOST = "https://login.microsoftonline.com"

#: The scopes requested. Identity only: this application reads no mailbox, no calendar and
#: no directory, and asking for what it does not need is what turns a token leak into a
#: bigger one.
ENTRA_SCOPES = "openid profile email"

#: How much clock skew is tolerated when checking a token's expiry.
CLOCK_SKEW_SECONDS = 60

#: How long the back-channel token exchange may take before it is abandoned. A sign-in that
#: hangs is a sign-in that holds a worker thread.
TOKEN_TIMEOUT_SECONDS = 10


class AuthError(RuntimeError):
    """Raised when a sign-in cannot be completed. The caller sees a generic failure."""


def authorise_endpoint() -> str:
    """Return the tenant's authorisation endpoint."""
    return f"{ENTRA_HOST}/{quote(str(config.env('TENANT_ID')), safe='')}/oauth2/v2.0/authorize"


def token_endpoint() -> str:
    """Return the tenant's token endpoint."""
    return f"{ENTRA_HOST}/{quote(str(config.env('TENANT_ID')), safe='')}/oauth2/v2.0/token"


def expected_issuer() -> str:
    """Return the issuer an identity token from this tenant must name."""
    return f"{ENTRA_HOST}/{config.env('TENANT_ID')}/v2.0"


def new_verifier() -> str:
    """Return a fresh Proof Key for Code Exchange (PKCE) verifier."""
    return secrets.token_urlsafe(64)


def challenge_for(verifier: str) -> str:
    """Return the S256 challenge for a verifier.

    PKCE binds the authorisation code to the browser that started the sign-in, so a code
    intercepted from the redirect cannot be redeemed by anybody else. A confidential client
    already holds a secret; this closes the window where the code is in a URL and the
    secret is not yet involved.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def entra_authorise_url(state: str, *, challenge: str, nonce: str) -> str:
    """Return the Entra ID authorisation URL for the configured tenant.

    Every value is URL-encoded. A configured value interpolated raw would let a stray
    ampersand in a redirect URI inject a parameter into this application's own sign-in.
    """
    query = urlencode(
        {
            "client_id": config.env("CLIENT_ID"),
            "response_type": "code",
            "redirect_uri": config.env("REDIRECT_URI"),
            "response_mode": "query",
            "scope": ENTRA_SCOPES,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    )
    return f"{authorise_endpoint()}?{query}"


def _post_form(url: str, form: dict[str, str]) -> dict[str, Any]:
    """POST a form to Entra ID over TLS and return the parsed response.

    Held in one function so a test can replace exactly this and nothing else. The URL is
    built from :data:`ENTRA_HOST`, so it is always HTTPS to Microsoft; it is asserted
    anyway, because a future edit that made the host configurable would otherwise send a
    client secret wherever that configuration pointed.
    """
    if not url.startswith(f"{ENTRA_HOST}/"):
        raise AuthError("the token endpoint is not the configured Entra ID host")
    request_body = urlencode(form).encode("ascii")
    post = Request(  # noqa: S310 - the scheme is fixed to HTTPS by the check above
        url,
        data=request_body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        # Both analysers flag urlopen because a caller-supplied URL could name file:/ or a
        # custom scheme. This one cannot: the check above requires it to begin with the
        # ENTRA_HOST literal, which is an https URL fixed in source. Suppressed with the
        # reason rather than by relaxing either analyser.
        with urlopen(post, timeout=TOKEN_TIMEOUT_SECONDS) as response:  # noqa: S310  # nosec B310
            return dict(json.loads(response.read().decode("utf-8")))
    except (OSError, ValueError) as error:
        raise AuthError(f"the token exchange failed: {type(error).__name__}") from error


def exchange_code(code: str, verifier: str) -> dict[str, Any]:
    """Redeem an authorisation code for tokens, over the back channel.

    The client secret goes only here, in a POST body to Microsoft over TLS, never into a
    URL and never near the browser.
    """
    payload = _post_form(
        token_endpoint(),
        {
            "client_id": str(config.env("CLIENT_ID")),
            "client_secret": str(config.env("CLIENT_SECRET")),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": str(config.env("REDIRECT_URI")),
            "scope": ENTRA_SCOPES,
            "code_verifier": verifier,
        },
    )
    if "id_token" not in payload:
        raise AuthError("Entra ID returned no identity token")
    return payload


def _decode_segment(segment: str) -> dict[str, Any]:
    """Decode one base64url JSON segment of a token."""
    padded = segment + "=" * (-len(segment) % 4)
    try:
        loaded = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")))
    except (ValueError, TypeError) as error:
        raise AuthError("the identity token is not readable") from error
    if not isinstance(loaded, dict):
        raise AuthError("the identity token is not an object")
    return loaded


def claims_from_id_token(id_token: str, *, nonce: str, now: float | None = None) -> dict[str, Any]:
    """Return the claims of an identity token, checking everything this build checks.

    Be precise about what this does and does not do, because it is the kind of thing that
    gets over-claimed. It checks the issuer, the audience, the expiry and the nonce. It does
    NOT verify the token's signature.

    That is sound only because of where this token came from, and only here: it was received
    in the direct response to :func:`exchange_code`, which is an HTTPS POST this process
    made to Microsoft carrying this application's own client secret. OpenID Connect Core
    section 3.1.3.7 permits TLS server validation in place of signature checking for exactly
    that back-channel case. It would NOT be sound for a token arriving any other way, so
    nothing else in this application may call this function on a token it did not just
    exchange for itself. Verifying the signature as well needs a JSON Web Key Set fetch and
    an RSA implementation, which means a new dependency; recorded as a deviation for Adam
    Field's sign-off and `TBC, re-verify` before the accreditation review.
    """
    parts = id_token.split(".")
    expected_segments = 3
    if len(parts) != expected_segments:
        raise AuthError("the identity token is not a JSON Web Token")
    claims = _decode_segment(parts[1])

    if claims.get("iss") != expected_issuer():
        raise AuthError("the identity token names another issuer")
    if claims.get("aud") != config.env("CLIENT_ID"):
        raise AuthError("the identity token was issued for another application")
    if not state_matches(
        nonce, claims.get("nonce") if isinstance(claims.get("nonce"), str) else None
    ):
        raise AuthError("the identity token does not carry this sign-in's nonce")

    moment = datetime.now(UTC).timestamp() if now is None else now
    expiry = claims.get("exp")
    if not isinstance(expiry, int | float) or moment > float(expiry) + CLOCK_SKEW_SECONDS:
        raise AuthError("the identity token has expired")
    return claims


def actor_from_claims(claims: dict[str, Any]) -> str:
    """Return the user principal name to record as the actor.

    Falls back through the claims Entra ID may or may not issue depending on the account
    type, and raises rather than inventing one: an audit entry with no real actor on it is
    worse than a refused sign-in.
    """
    for name in ("preferred_username", "upn", "email", "sub"):
        value = claims.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()[:320]
    raise AuthError("the identity token carries no usable actor claim")


def describe() -> dict[str, object]:
    """Return the authentication posture, for the diagnostics read-out."""
    return {
        "entraConfigured": entra_is_configured(),
        "production": is_production(),
        "actorVerified": actor_is_verified() if current_actor() else False,
    }


#: The flight plan's figure: an eight-hour idle timeout on a signed-in session.
SESSION_LIFETIME = timedelta(hours=8)


def install(app: Flask) -> None:
    """Wire the session policy and the startup check into an application."""
    check_startup()
    app.secret_key = signing_secret()
    app.permanent_session_lifetime = SESSION_LIFETIME
    configure(app)
