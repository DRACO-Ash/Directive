"""Cross-site request forgery protection, required by AMD-001 section 10.6.

A real boundary, not defence in depth. The session cookie is `SameSite=Lax`, which stops a
cross-site POST carrying it, but Lax is a browser behaviour and this control must not
depend on one: an older browser, a subtle redirect chain, or a future route that accepts a
different method would each erode it. So every state-changing request carries a token that
a cross-origin page cannot read.

The token is derived from the session, not stored in it, so it survives a session write
without extra bookkeeping, and it is compared in constant time.
"""

from __future__ import annotations

import functools
import hmac
import secrets
from collections.abc import Callable
from typing import Any

from flask import current_app, jsonify, request, session
from werkzeug.wrappers.response import Response

#: Where the token lives on the session, and the header a caller returns it in.
#:
#: Both analysers flag these as hardcoded credentials because the names contain "token".
#: Neither value is one: the first is a session dictionary key and the second is an HTTP
#: header name, both of which are public by construction. The actual token is generated per
#: session by `secrets.token_urlsafe` below. Suppressed at the line with the reason above,
#: rather than by relaxing either analyser.
TOKEN_KEY = "complyops_csrf"  # noqa: S105  # nosec B105
TOKEN_HEADER = "X-CSRF-Token"  # noqa: S105  # nosec B105

#: The methods that change state and therefore need a token.
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def token() -> str:
    """Return this session's token, creating one on first use."""
    existing = session.get(TOKEN_KEY)
    if isinstance(existing, str) and existing:
        return existing
    fresh = secrets.token_urlsafe(32)
    session[TOKEN_KEY] = fresh
    return fresh


def submitted() -> str | None:
    """Return the token the caller sent, from the header or the form."""
    return request.headers.get(TOKEN_HEADER) or request.form.get("csrf_token")


def valid() -> bool:
    """Return whether the caller's token matches this session's, in constant time."""
    expected = session.get(TOKEN_KEY)
    provided = submitted()
    if not isinstance(expected, str) or not expected or not provided:
        return False
    return hmac.compare_digest(expected, provided)


def required[Handler: Callable[..., Any]](handler: Handler) -> Handler:
    """Refuse a state-changing request that does not carry a valid token.

    Fails closed: a missing token, a missing session, and a mismatched token are all the
    same answer, and the answer is generic because the caller does not need to know which.
    """

    @functools.wraps(handler)
    def guarded(*args: object, **kwargs: object) -> object:
        if request.method in UNSAFE_METHODS and not valid():
            return jsonify({"error": "invalid or missing request token"}), 403
        return handler(*args, **kwargs)

    return guarded  # type: ignore[return-value]


def install(app: object) -> None:
    """Expose the token to templates, so a form can carry it without extra wiring."""
    app.jinja_env.globals["csrf_token"] = token  # type: ignore[attr-defined]


def attach_to_response(response: Response) -> Response:
    """Send the token to the single-page console, which reads it for its fetch calls.

    Safe to expose to the page: a cross-origin page cannot read a response body or a
    response header from this origin, which is precisely the property the token relies on.
    """
    if request.path.startswith("/api/") or request.path == "/":
        with current_app.app_context():
            response.headers[TOKEN_HEADER] = token()
    return response
