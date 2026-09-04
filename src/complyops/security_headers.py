"""Response security headers, required by AMD-001 section 10.6.

The policy names four: Content-Security-Policy, Strict-Transport-Security,
X-Content-Type-Options and X-Frame-Options, applied to all responses. All four are set
here, on every response including a health probe and an error page, because a header
applied selectively is a header an attacker reaches the exception to.

Defence in depth, not a boundary. The real boundaries are authentication against Entra
ID, the server-side authorisation check, and the Cross-Site Request Forgery token. These
headers reduce what a successful injection can do; they do not stop one.

Tighten only, and mechanically so. The values below are applied over anything a route
set, because the earlier `setdefault` implementation was first-writer-wins: a route could
serve `default-src * 'unsafe-inline'` and keep it, while three documents promised it
could not. A route that needs a genuinely NARROWER policy calls :func:`tighten`; there is
no door for a wider one.

The Content-Security-Policy is deliberately strict for an application that serves its own
interface and calls nothing outbound from the browser: no remote script, no remote style,
no frame, no object, and no form target other than this origin. `connect-src 'self'` is
what the interface needs to call its own Application Programming Interface, and nothing
wider. There is no `unsafe-inline` and no `unsafe-eval`; an interface that needs either
is asking for the policy to be weakened and the answer is to change the interface.
"""

from __future__ import annotations

from flask import Flask, Response, g, has_request_context

#: One year, which is the floor for a host to be eligible for browser preloading.
HSTS_MAX_AGE_SECONDS = 31_536_000

#: The directives, one per line for reviewability. Tighten only.
CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "base-uri 'none'",
        "frame-ancestors 'none'",
        "object-src 'none'",
    )
)

SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    # `includeSubDomains` and `preload` are deliberate: the App Store serves this over
    # Transport Layer Security on a subdomain of a domain that is already HTTPS-only.
    "Strict-Transport-Security": (f"max-age={HSTS_MAX_AGE_SECONDS}; includeSubDomains; preload"),
    "X-Content-Type-Options": "nosniff",
    # Redundant with `frame-ancestors` for a modern browser, and named by AMD-001, so it
    # stays for the older client and for the policy line.
    "X-Frame-Options": "DENY",
    # Not named by AMD-001. Added because the alternative is leaking the full request path
    # of an authenticated compliance console to any outbound link target.
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


#: The narrower values a route is permitted to set, per header. An ALLOWLIST of exact
#: values, because "is this Content-Security-Policy narrower than that one?" is not
#: decidable in general, and a check that cannot decide is a check that waves things
#: through. Adding a permitted narrowing is a reviewed change to this table.
#:
#: A header absent from this table has no narrower value and cannot be overridden at all:
#: there is nothing stricter than `nosniff`, `DENY`, or `no-referrer`.
PERMITTED_TIGHTENINGS: dict[str, frozenset[str]] = {
    "Content-Security-Policy": frozenset(
        {
            f"{CONTENT_SECURITY_POLICY}; sandbox",
            "default-src 'none'; sandbox",
        }
    ),
}


class HeaderNotNarrowerError(ValueError):
    """Raised when a route tries to set a value that is not a sanctioned narrowing."""


def tighten(response: Response, name: str, value: str) -> Response:
    """Set a NARROWER value for one header on this response, and protect it.

    The only sanctioned way to depart from :data:`SECURITY_HEADERS`, and it refuses
    anything not in :data:`PERMITTED_TIGHTENINGS`.

    The first version of this function performed no comparison at all, which made it the
    door for a WIDER policy while three documents said no such door existed: a route could
    call it with `default-src * 'unsafe-inline'` and reach the client. Two further holes
    came from keeping the bookkeeping in the response headers: marking a header tightened
    without setting it deleted the header entirely, and a route that reflects a request
    header handed the choice to the client, who could remove any header by naming it. The
    bookkeeping is now request-scoped state that never touches the wire, and this function
    always sets the value itself, so neither is reachable.
    """
    permitted = PERMITTED_TIGHTENINGS.get(name, frozenset())
    if value not in permitted:
        raise HeaderNotNarrowerError(
            f"{value!r} is not a sanctioned narrower value for {name!r}. Permitted: "
            f"{sorted(permitted) or 'none, this header has no narrower value'}. A WIDER "
            f"value is never permitted."
        )
    response.headers[name] = value
    _tightened().add(name)
    return response


def _tightened() -> set[str]:
    """Return the set of headers this request has legitimately narrowed.

    Held on the APP context (`flask.g`), not on the response, so it cannot be set by a
    client, sent to one, or confused with a header a route echoes. App context, not request
    context, is the honest description: Flask reuses an already-pushed app context, so where
    one wraps request handling the mark outlives the request that set it. That is why
    :func:`apply_security_headers` validates the served value rather than trusting the mark.
    """
    if not hasattr(g, "_complyops_tightened"):
        g._complyops_tightened = set()
    tightened: set[str] = g._complyops_tightened
    return tightened


def apply_security_headers(response: Response) -> Response:
    """Set every security header on one response, overwriting anything a route set.

    Overwriting, not `setdefault`. `setdefault` is first-writer-wins, which meant a route
    returning `default-src * 'unsafe-inline'`, `X-Frame-Options: ALLOWALL` or `max-age=0`
    kept all three, while this module and the deployment notes promised tighten-only. The
    forms and templates slices are exactly where somebody loosens a policy to make a page
    render, so the guarantee has to be mechanical.

    A header is left alone only when :func:`tighten` set it during this request, which
    means it passed the allowlist. A route cannot reach that state by setting a header.
    """
    tightened = _tightened() if has_request_context() else set()
    for name, value in SECURITY_HEADERS.items():
        # Self-validating: the mark alone is not enough, because it can desynchronise from
        # the response actually served. Trusting it meant a route could tighten and then
        # widen the same header, tighten and then raise (a 500 with NO policy), tighten and
        # then delete the header, or tighten one response object and return another. The
        # skip now requires the value ON THE WIRE to be a sanctioned narrowing, so a
        # desynchronised mark fails safe by re-asserting the default.
        # getlist, not get: `get` reads the FIRST occurrence, so a route could tighten and
        # then `headers.add` a second, wider value, and both reached the wire. Browsers
        # enforce multiple policies as an intersection, so it was not a weakening, but two
        # documents say no wider value reaches a client and one visibly did. The skip now
        # requires exactly one occurrence, and that one to be a sanctioned narrowing.
        served = response.headers.getlist(name)
        sanctioned = PERMITTED_TIGHTENINGS.get(name, frozenset())
        if name in tightened and len(served) == 1 and served[0] in sanctioned:
            continue
        response.headers[name] = value
    return response


def register(app: Flask) -> None:
    """Attach the headers to every response the application produces."""
    app.after_request(apply_security_headers)
