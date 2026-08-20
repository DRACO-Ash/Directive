"""Response security headers, required by AMD-001 section 10.6.

The policy names four: Content-Security-Policy, Strict-Transport-Security,
X-Content-Type-Options and X-Frame-Options, applied to all responses. All four are set
here, on every response including a health probe and an error page, because a header
applied selectively is a header an attacker reaches the exception to.

Defence in depth, not a boundary. The real boundaries are authentication against Entra
ID, the server-side authorisation check, and the Cross-Site Request Forgery token. These
headers reduce what a successful injection can do; they do not stop one. Treat a change
here as tightening only: loosening a directive to make something render is how a policy
becomes decoration.

The Content-Security-Policy is deliberately strict for an application that serves its own
interface and calls nothing outbound from the browser: no remote script, no remote style,
no frame, no object, and no form target other than this origin. `connect-src 'self'` is
what the interface needs to call its own Application Programming Interface, and nothing
wider. There is no `unsafe-inline` and no `unsafe-eval`; an interface that needs either
is asking for the policy to be weakened and the answer is to change the interface.
"""

from __future__ import annotations

from flask import Flask, Response

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


def apply_security_headers(response: Response) -> Response:
    """Set every security header on one response, without overwriting a stricter value."""
    for name, value in SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


def register(app: Flask) -> None:
    """Attach the headers to every response the application produces."""
    app.after_request(apply_security_headers)
