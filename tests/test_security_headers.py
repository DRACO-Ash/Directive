"""Security headers, required on every response by AMD-001 section 10.6."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from flask import Flask, make_response, request
from flask.testing import FlaskClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from complyops import create_app, security_headers

#: The four AMD-001 section 10.6 names it against, so a rename cannot pass unnoticed.
POLICY_HEADERS = (
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
)


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    return create_app().test_client()


@pytest.mark.parametrize("header", POLICY_HEADERS)
@pytest.mark.parametrize("path", ["/", "/healthz", "/health", "/livez", "/ping", "/readyz"])
def test_every_response_carries_every_policy_header(
    client: FlaskClient, path: str, header: str
) -> None:
    """Including the probes: a header applied selectively is one an attacker routes around."""
    assert header in client.get(path).headers


@pytest.mark.parametrize("header", POLICY_HEADERS)
def test_an_error_response_carries_the_headers_too(client: FlaskClient, header: str) -> None:
    """A 404 renders attacker-influenced routing, so it needs the headers most."""
    assert header in client.get("/no-such-path").headers


def test_the_policy_forbids_inline_script_and_eval(client: FlaskClient) -> None:
    """An interface needing either is asking for the policy to be decoration."""
    policy = client.get("/").headers["Content-Security-Policy"]
    assert "unsafe-inline" not in policy
    assert "unsafe-eval" not in policy
    assert "default-src 'none'" in policy


def test_framing_is_denied_by_both_mechanisms(client: FlaskClient) -> None:
    response = client.get("/")
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"


def test_transport_security_meets_the_preload_floor(client: FlaskClient) -> None:
    value = client.get("/").headers["Strict-Transport-Security"]
    assert f"max-age={security_headers.HSTS_MAX_AGE_SECONDS}" in value
    assert security_headers.HSTS_MAX_AGE_SECONDS >= 31_536_000
    assert "includeSubDomains" in value


def test_the_referrer_is_never_sent(client: FlaskClient) -> None:
    """Otherwise the full request path of an authenticated console leaks to a link target."""
    assert client.get("/").headers["Referrer-Policy"] == "no-referrer"


@pytest.mark.parametrize(
    ("header", "looser"),
    [
        ("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'"),
        ("X-Frame-Options", "ALLOWALL"),
        ("Strict-Transport-Security", "max-age=0"),
        ("Referrer-Policy", "unsafe-url"),
    ],
)
def test_a_route_cannot_loosen_a_header(header: str, looser: str) -> None:
    """The direction that matters, and the one the previous test did not cover.

    `setdefault` was first-writer-wins, not tighten-only: a route serving
    `default-src * 'unsafe-inline'` kept it while this module, CLAUDE.md and the
    deployment notes all promised it could not. The forms and templates slices are exactly
    where somebody loosens a policy to make a page render, so the guarantee has to be
    mechanical rather than a convention.
    """
    app = Flask(__name__)
    security_headers.register(app)

    @app.get("/loosen")
    def loosen() -> tuple[str, int, dict[str, str]]:
        return "", 204, {header: looser}

    served = app.test_client().get("/loosen").headers[header]
    assert served == security_headers.SECURITY_HEADERS[header]
    assert served != looser


def test_a_route_can_tighten_a_header_through_the_explicit_door() -> None:
    """Fail closed, but leave a sanctioned way to be stricter.

    Deliberately awkward: a narrowing override is a visible call in a diff, and there is
    no equivalent door for a wider policy.
    """
    app = Flask(__name__)
    security_headers.register(app)

    @app.get("/narrower")
    def narrower():  # noqa: ANN202 - Flask response object
        response = make_response("", 204)
        return security_headers.tighten(
            response, "Content-Security-Policy", "default-src 'none'; sandbox"
        )

    response = app.test_client().get("/narrower")
    assert response.headers["Content-Security-Policy"] == "default-src 'none'; sandbox"
    assert response.headers["X-Frame-Options"] == "DENY", "the rest still apply"
    assert "_complyops_tightened" not in response.headers, "the bookkeeping never ships"


def test_tightening_one_header_does_not_release_the_others() -> None:
    app = Flask(__name__)
    security_headers.register(app)

    @app.get("/mixed")
    def mixed():  # noqa: ANN202 - Flask response object
        response = make_response("", 204)
        security_headers.tighten(response, "Content-Security-Policy", "default-src 'none'; sandbox")
        response.headers["X-Frame-Options"] = "ALLOWALL"
        return response

    headers = app.test_client().get("/mixed").headers
    assert headers["Content-Security-Policy"] == "default-src 'none'; sandbox"
    assert headers["X-Frame-Options"] == "DENY"


def test_the_content_type_is_never_sniffed(client: FlaskClient) -> None:
    assert client.get("/").headers["X-Content-Type-Options"] == "nosniff"


@pytest.mark.parametrize(
    ("header", "wider"),
    [
        ("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'"),
        ("X-Frame-Options", "ALLOWALL"),
        ("Strict-Transport-Security", "max-age=0"),
        ("Referrer-Policy", "unsafe-url"),
        ("X-Content-Type-Options", "sniff"),
    ],
)
def test_the_tighten_door_refuses_a_wider_value(header: str, wider: str) -> None:
    """The door was the hole. It performed no comparison at all.

    Three documents said there was no door for a wider policy while `tighten` would set
    any value it was given, including one weaker than the default. It now refuses anything
    outside an explicit allowlist, and a header with no narrower value cannot be
    overridden at all.
    """
    app = Flask(__name__)
    with app.test_request_context():
        response = make_response("", 204)
        with pytest.raises(security_headers.HeaderNotNarrowerError, match="never permitted"):
            security_headers.tighten(response, header, wider)


def test_a_header_with_no_narrower_value_cannot_be_overridden_at_all() -> None:
    """There is nothing stricter than nosniff, DENY, or no-referrer."""
    for header in ("X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"):
        assert header not in security_headers.PERMITTED_TIGHTENINGS


def test_a_route_cannot_delete_a_header_by_claiming_it_tightened_one() -> None:
    """Bookkeeping in the response headers let a route strip a header entirely.

    Setting the marker without setting the header made the blanket pass skip it, so the
    response carried no policy at all. The bookkeeping is now request-scoped state that
    never touches the wire.
    """
    app = Flask(__name__)
    security_headers.register(app)

    @app.get("/strip")
    def strip():  # noqa: ANN202 - Flask response object
        response = make_response("", 204)
        response.headers["_complyops_tightened"] = "Content-Security-Policy,X-Frame-Options"
        return response

    headers = app.test_client().get("/strip").headers
    assert headers["Content-Security-Policy"] == security_headers.CONTENT_SECURITY_POLICY
    assert headers["X-Frame-Options"] == "DENY"


def test_a_client_cannot_remove_a_header_through_a_route_that_echoes_one() -> None:
    """The worst shape of the same bug: the client chose which headers to drop.

    A route echoing a request header (a correlation id, a CORS handler, the kind of thing
    the forms and API slices add) handed the marker namespace to the caller.
    """
    app = Flask(__name__)
    security_headers.register(app)

    @app.get("/echo")
    def echo():  # noqa: ANN202 - Flask response object
        response = make_response("", 204)
        for name, value in request.headers:
            if name.lower().startswith("x-echo"):
                response.headers["_complyops_tightened"] = value
        return response

    headers = (
        app.test_client()
        .get("/echo", headers={"X-Echo": "Content-Security-Policy,Strict-Transport-Security"})
        .headers
    )
    assert "Content-Security-Policy" in headers
    assert "Strict-Transport-Security" in headers


def test_the_blanket_pass_runs_last() -> None:
    """The guarantee depends on registration order, so pin it.

    An app-level after_request registered BEFORE this one runs after it and can serve a
    wider policy. create_app registers headers first, which is correct; this asserts it.
    """
    from complyops import create_app  # noqa: PLC0415

    app = create_app()
    handlers = app.after_request_funcs[None]
    assert handlers[0] is security_headers.apply_security_headers, (
        "the blanket pass must be registered first, so Flask runs it last"
    )
