"""Security headers, required on every response by AMD-001 section 10.6."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from flask import Flask, make_response
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
    assert security_headers.TIGHTENED_MARKER not in response.headers, "the marker is internal"


def test_tightening_one_header_does_not_release_the_others() -> None:
    app = Flask(__name__)
    security_headers.register(app)

    @app.get("/mixed")
    def mixed():  # noqa: ANN202 - Flask response object
        response = make_response("", 204)
        security_headers.tighten(response, "Referrer-Policy", "no-referrer")
        response.headers["X-Frame-Options"] = "ALLOWALL"
        return response

    headers = app.test_client().get("/mixed").headers
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["X-Frame-Options"] == "DENY"


def test_the_content_type_is_never_sniffed(client: FlaskClient) -> None:
    assert client.get("/").headers["X-Content-Type-Options"] == "nosniff"
