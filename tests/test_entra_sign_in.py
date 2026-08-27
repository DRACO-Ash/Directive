"""The Entra ID authorisation code flow, driven end to end against a fake token endpoint.

The back channel is faked at exactly one seam, :func:`complyops.auth._post_form`, so
everything above it is the real code path: the redirect this application builds, the state
and nonce it stores, the Proof Key for Code Exchange (PKCE) verifier it holds back, the
claim checks, and the audit entry the sign-in produces.

What is NOT proved here, stated because it is the kind of thing that gets over-claimed:
no request has ever reached Microsoft. The wire format of the token response, the tenant's
real issuer string, and the reply URL registered against the application are all
`TBC, re-verify` on first deploy.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from flask import Flask
from flask.testing import FlaskClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from complyops import auth, create_app

#: Real key material, published here on purpose: it is not a credential.
SUITE_KEY = bytes(range(32)).hex()

#: Not a credential: a placeholder the fake endpoint compares against, so the test can
#: prove the real secret goes into the POST body rather than into a URL.
TEST_SECRET = "not-a-real-secret"  # noqa: S105

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "66666666-7777-8888-9999-000000000000"
ISSUER = f"https://login.microsoftonline.com/{TENANT}/v2.0"


def segment(payload: dict[str, Any]) -> str:
    """Return one base64url JSON token segment."""
    raw = json.dumps(payload).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def id_token(**overrides: object) -> str:
    """Return an identity token whose claims are valid unless overridden."""
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": CLIENT,
        "exp": 4102444800,
        "preferred_username": "ash.higgins@bluestaq.uk",
    }
    claims.update(overrides)
    return f"{segment({'alg': 'RS256'})}.{segment(claims)}.signature-not-checked"


@pytest.fixture
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Flask:
    """Return an application with Entra ID configured."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    monkeypatch.setenv("TENANT_ID", TENANT)
    monkeypatch.setenv("CLIENT_ID", CLIENT)
    monkeypatch.setenv("CLIENT_SECRET", TEST_SECRET)
    monkeypatch.setenv("REDIRECT_URI", "https://comply-ops.apps.bluestaq.com/auth/callback")
    monkeypatch.setenv("SESSION_KEY", "0" * 48)
    monkeypatch.delenv("COMPLYOPS_ENV", raising=False)
    return create_app()


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Return a client for an application with Entra ID configured."""
    return app.test_client()


class Endpoint:
    """A stand-in for Entra ID's token endpoint that records what it was sent."""

    def __init__(self, response: dict[str, Any]) -> None:
        """Hold the canned response this endpoint will return."""
        self.response = response
        self.url: str | None = None
        self.form: dict[str, str] = {}

    def __call__(self, url: str, form: dict[str, str]) -> dict[str, Any]:
        """Record the request and return the canned response."""
        self.url = url
        self.form = form
        return self.response


def start(client: FlaskClient) -> str:
    """Begin a sign-in and return the state the application generated."""
    location = client.get("/sign-in").headers["Location"]
    return dict(part.split("=", 1) for part in location.split("?", 1)[1].split("&"))["state"]


# ============================ the happy path ============================


def test_a_signed_in_operator_is_recorded_as_verified(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The whole reason authentication stays in the application: a verified actor."""
    nonce = None

    def endpoint(url: str, form: dict[str, str]) -> dict[str, Any]:
        return {"id_token": id_token(nonce=nonce)}

    state = start(client)
    with client.session_transaction() as stored:
        nonce = stored["complyops_signin_nonce"]
    monkeypatch.setattr(auth, "_post_form", endpoint)

    landed = client.get(f"/auth/callback?code=the-code&state={state}")
    assert landed.headers["Location"].endswith("/console")

    registers = client.get("/api/registers").get_json()
    assert registers["actor"] == "ash.higgins@bluestaq.uk"
    assert registers["actorVerified"] is True

    entry = client.get("/api/audit").get_json()["entries"][0]
    assert entry["action"] == "LOGIN"
    assert entry["actor"] == "ash.higgins@bluestaq.uk", "no self-asserted marker on a real token"


def test_the_exchange_sends_the_secret_and_the_verifier_and_nothing_else(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The secret goes in a POST body to Microsoft, never into a URL."""
    recorded = Endpoint({"id_token": id_token(nonce="wrong")})
    state = start(client)
    with client.session_transaction() as stored:
        verifier = stored["complyops_signin_verifier"]
    monkeypatch.setattr(auth, "_post_form", recorded)

    client.get(f"/auth/callback?code=the-code&state={state}")

    assert recorded.url == f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    assert recorded.form["client_secret"] == TEST_SECRET
    assert recorded.form["code_verifier"] == verifier
    assert recorded.form["grant_type"] == "authorization_code"


# ============================ what must fail closed ============================


@pytest.mark.parametrize(
    ("overrides", "why"),
    [
        ({"iss": "https://login.microsoftonline.com/somebody-else/v2.0"}, "another issuer"),
        ({"aud": "another-application"}, "another audience"),
        ({"exp": 1}, "expired"),
        ({"preferred_username": "", "upn": "", "email": "", "sub": ""}, "no usable actor"),
    ],
)
def test_a_bad_token_signs_nobody_in(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any], why: str
) -> None:
    """Each check refuses on its own, and the caller is told nothing about which."""
    nonce = None

    def endpoint(url: str, form: dict[str, str]) -> dict[str, Any]:
        return {"id_token": id_token(nonce=nonce, **overrides)}

    state = start(client)
    with client.session_transaction() as stored:
        nonce = stored["complyops_signin_nonce"]
    monkeypatch.setattr(auth, "_post_form", endpoint)

    landed = client.get(f"/auth/callback?code=the-code&state={state}")
    assert landed.headers["Location"].endswith("/sign-in"), why
    assert client.get("/api/registers").status_code == 401, why


def test_a_token_carrying_another_nonce_signs_nobody_in(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The nonce binds the token to the browser that started this sign-in."""
    monkeypatch.setattr(auth, "_post_form", Endpoint({"id_token": id_token(nonce="somebody-else")}))
    state = start(client)

    client.get(f"/auth/callback?code=the-code&state={state}")
    assert client.get("/api/registers").status_code == 401


def test_a_replayed_callback_signs_nobody_in(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The round-trip values are consumed on first use, so the second attempt has nothing."""
    nonce = None

    def endpoint(url: str, form: dict[str, str]) -> dict[str, Any]:
        return {"id_token": id_token(nonce=nonce)}

    state = start(client)
    with client.session_transaction() as stored:
        nonce = stored["complyops_signin_nonce"]
    monkeypatch.setattr(auth, "_post_form", endpoint)
    client.get(f"/auth/callback?code=the-code&state={state}")
    client.post("/sign-out", data={"csrf_token": client.get("/").headers["X-CSRF-Token"]})

    replayed = client.get(f"/auth/callback?code=the-code&state={state}")
    assert replayed.headers["Location"].endswith("/sign-in")
    assert client.get("/api/registers").status_code == 401


def test_a_callback_with_no_code_signs_nobody_in(client: FlaskClient) -> None:
    """A callback carrying a good state and no code is not a sign-in."""
    state = start(client)
    landed = client.get(f"/auth/callback?state={state}")
    assert landed.headers["Location"].endswith("/sign-in")


def test_a_response_with_no_identity_token_is_refused(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Entra ID returning an error body must not read as a sign-in."""
    monkeypatch.setattr(auth, "_post_form", Endpoint({"error": "invalid_grant"}))
    state = start(client)

    client.get(f"/auth/callback?code=the-code&state={state}")
    assert client.get("/api/registers").status_code == 401


def test_a_failed_exchange_is_audited(client: FlaskClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """AUD-001 requires a failed authentication event, not only a successful one."""

    def refuse(url: str, form: dict[str, str]) -> dict[str, Any]:
        raise auth.AuthError("the token exchange failed: URLError")

    monkeypatch.setattr(auth, "_post_form", refuse)
    state = start(client)
    client.get(f"/auth/callback?code=the-code&state={state}")

    chain = client.application.extensions["complyops_chain"]
    assert [entry.action for entry in chain.entries] == ["LOGIN_FAILED"]
    assert chain.entries[0].outcome == "FAILURE"


# ============================ the token reader in isolation ============================


def test_a_token_that_is_not_a_jwt_is_refused(app: Flask) -> None:
    """Three segments, or it is not a token this application will read."""
    with app.app_context(), pytest.raises(auth.AuthError, match="not a JSON Web Token"):
        auth.claims_from_id_token("not.a.jwt.at.all", nonce="n")


def test_an_unreadable_segment_is_refused(app: Flask) -> None:
    """Base64 that decodes to nothing readable is refused rather than guessed at."""
    with app.app_context(), pytest.raises(auth.AuthError, match="not readable"):
        auth.claims_from_id_token("a.!!!!.c", nonce="n")


def test_a_segment_that_is_not_an_object_is_refused(app: Flask) -> None:
    """A JSON array decodes cleanly and is still not a claim set."""
    with app.app_context(), pytest.raises(auth.AuthError, match="not an object"):
        auth.claims_from_id_token(f"a.{segment([1, 2, 3])}.c", nonce="n")  # type: ignore[arg-type]


def test_the_token_endpoint_must_be_the_configured_host(app: Flask) -> None:
    """A future edit making the host configurable must not post the secret elsewhere."""
    with app.app_context(), pytest.raises(auth.AuthError, match="not the configured"):
        auth._post_form("https://attacker.example/token", {"client_secret": TEST_SECRET})


def test_clock_skew_is_tolerated(app: Flask) -> None:
    """A token that expired a moment ago is accepted; one long expired is not."""
    with app.app_context():
        token = id_token(nonce="n", exp=1000)
        assert auth.claims_from_id_token(token, nonce="n", now=1030)["aud"] == CLIENT
        with pytest.raises(auth.AuthError, match="expired"):
            auth.claims_from_id_token(token, nonce="n", now=2000)


@pytest.mark.parametrize(
    ("claim", "expected"),
    [
        ("preferred_username", "ash.higgins@bluestaq.uk"),
        ("upn", "ash.higgins@bluestaq.uk"),
        ("email", "ash.higgins@bluestaq.uk"),
        ("sub", "ash.higgins@bluestaq.uk"),
    ],
)
def test_the_actor_falls_back_through_the_claims(claim: str, expected: str) -> None:
    """Entra ID issues different claims for different account types."""
    assert auth.actor_from_claims({claim: expected}) == expected


def test_an_actor_is_never_invented(app: Flask) -> None:
    """An audit entry with no real actor is worse than a refused sign-in."""
    with pytest.raises(auth.AuthError, match="no usable actor"):
        auth.actor_from_claims({"name": "Somebody"})


def test_a_verified_actor_the_log_cannot_name_is_refused(
    client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Entra `preferred_username` legitimately carries non-ASCII, and the log cannot.

    That combination used to sign the operator in with no authentication entry at all,
    which defeats the stated reason authentication stays in this application. It now
    refuses, and the refusal is audited against a placeholder actor.
    """
    nonce = None

    def endpoint(url: str, form: dict[str, str]) -> dict[str, Any]:
        return {"id_token": id_token(nonce=nonce, preferred_username="renée@bluestaq.uk")}

    state = start(client)
    with client.session_transaction() as stored:
        nonce = stored["complyops_signin_nonce"]
    monkeypatch.setattr(auth, "_post_form", endpoint)

    landed = client.get(f"/auth/callback?code=the-code&state={state}")
    assert landed.headers["Location"].endswith("/sign-in")
    assert client.get("/api/registers").status_code == 401

    chain = client.application.extensions["complyops_chain"]
    assert [entry.action for entry in chain.entries] == ["LOGIN_FAILED"]


def test_a_non_ascii_state_is_refused_rather_than_raising(client: FlaskClient) -> None:
    """`compare_digest` raises TypeError on a non-ASCII str, on an unauthenticated route.

    A 500 there would also skip the LOGIN_FAILED entry the refusal path writes.
    """
    start(client)
    landed = client.get("/auth/callback?code=the-code&state=%C3%A9%C3%A9")

    assert landed.status_code == 302
    assert landed.headers["Location"].endswith("/sign-in")
    chain = client.application.extensions["complyops_chain"]
    assert [entry.action for entry in chain.entries] == ["LOGIN_FAILED"]


def test_a_non_ascii_nonce_in_a_token_is_refused(app: Flask) -> None:
    """Same comparison, same failure mode, reached through the token instead."""
    with app.app_context(), pytest.raises(auth.AuthError, match="nonce"):
        auth.claims_from_id_token(id_token(nonce="ééé"), nonce="the-nonce")
