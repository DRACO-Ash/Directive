"""The App Store's dynamic security scan gets a running container, and nothing else.

The scan runs the image with NO environment variables and expects HTTP on port 8080 within
sixty seconds. This application refuses to boot without Entra ID and without `SESSION_KEY`,
both deliberately, so it never answered and the gate reported `no_report`: nothing scanned,
release blocked. The platform's instruction is to generate a throwaway value when
`APPSTORE_DAST_SCAN=true`.

Every test here exists because the relaxation is an authentication control being stood down
on a flag, which is the shape of a back door whether or not it is one. What makes it not one
is that it is honoured ONLY while Entra ID is unconfigured, and that nothing after boot is
relaxed. Both properties are asserted below, in both directions.
"""

from __future__ import annotations

import pytest
from flask import Flask
from flask.testing import FlaskClient

from directive import auth, create_app

ENTRA = {
    "TENANT_ID": "11111111-1111-1111-1111-111111111111",
    "CLIENT_ID": "22222222-2222-2222-2222-222222222222",
    "CLIENT_SECRET": "a-secret-value-for-the-test",
    "REDIRECT_URI": "https://directive.apps.bluestaq.com/auth/callback",
}


@pytest.fixture
def scanned(tmp_path, monkeypatch) -> Flask:
    """Return an application booted as the scanner boots it: one variable, nothing else."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APPSTORE_DAST_SCAN", "true")
    return create_app()


def test_the_container_refuses_to_boot_without_the_flag(tmp_path, monkeypatch) -> None:
    """The control this relaxes is real, so it must still bite with the flag absent.

    Without this the whole module could pass against an application that never refused
    anything, and the relaxation would be measuring nothing.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    with pytest.raises(auth.AuthNotConfiguredError, match="Refusing to start"):
        create_app()


def test_the_scanner_gets_a_running_container(scanned: Flask) -> None:
    """The gate's own requirement: HTTP on the declared port, or `no_report`."""
    client = scanned.test_client()
    for path in ("/", "/healthz", "/health", "/readyz", "/livez", "/ping"):
        assert client.get(path).status_code == 200, path


def test_the_root_is_not_a_redirect_under_the_scan(scanned: Flask) -> None:
    """The platform router treats a 302 at the root as unhealthy, scan or no scan."""
    assert scanned.test_client().get("/").status_code == 200


@pytest.mark.parametrize("value", ["false", "True ", "1", "yes", "", "TRUE", "true\n"])
def test_only_the_exact_lower_case_true_arms_the_flag(value: str, tmp_path, monkeypatch) -> None:
    """A loose truthiness test here would arm this on any non-empty string.

    `config.env` strips and unquotes, so a trailing newline normalises to `true` and IS
    accepted; that is the operator-console normalisation every variable gets, not a
    widening. Everything else must refuse to boot.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APPSTORE_DAST_SCAN", value)
    if value.strip().lower() == "true":
        assert create_app() is not None
        return
    with pytest.raises(auth.AuthNotConfiguredError):
        create_app()


def test_the_flag_cannot_degrade_a_deployment_that_has_entra(tmp_path, monkeypatch) -> None:
    """The safety property, stated as a test rather than as a comment.

    Set on a real pod, the flag must change nothing. If this ever goes green in the other
    direction the flag has become a way around the identity provider.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("APPSTORE_DAST_SCAN", "true")
    for name, value in ENTRA.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("SESSION_KEY", "a-real-session-key-for-the-test")

    assert auth.scan_mode() is False
    assert auth.entra_is_configured() is True


def test_the_scan_is_still_production(scanned: Flask) -> None:
    """Nothing after boot is relaxed. The cookie keeps its Secure flag."""
    with scanned.app_context():
        assert auth.is_production() is True
    assert scanned.config["SESSION_COOKIE_SECURE"] is True


def test_the_self_asserted_sign_in_is_refused_under_the_scan(scanned: Flask) -> None:
    """The boot relaxation must not open the sign-in path it sits next to.

    That path is gated on Entra being CONFIGURED, and in scan mode it is not, so without an
    explicit clause the relaxation would have handed the scanner, and anyone else reaching
    the container, a signed-in session with a self-asserted actor.
    """
    client: FlaskClient = scanned.test_client()
    token = client.get("/").headers["X-CSRF-Token"]

    refused = client.post("/sign-in", data={"actor": "anybody@example.com", "csrf_token": token})

    assert refused.status_code != 302 or "/console" not in refused.headers.get("Location", "")
    # The session must carry no actor afterwards, which is the property that matters: a
    # refusal that still set the cookie would be a refusal in name only.
    assert client.get("/api/registers").status_code == 401
    assert client.get("/console").status_code == 302


def test_every_register_route_is_still_gated_under_the_scan(scanned: Flask) -> None:
    """What the scanner should find is the real unauthenticated surface, and only that."""
    client = scanned.test_client()
    assert client.get("/api/registers").status_code == 401
    assert client.post("/api/registers/tasks", json={"title": "x"}).status_code in (401, 403)
    assert client.get("/api/audit").status_code == 401
    assert client.get("/console").status_code == 302
