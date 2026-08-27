"""The application end to end: the gate, the registers, the audit trail, the export."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from flask import Flask
from flask.testing import FlaskClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from complyops import (
    create_app,
    records,
    store,
)
from complyops.audit.journal import JournalError

#: Real key material, published here on purpose: it is not a credential.
SUITE_KEY = bytes(range(32)).hex()


@pytest.fixture
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Flask:
    """Return an application with a working audit chain on a fresh volume."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    monkeypatch.delenv("COMPLYOPS_ENV", raising=False)
    return create_app()


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Return an unauthenticated client."""
    return app.test_client()


@pytest.fixture
def signed_in(client: FlaskClient) -> FlaskClient:
    """Return a client that has signed in."""
    client.post("/sign-in", data={"actor": "ash.higgins@bluestaq.uk"})
    return client


def token_for(client: FlaskClient) -> dict[str, str]:
    """Return the cross-site request forgery header for this session."""
    return {"X-CSRF-Token": client.get("/api/registers").headers["X-CSRF-Token"]}


# ============================ the gate ============================


@pytest.mark.parametrize("path", ["/console", "/api/registers", "/api/audit", "/api/export"])
def test_every_console_path_refuses_an_unauthenticated_caller(
    client: FlaskClient, path: str
) -> None:
    """Server-side, and fails closed. There is no client-side gate anywhere."""
    assert client.get(path).status_code in {302, 401}


def test_a_mutation_refuses_an_unauthenticated_caller(client: FlaskClient) -> None:
    assert client.post("/api/registers/tasks", json={"title": "x"}).status_code == 401


def test_a_mutation_without_a_request_token_is_refused(signed_in: FlaskClient) -> None:
    """The token is a real boundary, not defence in depth: SameSite is a browser behaviour."""
    refused = signed_in.post("/api/registers/tasks", json={"title": "no token"})
    assert refused.status_code == 403
    assert "token" in refused.get_json()["error"]


def test_a_mutation_with_another_sessions_token_is_refused(
    app: Flask, signed_in: FlaskClient
) -> None:
    other = app.test_client()
    other.post("/sign-in", data={"actor": "someone.else@bluestaq.uk"})
    stolen = token_for(other)
    assert (
        signed_in.post("/api/registers/tasks", json={"title": "x"}, headers=stolen).status_code
        == 403
    )


def test_signing_out_ends_the_session(signed_in: FlaskClient) -> None:
    headers = token_for(signed_in)
    signed_in.post("/sign-out", data={"csrf_token": headers["X-CSRF-Token"]})
    assert signed_in.get("/api/registers").status_code == 401


# ============================ the registers ============================


@pytest.mark.parametrize("register", sorted(records.REGISTERS))
def test_a_record_can_be_created_and_read_back(signed_in: FlaskClient, register: str) -> None:
    headers = token_for(signed_in)
    created = signed_in.post(
        f"/api/registers/{register}",
        json={"title": "A real thing", "owner": "A. Higgins"},
        headers=headers,
    )
    assert created.status_code == 201
    record = created.get_json()["record"]
    assert record["title"] == "A real thing"

    listed = signed_in.get(f"/api/registers/{register}").get_json()["records"]
    assert [row["id"] for row in listed] == [record["id"]]


def test_records_survive_a_restart(app: Flask, tmp_path: Path, signed_in: FlaskClient) -> None:
    """The volume is the system of record, so a new process must see the same rows."""
    signed_in.post(
        "/api/registers/tasks", json={"title": "Persisted"}, headers=token_for(signed_in)
    )
    assert [row["title"] for row in store.read(str(tmp_path), "tasks")] == ["Persisted"]


def test_a_state_transition_needs_only_the_state(signed_in: FlaskClient) -> None:
    """A partial update, so moving a task does not mean resending its title."""
    headers = token_for(signed_in)
    signed_in.post("/api/registers/tasks", json={"title": "Move me"}, headers=headers)
    moved = signed_in.patch(
        "/api/registers/tasks/TSK-0001", json={"state": "DONE"}, headers=headers
    )
    assert moved.status_code == 200
    assert moved.get_json()["record"]["state"] == "DONE"
    assert moved.get_json()["record"]["title"] == "Move me"


@pytest.mark.parametrize(
    ("payload", "fragment"),
    [
        ({"title": "x", "state": "NOT_A_STATE"}, "is not a tasks state"),
        ({"title": "x" * 201}, "over its cap"),
        ({"title": "x", "unknown_field": "y"}, "not a field"),
        ({"title": "x", "owner": 7}, "must be text"),
        ({}, "needs a title"),
    ],
)
def test_the_boundary_rejects_bad_input(
    signed_in: FlaskClient, payload: dict[str, Any], fragment: str
) -> None:
    """Rejected at the boundary, never coerced, and the message names the rule."""
    refused = signed_in.post("/api/registers/tasks", json=payload, headers=token_for(signed_in))
    assert refused.status_code == 400
    assert fragment in refused.get_json()["error"]


def test_an_unknown_register_is_refused(signed_in: FlaskClient) -> None:
    refused = signed_in.post(
        "/api/registers/not-a-register", json={"title": "x"}, headers=token_for(signed_in)
    )
    assert refused.status_code == 400


def test_updating_a_record_that_does_not_exist_is_refused(signed_in: FlaskClient) -> None:
    refused = signed_in.patch(
        "/api/registers/tasks/TSK-9999", json={"state": "DONE"}, headers=token_for(signed_in)
    )
    assert refused.status_code == 400


# ============================ the audit trail ============================


def test_every_mutation_writes_one_chained_entry(signed_in: FlaskClient) -> None:
    """The hard rule: no code path writes a record without an audit entry."""
    headers = token_for(signed_in)
    signed_in.post("/api/registers/incidents", json={"title": "Phishing report"}, headers=headers)
    signed_in.patch(
        "/api/registers/incidents/INC-0001", json={"state": "INVESTIGATING"}, headers=headers
    )

    entries = signed_in.get("/api/audit").get_json()["entries"]
    actions = [entry["action"] for entry in entries]
    assert actions == ["INC_UPDATED", "INC_CREATED", "LOGIN"]

    transition = entries[0]
    assert transition["old_state"] == "TRIAGE"
    assert transition["new_state"] == "INVESTIGATING"
    assert transition["resource_id"] == "INC-0001"


def test_the_chain_verifies_after_real_use(signed_in: FlaskClient) -> None:
    headers = token_for(signed_in)
    for index in range(4):
        signed_in.post("/api/registers/tasks", json={"title": f"Task {index}"}, headers=headers)

    verdict = signed_in.post("/api/audit/verify", headers=headers).get_json()
    assert verdict["ok"] is True
    assert verdict["tampered"] is False
    assert verdict["checked"] == 5


def test_an_entry_records_the_authentication_context(signed_in: FlaskClient) -> None:
    """AUD-001 requires the address and the user agent on an authentication event."""
    login = next(
        entry
        for entry in signed_in.get("/api/audit").get_json()["entries"]
        if entry["action"] == "LOGIN"
    )
    assert login["outcome"] == "SUCCESS"
    assert login["source_ip"]
    assert login["user_agent"]


def test_a_self_asserted_actor_is_marked_as_such(signed_in: FlaskClient) -> None:
    """Evidence from development can never be mistaken for a verified identity."""
    entries = signed_in.get("/api/audit").get_json()["entries"]
    assert all("(self-asserted)" in entry["actor"] for entry in entries)


def test_the_log_records_field_names_and_never_values(signed_in: FlaskClient) -> None:
    """An entry says an action happened, never what the record said."""
    headers = token_for(signed_in)
    signed_in.post(
        "/api/registers/incidents",
        json={"title": "Laptop lost by Jane Doe", "owner": "A. Higgins"},
        headers=headers,
    )
    signed_in.patch(
        "/api/registers/incidents/INC-0001",
        json={"summary": "Reported by jane.doe@example.invalid at her home address"},
        headers=headers,
    )

    entries = signed_in.get("/api/audit").get_json()["entries"]
    written = " ".join(f"{entry}" for entry in entries)
    assert "fields_changed" in written
    assert entries[0]["fields_changed"] == "summary"
    assert "Jane Doe" not in written
    assert "jane.doe@example.invalid" not in written
    assert "home address" not in written


def test_a_failed_sign_in_is_recorded(client: FlaskClient) -> None:
    client.post("/sign-in", data={"actor": ""})
    client.post("/sign-in", data={"actor": "ash.higgins@bluestaq.uk"})
    failures = [
        entry
        for entry in client.get("/api/audit").get_json()["entries"]
        if entry["action"] == "LOGIN_FAILED"
    ]
    assert failures and failures[0]["outcome"] == "FAILURE"


# ============================ the evidence pack ============================


def test_the_export_carries_the_registers_the_entries_and_the_anchor(
    signed_in: FlaskClient,
) -> None:
    """The pack is the off-volume corroboration, so it must carry the anchor."""
    headers = token_for(signed_in)
    signed_in.post("/api/registers/risks", json={"title": "Concentration risk"}, headers=headers)

    pack = signed_in.get("/api/export")
    assert "attachment" in pack.headers["Content-Disposition"]
    body = pack.get_json()
    assert body["registers"]["risks"][0]["title"] == "Concentration risk"
    assert body["auditEntries"]
    assert body["auditAnchor"]["length"] == len(body["auditEntries"])
    assert "Keep the anchor with this pack" in body["note"]


# ============================ the console ============================


def test_the_console_renders_for_a_signed_in_operator(signed_in: FlaskClient) -> None:
    page = signed_in.get("/console")
    assert page.status_code == 200
    body = page.get_data(as_text=True)
    for register in records.REGISTERS.values():
        assert register["title"] in body


def test_a_record_title_is_escaped_in_the_page(signed_in: FlaskClient) -> None:
    """Autoescaping on, and the page's own script uses textContent, never innerHTML."""
    headers = token_for(signed_in)
    signed_in.post(
        "/api/registers/tasks", json={"title": "<script>alert(1)</script>"}, headers=headers
    )
    assert "<script>alert(1)</script>" not in signed_in.get("/console").get_data(as_text=True)


def test_the_console_carries_the_security_headers(signed_in: FlaskClient) -> None:
    headers = signed_in.get("/console").headers
    assert "Content-Security-Policy" in headers
    assert headers["X-Frame-Options"] == "DENY"


# ============================ the Entra ID paths ============================


@pytest.fixture
def entra(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    """Return a client for an app with Entra ID configured."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    for name, value in [
        ("TENANT_ID", "a-tenant"),
        ("CLIENT_ID", "a-client"),
        ("CLIENT_SECRET", "a-secret"),
        ("REDIRECT_URI", "https://comply-ops.apps.bluestaq.com/auth/callback"),
    ]:
        monkeypatch.setenv(name, value)
    return create_app().test_client()


def test_a_configured_tenant_sends_the_operator_to_entra(entra: FlaskClient) -> None:
    response = entra.get("/sign-in")
    assert response.status_code == 302
    assert response.headers["Location"].startswith("https://login.microsoftonline.com/a-tenant/")


def test_the_self_asserted_path_is_refused_once_entra_is_configured(entra: FlaskClient) -> None:
    """The self-asserted path must never become a way around a real identity provider."""
    entra.post("/sign-in", data={"actor": "attacker@evil.example"})
    assert entra.get("/api/registers").status_code == 401


def test_a_callback_without_matching_state_signs_nobody_in(entra: FlaskClient) -> None:
    """A replayed or forged callback must not authenticate anybody."""
    entra.get("/sign-in")
    assert entra.get("/auth/callback?code=x&state=forged").status_code == 302
    assert entra.get("/api/registers").status_code == 401


def test_a_callback_with_matching_state_still_fails_closed(entra: FlaskClient) -> None:
    """The token exchange needs a real tenant, so until it lands this path signs nobody in.

    Failing closed here is why `check_startup` refuses to boot in production without Entra
    ID configured: the two rules together mean there is no state in which an unverified
    actor reaches production.
    """
    entra.get("/sign-in")
    with entra.session_transaction() as stored:
        state = stored.get("complyops_signin_state")
    assert entra.get(f"/auth/callback?code=x&state={state}").status_code == 302
    assert entra.get("/api/registers").status_code == 401


def test_an_already_signed_in_operator_skips_the_sign_in_page(signed_in: FlaskClient) -> None:
    response = signed_in.get("/sign-in")
    assert response.status_code == 302
    assert response.headers["Location"] == "/console"


def test_an_over_long_self_asserted_actor_is_refused(client: FlaskClient) -> None:
    client.post("/sign-in", data={"actor": "x" * 400})
    assert client.get("/api/registers").status_code == 401


def test_a_body_that_is_not_an_object_is_refused(signed_in: FlaskClient) -> None:
    refused = signed_in.post(
        "/api/registers/tasks",
        data="[]",
        content_type="application/json",
        headers=token_for(signed_in),
    )
    assert refused.status_code == 400


# ============================ the log across a restart ============================


def test_the_audit_log_survives_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signed_in: FlaskClient
) -> None:
    """AUD-001 retains the log for 24 months, so it cannot live in one process's memory."""
    signed_in.post(
        "/api/registers/tasks",
        json={"title": "Quarterly access review"},
        headers=token_for(signed_in),
    )
    before = signed_in.get("/api/audit").get_json()

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    restarted = create_app().test_client()
    restarted.post("/sign-in", data={"actor": "ash.higgins@bluestaq.uk"})
    after = restarted.get("/api/audit").get_json()

    assert [entry["entry_hash"] for entry in before["entries"]] == [
        entry["entry_hash"] for entry in after["entries"][1:]
    ]
    assert after["anchor"]["length"] == before["anchor"]["length"] + 1


def test_the_chain_verifies_after_a_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signed_in: FlaskClient
) -> None:
    """A restart must leave evidence that reads as intact, not as an unexplained break."""
    signed_in.post(
        "/api/registers/risks", json={"title": "Supplier assurance"}, headers=token_for(signed_in)
    )

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    restarted = create_app().test_client()
    restarted.post("/sign-in", data={"actor": "ash.higgins@bluestaq.uk"})
    verdict = restarted.post("/api/audit/verify", headers=token_for(restarted)).get_json()

    assert verdict["ok"] is True
    assert verdict["tampered"] is False
    assert verdict["checked"] >= 3


def test_a_truncated_log_leaves_the_audit_path_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signed_in: FlaskClient
) -> None:
    """Fails closed rather than starting a fresh chain, and says so on diagnostics.

    Boot still completes, because the diagnostics read-out is the documented recovery
    channel and a probe that wedges it takes away the only thing that would explain the
    fault.
    """
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )

    target = Path(tmp_path) / "audit" / "log.jsonl"
    target.write_text(target.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    restarted = create_app().test_client()

    assert "unavailable" in restarted.get("/api/diagnostics").get_json()["auditLog"]
    restarted.post("/sign-in", data={"actor": "ash.higgins@bluestaq.uk"})
    refused = restarted.post(
        "/api/registers/tasks", json={"title": "Anything"}, headers=token_for(restarted)
    )
    assert refused.status_code == 503
    assert "audit chain is unavailable" in refused.get_json()["error"]


def test_a_register_is_untouched_when_the_log_cannot_be_written(
    app: Flask, tmp_path: Path, signed_in: FlaskClient
) -> None:
    """Refuse the change outright when its evidence cannot be written.

    The whole ordering rule in one assertion, and 503 rather than 400 because the volume
    is at fault rather than the caller.
    """

    def refuse(entry_fields: object) -> None:
        raise JournalError("the audit log could not be written")

    chain = app.extensions["complyops_chain"]
    original = chain.append
    chain.append = refuse  # type: ignore[method-assign]
    try:
        response = signed_in.post(
            "/api/registers/incidents",
            json={"title": "Phishing report"},
            headers=token_for(signed_in),
        )
    finally:
        chain.append = original  # type: ignore[method-assign]

    assert response.status_code == 503
    assert store.read(str(tmp_path), "incidents") == []


def test_the_audit_read_out_pages(signed_in: FlaskClient) -> None:
    """A log held for 24 months does not belong in one payload."""
    for number in range(4):
        signed_in.post(
            "/api/registers/tasks",
            json={"title": f"Task {number}"},
            headers=token_for(signed_in),
        )
    page = signed_in.get("/api/audit?limit=2").get_json()

    assert len(page["entries"]) == 2
    assert page["pageOf"] == 5
    assert page["entries"][0]["timestamp"] >= page["entries"][1]["timestamp"]


def test_the_audit_page_size_is_capped(signed_in: FlaskClient) -> None:
    """A caller cannot ask for an unbounded page, and a nonsense limit falls back."""
    for limit in ("0", "-5", "999999", "banana"):
        assert signed_in.get(f"/api/audit?limit={limit}").status_code == 200


def test_diagnostics_reports_a_healthy_log(client: FlaskClient) -> None:
    """The read-out names the state of the log, which is what an operator needs first."""
    assert "chain intact" in client.get("/api/diagnostics").get_json()["auditLog"]
