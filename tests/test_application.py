"""The application end to end: the gate, the registers, the audit trail, the export."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.test import TestResponse

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from complyops import (
    create_app,
    records,
    store,
)
from complyops.audit import AuditFieldError, normalise_fields
from complyops.audit.journal import JournalError

#: Real key material, published here on purpose: it is not a credential.
SUITE_KEY = bytes(range(32)).hex()


@pytest.fixture
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Flask:
    """Return an application with a working audit chain on a fresh volume."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    return create_app()


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Return an unauthenticated client."""
    return app.test_client()


@pytest.fixture
def signed_in(client: FlaskClient) -> FlaskClient:
    """Return a client that has signed in."""
    sign_in_as(client, "ash.higgins@bluestaq.uk")
    return client


def token_for(client: FlaskClient) -> dict[str, str]:
    """Return the cross-site request forgery header for this session."""
    return {"X-CSRF-Token": client.get("/api/registers").headers["X-CSRF-Token"]}


def form_token(client: FlaskClient) -> str:
    """Return this session's request token, minting one if the session has none yet.

    The sign-in and sign-out forms both carry it now, so a test has to fetch it the way a
    browser does: load a page that renders the token, then submit it.
    """
    return str(client.get("/").headers["X-CSRF-Token"])


def sign_in_as(client: FlaskClient, actor: str, **extra: str) -> TestResponse:
    """Sign a client in the way the form does, carrying the request token."""
    return client.post("/sign-in", data={"actor": actor, "csrf_token": form_token(client), **extra})


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
    signed_in: FlaskClient, client: FlaskClient
) -> None:
    """A token that is real, well formed, and somebody else's is still refused.

    The victim's OWN token is fetched first, deliberately. Without that the session holds
    no token at all and `csrf.valid` refuses at the "no expected token" guard, so the test
    passed with the constant-time comparison replaced by `return True`: it proved the
    absence of a token, never the comparison.
    """
    mine = token_for(signed_in)["X-CSRF-Token"]
    other = signed_in.application.test_client()
    sign_in_as(other, "someone.else@bluestaq.uk")
    theirs = token_for(other)["X-CSRF-Token"]
    assert theirs != mine

    refused = signed_in.post(
        "/api/registers/tasks", json={"title": "x"}, headers={"X-CSRF-Token": theirs}
    )
    assert refused.status_code == 403


def test_a_well_formed_but_wrong_token_is_refused(signed_in: FlaskClient) -> None:
    """The comparison itself, held. This fails if `csrf.valid` ever returns True early."""
    mine = token_for(signed_in)["X-CSRF-Token"]
    forged = mine[:-1] + ("A" if mine[-1] != "A" else "B")

    refused = signed_in.post(
        "/api/registers/tasks", json={"title": "x"}, headers={"X-CSRF-Token": forged}
    )
    assert refused.status_code == 403
    assert records.read(str(signed_in.application.config["COMPLYOPS_DATA_DIR"]), "tasks") == []


def test_a_non_ascii_token_is_refused_rather_than_raising(signed_in: FlaskClient) -> None:
    """Fail closed on a non-ASCII token rather than raising.

    `compare_digest` raises TypeError on a non-ASCII str, and 500 is the wrong answer to a
    forged token; on the sign-in route it would also skip the audit entry.

    The session's own token is minted first, deliberately. Without that the comparison is
    never reached at all: `valid` returns False at the "no expected token" guard, and this
    test passed with the ASCII guard deleted.
    """
    token_for(signed_in)
    refused = signed_in.post(
        "/api/registers/tasks", json={"title": "x"}, headers={"X-CSRF-Token": "é" * 43}
    )
    assert refused.status_code == 403


def test_signing_out_needs_a_token(signed_in: FlaskClient) -> None:
    """Every state-changing route carries one, sign-out included."""
    assert signed_in.post("/sign-out").status_code == 403
    assert signed_in.get("/api/registers").status_code == 200, "still signed in"


def test_signing_in_needs_a_token(client: FlaskClient) -> None:
    """Login cross-site request forgery is still cross-site request forgery."""
    assert client.post("/sign-in", data={"actor": "ash.higgins@bluestaq.uk"}).status_code == 403
    assert client.get("/api/registers").status_code == 401


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
    sign_in_as(client, "")
    sign_in_as(client, "ash.higgins@bluestaq.uk")
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
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
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
    sign_in_as(entra, "attacker@evil.example")
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
    sign_in_as(client, "x" * 400)
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
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    restarted = create_app().test_client()
    sign_in_as(restarted, "ash.higgins@bluestaq.uk")
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
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    restarted = create_app().test_client()
    sign_in_as(restarted, "ash.higgins@bluestaq.uk")
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
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    restarted = create_app().test_client()
    sign_in_as(restarted, "ash.higgins@bluestaq.uk")

    assert "unavailable" in restarted.get("/api/diagnostics").get_json()["auditLog"]
    refused = restarted.post(
        "/api/registers/tasks", json={"title": "Anything"}, headers=token_for(restarted)
    )
    assert refused.status_code == 503
    body = refused.get_json()["error"]
    assert "the audit log is unavailable" in body
    assert str(tmp_path) not in body, "no server-side path may reach a client error"


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


def test_diagnostics_reports_a_healthy_log(signed_in: FlaskClient) -> None:
    """The read-out names the state of the log, which is what an operator needs first."""
    assert "chain intact" in signed_in.get("/api/diagnostics").get_json()["auditLog"]


def test_the_audit_log_line_is_not_disclosed_unauthenticated(client: FlaskClient) -> None:
    """It carries a filesystem path and an entry count, so it is signed-in only."""
    assert "auditLog" not in client.get("/api/diagnostics").get_json()


# ============================ verification reads the volume ============================


def test_verification_reads_the_volume_not_this_process(
    tmp_path: Path, signed_in: FlaskClient
) -> None:
    """The control has to be able to FAIL on an attacker-reachable input.

    It could not. Reading the process's own entries against the process's own anchor made
    both sides the same memory, so the check passed while the file on disk was truncated to
    one line and the anchor was deleted. Everything is now re-read from the volume.
    """
    for number in range(3):
        signed_in.post(
            "/api/registers/tasks",
            json={"title": f"Task {number}"},
            headers=token_for(signed_in),
        )
    assert signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()["ok"]

    target = Path(tmp_path) / "audit" / "log.jsonl"
    target.write_text(target.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["ok"] is False
    assert verdict["tampered"] is True


def test_verification_fails_when_the_anchor_is_deleted(
    tmp_path: Path, signed_in: FlaskClient
) -> None:
    """A missing anchor means nothing can be verified, which is not the same as intact."""
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )
    for name in ("audit-anchor.json", "audit-initialised"):
        (Path(tmp_path) / name).unlink()

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["ok"] is False
    assert "no anchor" in verdict["note"]


def test_the_export_pack_is_built_from_the_volume(tmp_path: Path, signed_in: FlaskClient) -> None:
    """The pack is the off-volume corroboration, so it must reflect the volume.

    A pack assembled from this process's memory would corroborate the volume against
    nothing at all.
    """
    signed_in.post(
        "/api/registers/risks", json={"title": "Supplier assurance"}, headers=token_for(signed_in)
    )
    target = Path(tmp_path) / "audit" / "log.jsonl"
    target.write_text(target.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")

    pack = signed_in.get("/api/export").get_json()
    assert len(pack["auditEntries"]) == 1, "read from the volume, which now holds one entry"
    assert pack["auditAnchor"]["length"] == 2, "and the anchor still records two"


# ============================ an actor that cannot be recorded ============================


def test_a_sign_in_whose_actor_cannot_be_audited_is_refused(client: FlaskClient) -> None:
    """An unrecorded sign-in is the attribution gap in-app authentication exists to close.

    The audit field rules are printable ASCII by allowlist, so an actor carrying a non-ASCII
    character cannot be written. That used to be swallowed and the sign-in succeeded, which
    left an operator acting on the registers with no AUD-001 authentication record at all.
    """
    landed = sign_in_as(client, "renée@bluestaq.uk")

    assert landed.headers["Location"].endswith("/sign-in")
    assert client.get("/api/registers").status_code == 401


def test_the_refusal_is_itself_recorded(app: Flask, client: FlaskClient) -> None:
    """AUD-001 requires the failed authentication event, and it must be recordable."""
    sign_in_as(client, "renée@bluestaq.uk")

    entries = app.extensions["complyops_chain"].entries
    assert [entry.action for entry in entries] == ["LOGIN_FAILED"]
    assert entries[0].outcome == "FAILURE"


def test_an_over_long_request_body_is_refused(signed_in: FlaskClient) -> None:
    """Werkzeug refuses it before any handler sees it, so no route defends itself."""
    oversized = signed_in.post(
        "/api/registers/tasks",
        json={"title": "x", "notes": "y" * (300 * 1024)},
        headers=token_for(signed_in),
    )
    assert oversized.status_code == 413


def test_an_unknown_field_name_is_not_mirrored_back(signed_in: FlaskClient) -> None:
    """A client error is not a mirror. The name is attacker-supplied and unbounded."""
    refused = signed_in.post(
        "/api/registers/tasks",
        json={"title": "Access review", "z" * 4000: "x"},
        headers=token_for(signed_in),
    )
    assert refused.status_code == 400
    assert len(refused.get_json()["error"]) < 200


def test_a_no_op_state_change_claims_no_transition(signed_in: FlaskClient) -> None:
    """Writing OPEN to OPEN into an immutable entry is a transition that never happened."""
    created = signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    ).get_json()["record"]
    signed_in.patch(
        f"/api/registers/tasks/{created['id']}",
        json={"state": created["state"]},
        headers=token_for(signed_in),
    )

    latest = signed_in.get("/api/audit").get_json()["entries"][0]
    assert latest["old_state"] == ""
    assert latest["new_state"] == ""


def test_verification_reports_a_volume_it_cannot_read(
    tmp_path: Path, signed_in: FlaskClient
) -> None:
    """A log that cannot be read is a fault to report, never a silent pass."""
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )
    (Path(tmp_path) / "audit" / "log.jsonl").write_text("{not json}\n", encoding="utf-8")

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["ok"] is False
    assert "could not be read" in verdict["note"]
    assert str(tmp_path) not in verdict["note"], "no server-side path in a client body"


def test_verification_reports_a_volume_that_disagrees_with_this_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signed_in: FlaskClient
) -> None:
    """A restored older anchor with a matching truncation, caught while the process runs.

    This is the attack `docs/DEPLOYMENT.md` records as surviving a RESTART: the refusal to
    move backwards lives in process memory. Inside one process it is caught, and the finding
    is reported as tampering rather than as an unreadable file.
    """
    signed_in.post("/api/registers/tasks", json={"title": "First"}, headers=token_for(signed_in))
    keep_log = (Path(tmp_path) / "audit" / "log.jsonl").read_bytes()
    keep_anchor = (Path(tmp_path) / "audit-anchor.json").read_bytes()

    signed_in.post("/api/registers/tasks", json={"title": "Second"}, headers=token_for(signed_in))
    (Path(tmp_path) / "audit" / "log.jsonl").write_bytes(keep_log)
    (Path(tmp_path) / "audit-anchor.json").write_bytes(keep_anchor)

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["ok"] is False
    assert verdict["tampered"] is True
    assert "shows interference" in verdict["note"]
    assert str(tmp_path) not in verdict["note"], "no server-side path in a client body"
    assert str(tmp_path) not in verdict["summary"], "nor in the summary"


def test_an_unknown_register_creates_nothing(signed_in: FlaskClient) -> None:
    """The action name falls back, and the register check still refuses the write."""
    refused = signed_in.post(
        "/api/registers/nonsense", json={"title": "x"}, headers=token_for(signed_in)
    )
    assert refused.status_code == 400
    assert "is not a register" in refused.get_json()["error"]


def test_a_patch_body_that_is_not_an_object_is_refused(signed_in: FlaskClient) -> None:
    """Both mutating routes check the body's shape, not only the create route."""
    created = signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    ).get_json()["record"]
    refused = signed_in.patch(
        f"/api/registers/tasks/{created['id']}", json=[1, 2, 3], headers=token_for(signed_in)
    )
    assert refused.status_code == 400


# ============================ a caller may not veto their own entry ============================


#: Every shape the audit boundary refuses, not only the non-ASCII one. A helper that
#: mirrored the character rule alone shipped once and left this hole open: a printable
#: ASCII agent beginning `-` passed the mirror, the boundary refused it, and the whole
#: entry was discarded, so an unauthenticated caller could still probe the callback route
#: leaving nothing behind.
HOSTILE_AGENTS = {
    "non-ascii": "Mozilla/5.0 \u00e9vil",
    "formula lead =": "=cmd|'/c calc'!A1",
    "formula lead -": "-Mozilla/5.0 (probe)",
    "formula lead +": "+44 probe",
    "formula lead @": "@SUM(A1)",
    "trailing whitespace": "Mozilla/5.0 ",
    "leading whitespace": " Mozilla/5.0",
    "double quote": 'Mozilla/5.0 "probe"',
    "over the cap": "M" * 900,
    "line separator": "Mozilla\u2028evil",
    "empty": "",
    "whitespace only": "   ",
    "null byte": "Mozilla\x00evil",
}
HOSTILE_AGENT = {"User-Agent": HOSTILE_AGENTS["non-ascii"]}


@pytest.mark.parametrize("shape", list(HOSTILE_AGENTS))
def test_no_header_shape_can_suppress_the_callback_entry(
    app: Flask, client: FlaskClient, shape: str
) -> None:
    """Every shape the boundary refuses, on the unauthenticated production-reachable route.

    The invariant is that an entry is ALWAYS written, never that the marker always appears:
    a value the helper can bring inside the rules by trimming or truncating is recorded as
    the trimmed value, which is better evidence than a marker. What a caller must never be
    able to do is leave nothing behind.
    """
    entries = app.extensions["complyops_chain"].entries
    client.get("/auth/callback?code=x&state=forged", headers={"User-Agent": HOSTILE_AGENTS[shape]})

    assert [entry.action for entry in entries] == ["LOGIN_FAILED"], shape
    assert normalise_fields(entries[0].covered_fields()), "the entry satisfies the boundary"


@pytest.mark.parametrize("shape", list(HOSTILE_AGENTS))
def test_no_header_shape_can_deny_a_sign_in(app: Flask, client: FlaskClient, shape: str) -> None:
    """A caller must not be able to refuse their own sign-in by choosing a header either."""
    landed = client.post(
        "/sign-in",
        data={"actor": "ash.higgins@bluestaq.uk", "csrf_token": form_token(client)},
        headers={"User-Agent": HOSTILE_AGENTS[shape]},
    )

    assert landed.headers["Location"].endswith("/console"), shape
    assert [entry.action for entry in app.extensions["complyops_chain"].entries] == ["LOGIN"]


def test_a_header_cannot_suppress_an_audit_entry_on_the_callback(
    app: Flask, client: FlaskClient
) -> None:
    """The route that mattered: unauthenticated, production-reachable, and it left nothing.

    Werkzeug decodes headers as latin-1, so any byte from 0x80 to 0xFF arrives as a
    non-ASCII character, the audit boundary refused the entry, and the refusal path wrote
    its LOGIN_FAILED entry through the same function with the same header, so that was
    discarded too. Probing the callback left no record at all, which deletes exactly the
    source address and user agent AUD-001 collects for security monitoring.
    """
    entries = app.extensions["complyops_chain"].entries
    client.get("/auth/callback?code=x&state=forged", headers=HOSTILE_AGENT)

    assert [entry.action for entry in entries] == ["LOGIN_FAILED"]
    assert entries[0].user_agent == "unrecordable"


def test_a_header_cannot_suppress_a_sign_in_entry(app: Flask, client: FlaskClient) -> None:
    """Same header, the self-asserted path, a successful sign-in."""
    entries = app.extensions["complyops_chain"].entries
    client.post(
        "/sign-in",
        data={"actor": "ash.higgins@bluestaq.uk", "csrf_token": form_token(client)},
        headers=HOSTILE_AGENT,
    )

    assert [entry.action for entry in entries] == ["LOGIN"]
    assert entries[0].user_agent == "unrecordable"


def test_a_header_cannot_suppress_a_register_entry(app: Flask, signed_in: FlaskClient) -> None:
    """And a mutation, where a suppressed entry would mean an unevidenced record change."""
    entries = app.extensions["complyops_chain"].entries
    before = len(entries)
    created = signed_in.post(
        "/api/registers/tasks",
        json={"title": "Access review"},
        headers={**token_for(signed_in), **HOSTILE_AGENT},
    )

    assert created.status_code == 201
    assert len(entries) == before + 1
    assert entries[-1].user_agent == "unrecordable"


@pytest.mark.parametrize(
    "shape",
    [
        "non-ascii",
        "formula lead =",
        "formula lead -",
        "double quote",
        "line separator",
        "whitespace only",
    ],
)
def test_a_value_that_cannot_be_brought_inside_the_rules_is_marked(
    app: Flask, client: FlaskClient, shape: str
) -> None:
    """And where trimming cannot help, the marker appears rather than a partial value."""
    client.get("/auth/callback?code=x&state=forged", headers={"User-Agent": HOSTILE_AGENTS[shape]})
    assert app.extensions["complyops_chain"].entries[0].user_agent == "unrecordable", shape


def test_the_marker_is_not_a_transliteration(app: Flask, client: FlaskClient) -> None:
    """The rule forbids transliterating a value. This records that it could not be recorded."""
    client.post(
        "/sign-in",
        data={"actor": "ash.higgins@bluestaq.uk", "csrf_token": form_token(client)},
        headers={"User-Agent": "curl/8 é"},
    )
    entry = app.extensions["complyops_chain"].entries[-1]

    assert entry.user_agent == "unrecordable"
    assert "curl" not in entry.user_agent, "no partial value survives"


def test_a_recordable_user_agent_is_recorded_verbatim(app: Flask, client: FlaskClient) -> None:
    """The marker is for a value that cannot be written, never a blanket replacement."""
    client.post(
        "/sign-in",
        data={"actor": "ash.higgins@bluestaq.uk", "csrf_token": form_token(client)},
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"},
    )
    assert (
        app.extensions["complyops_chain"].entries[-1].user_agent == "Mozilla/5.0 (Windows NT 10.0)"
    )


# ============================ anchor faults are not all the same fault ============================


def test_a_corrupt_anchor_is_not_reported_as_an_attack(
    tmp_path: Path, signed_in: FlaskClient
) -> None:
    """A file of nonsense is a fault to diagnose, not a restored-anchor attack.

    Reporting every anchor fault as a rollback showed an assessor the bytes
    `{ not an anchor` as evidence of tampering, which is the false alarm the verdict type
    exists to prevent.
    """
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )
    # The marker goes too. A corrupt anchor BESIDE a valid marker is interference: this
    # application only writes the anchor by renaming a fully written temporary file over it,
    # so it cannot produce an unparseable one. Without the marker there is nothing saying
    # the log was ever used, so an unreadable file is a fault to diagnose.
    (Path(tmp_path) / "audit-anchor.json").write_text("{ not an anchor", encoding="utf-8")
    (Path(tmp_path) / "audit-initialised").unlink()

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["ok"] is False
    assert verdict["tampered"] is False, "a corrupt file is not evidence of tampering"
    assert verdict["anchorUnusable"] is True
    assert verdict["invalidUnderCurrentRules"] is False, (
        "that flag means a tightened rule on an ENTRY, which is a false statement here"
    )
    assert "could not be read" in verdict["note"]
    # Positively, not only by two negative substrings: the fall-through summary ("the log
    # does not match its trusted anchor") satisfies both, and is itself a false statement,
    # because nothing was compared against the anchor. That is the exact misstatement this
    # branch was added to prevent, so the test asserted it away rather than for it.
    assert "the trusted anchor could not be read or used" in verdict["summary"]
    assert "does not satisfy the current field rules" not in verdict["summary"]
    assert "entry None" not in verdict["summary"]


def test_a_restored_older_anchor_is_reported_as_an_attack(
    tmp_path: Path, signed_in: FlaskClient
) -> None:
    """And the one anchor fault that DOES mean tampering still says so."""
    signed_in.post("/api/registers/tasks", json={"title": "First"}, headers=token_for(signed_in))
    keep_log = (Path(tmp_path) / "audit" / "log.jsonl").read_bytes()
    keep_anchor = (Path(tmp_path) / "audit-anchor.json").read_bytes()
    signed_in.post("/api/registers/tasks", json={"title": "Second"}, headers=token_for(signed_in))
    (Path(tmp_path) / "audit" / "log.jsonl").write_bytes(keep_log)
    (Path(tmp_path) / "audit-anchor.json").write_bytes(keep_anchor)

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["tampered"] is True
    assert "shows interference" in verdict["note"]
    # The summary is what reaches an audit record or an operator banner, so the reason
    # itself has to name the rollback rather than a generic read fault.
    assert "older anchor was restored" in verdict["summary"]


def test_the_export_survives_an_unusable_anchor(tmp_path: Path, signed_in: FlaskClient) -> None:
    """503, not an unhandled 500. The pack matters most when tampering has been detected."""
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )
    (Path(tmp_path) / "audit-anchor.json").write_text("{ not an anchor", encoding="utf-8")

    refused = signed_in.get("/api/export")
    assert refused.status_code == 503
    body = refused.get_json()["error"]
    assert "the audit anchor is unusable" in body
    assert str(tmp_path) not in body


def test_the_exported_anchor_comes_from_the_volume(tmp_path: Path, signed_in: FlaskClient) -> None:
    """Both halves of the pack, not only the entries. It is the whole corroboration.

    The in-memory head is moved without touching the volume, which is the only way to make
    the two sources disagree without also tripping the rollback guard.
    """
    signed_in.post("/api/registers/tasks", json={"title": "First"}, headers=token_for(signed_in))
    stored = json.loads((Path(tmp_path) / "audit-anchor.json").read_text(encoding="utf-8"))
    chain = signed_in.application.extensions["complyops_chain"]
    chain._chain.head = "0" * 64

    pack = signed_in.get("/api/export").get_json()
    assert pack["auditAnchor"]["head"] == stored["head"], "the volume's anchor, not this process's"
    assert pack["auditAnchor"]["head"] != chain.anchor().head


def test_a_volume_that_disagrees_with_this_process_is_reported(
    tmp_path: Path, signed_in: FlaskClient
) -> None:
    """A volume internally consistent but not the chain this process is appending to.

    `read_anchor`'s high-water mark catches a SHORTER total; this catches the case where
    the totals agree and the heads do not, which nothing else would notice.
    """
    signed_in.post("/api/registers/tasks", json={"title": "First"}, headers=token_for(signed_in))
    chain = signed_in.application.extensions["complyops_chain"]
    entries = list(chain.entries)
    chain.entries.clear()
    chain.entries.extend(entries)
    chain._chain.head = "0" * 64

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["ok"] is False
    assert "disagrees with this process" in verdict["note"]


def test_a_tab_in_the_next_path_cannot_bounce_the_operator_off_this_origin(
    client: FlaskClient,
) -> None:
    """Werkzeug strips the control character on the way out, turning a tab path into //x."""
    landed = client.post(
        "/sign-in",
        data={
            "actor": "ash.higgins@bluestaq.uk",
            "csrf_token": form_token(client),
            "next": "/\t/evil.example",
        },
    )
    assert landed.headers["Location"].endswith("/console")


def test_a_refusal_that_cannot_be_recorded_is_logged(
    app: Flask, client: FlaskClient, caplog: pytest.LogCaptureFixture
) -> None:
    """There is nothing left to substitute at that point, so it is logged rather than retried.

    `recordable` already stops a caller's headers vetoing the entry and the actor here is a
    fixed placeholder, so reaching this line means the boundary refused something no caller
    controls. Asserted because it is live code, not a defensive branch nothing reaches.
    """

    def refuse(entry_fields: object) -> None:
        raise AuditFieldError("nothing here can be recorded")

    chain = app.extensions["complyops_chain"]
    original = chain.append
    chain.append = refuse  # type: ignore[method-assign]
    try:
        with caplog.at_level("ERROR"):
            client.get("/auth/callback?code=x&state=forged")
    finally:
        chain.append = original  # type: ignore[method-assign]

    assert any("refusal itself could not be recorded" in r.getMessage() for r in caplog.records)


def test_an_anchor_signed_by_another_key_is_reported_as_interference(
    tmp_path: Path, signed_in: FlaskClient
) -> None:
    """An anchor this server cannot authenticate did not get there by accident.

    Splitting off only the rollback put this case in the "fault to diagnose" class, which
    turned a true positive into an all-clear on the read-out an assessor is shown.
    """
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )
    target = Path(tmp_path) / "audit-anchor.json"
    document = json.loads(target.read_text(encoding="utf-8"))
    document["mac"] = "f" * 64
    target.write_text(json.dumps(document), encoding="utf-8")

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["tampered"] is True, "an unauthenticated anchor is interference"
    assert verdict["anchorUnusable"] is False
    assert "not authenticated under the current key" in verdict["summary"]
    assert str(tmp_path) not in verdict["summary"]


def test_a_deleted_anchor_beside_a_surviving_marker_is_reported_as_interference(
    tmp_path: Path, signed_in: FlaskClient
) -> None:
    """The AUD-001 delete control's own signal. It must not read as a read fault."""
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )
    (Path(tmp_path) / "audit-anchor.json").unlink()

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["tampered"] is True
    assert "was removed" in verdict["summary"]


def test_a_mistyped_retired_key_is_a_verdict_not_an_exception(
    monkeypatch: pytest.MonkeyPatch, signed_in: FlaskClient
) -> None:
    """A verdict, never an exception. `keyUnavailable` exists for exactly this."""
    monkeypatch.setenv("AUDIT_RETIRED_KEYS", "k0:not-hex-at-all")

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["ok"] is False
    assert verdict["keyUnavailable"] is True
    assert verdict["tampered"] is False, "a configuration fault is not evidence of tampering"


@pytest.mark.parametrize(
    ("shape", "content"),
    [
        ("emptied", ""),
        ("two bytes of valid JSON", "{}"),
        ("a JSON array", "[]"),
        ("unparseable", "{ not an anchor"),
        ("binary", "\x00\xff\x00"),
        ("a bumped schema version", '{"schemaVersion": 99}'),
        ("a plausible but unusable document", '{"head": "x", "length": 1, "keyId": "k1"}'),
    ],
)
def test_a_corrupt_anchor_beside_a_marker_is_reported_as_interference(
    tmp_path: Path, signed_in: FlaskClient, shape: str, content: str
) -> None:
    """Every one-write content fault, not just the one that happens to raise ValueError.

    Keying the classification off the exception TYPE covered an emptied file and missed
    every other shape: `{}`, `[]`, a bumped schema version, a malformed key id all raise
    `AnchorError` from the parser, so overwriting the anchor with two bytes reported as a
    fault to diagnose while emptying it reported as tampering. Same attacker, same single
    write, opposite labels, and the cheaper attack bought the softer verdict. The rule is
    the marker, not the exception.
    """
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )
    (Path(tmp_path) / "audit-anchor.json").write_text(content, encoding="utf-8", errors="replace")

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["tampered"] is True, shape
    assert verdict["anchorUnusable"] is False, shape
    assert str(tmp_path) not in verdict["summary"], shape


def test_the_diagnostics_read_out_reports_a_wedged_chain(
    app: Flask, signed_in: FlaskClient
) -> None:
    """Every 503 says "See /api/diagnostics", so it has to report the fault it is named in.

    The boot status alone was stale by construction: it went on saying "chain intact" while
    the chain had wedged and nothing could be written.
    """
    chain = app.extensions["complyops_chain"]
    chain._wedged = "OSError: no space left on device at /data/audit/log.jsonl"
    try:
        line = signed_in.get("/api/diagnostics").get_json()["auditLog"]
    finally:
        chain._wedged = None

    assert "wedged since boot: OSError" in line
    assert "/data/audit/log.jsonl" not in line, "the path stays in the pod log"


@pytest.mark.parametrize("shape", ["a directory", "a symlink to nothing", "a named pipe"])
def test_an_anchor_replaced_by_something_that_is_not_a_file(
    tmp_path: Path, signed_in: FlaskClient, shape: str
) -> None:
    """One command, no key, and the softer verdict was back.

    Leaving the access fault keyed on the exception type reintroduced the hole the state
    rule was written to close: `mkdir audit-anchor.json` beside a valid marker raised
    IsADirectoryError and reported as a fault to diagnose. The named pipe was worse than a
    wrong verdict: `read_text` blocked forever on the boot path, so the worker never
    finished loading, nothing answered the health paths, and the pod restart-looped.
    """
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )
    target = Path(tmp_path) / "audit-anchor.json"
    target.unlink()
    if shape == "a directory":
        target.mkdir()
    elif shape == "a symlink to nothing":
        target.symlink_to(Path(tmp_path) / "does-not-exist")
    else:
        os.mkfifo(target)

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["tampered"] is True, shape
    assert verdict["anchorUnusable"] is False, shape


def test_a_named_pipe_in_place_of_the_log_does_not_hang_the_boot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signed_in: FlaskClient
) -> None:
    """The hard rule: nothing in this path may prevent boot or block indefinitely."""
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )
    target = Path(tmp_path) / "audit" / "log.jsonl"
    target.unlink()
    os.mkfifo(target)

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    restarted = create_app().test_client()

    assert restarted.get("/healthz").status_code == 200, "the pod must still serve"
    sign_in_as(restarted, "ash.higgins@bluestaq.uk")
    assert "not a regular file" in restarted.get("/api/diagnostics").get_json()["auditLog"]


def test_a_read_fault_with_no_marker_stays_a_fault(tmp_path: Path, signed_in: FlaskClient) -> None:
    """Without the marker there is nothing saying the log was used, so it is a fault.

    The recorded limit of the state rule, asserted so it cannot quietly become an alarm.
    """
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )
    (Path(tmp_path) / "audit-anchor.json").unlink()
    (Path(tmp_path) / "audit-anchor.json").mkdir()
    (Path(tmp_path) / "audit-initialised").unlink()

    verdict = signed_in.post("/api/audit/verify", headers=token_for(signed_in)).get_json()
    assert verdict["tampered"] is False
    assert verdict["anchorUnusable"] is True
    assert "not a regular file" in verdict["summary"] or "could not be read" in verdict["summary"]


@pytest.mark.parametrize("shape", ["a directory", "a symlink to nothing", "a named pipe"])
@pytest.mark.parametrize("target_name", ["audit-anchor.json", "audit-initialised", "log.jsonl"])
def test_no_audit_file_can_be_replaced_by_something_that_is_not_a_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    signed_in: FlaskClient,
    shape: str,
    target_name: str,
) -> None:
    """All THREE paths, not two. The marker was the one no test reached.

    The anchor and the log were parametrised; `audit-initialised` was not, and its guard
    survived mutation because of it. `_marker_is_valid` runs from the app factory, so a
    named pipe there blocks `read_anchor` forever, the worker never finishes loading, and
    the pod restart-loops with no diagnostics reachable. Identical consequence to the two
    shapes that were covered, on the path that was not.
    """
    signed_in.post(
        "/api/registers/tasks", json={"title": "Access review"}, headers=token_for(signed_in)
    )
    target = (
        Path(tmp_path) / "audit" / "log.jsonl"
        if target_name == "log.jsonl"
        else Path(tmp_path) / target_name
    )
    target.unlink()
    if shape == "a directory":
        target.mkdir()
    elif shape == "a symlink to nothing":
        target.symlink_to(Path(tmp_path) / "does-not-exist")
    else:
        os.mkfifo(target)

    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")

    restarted = create_app().test_client()

    assert restarted.get("/healthz").status_code == 200, f"{target_name} as {shape} hung the boot"
