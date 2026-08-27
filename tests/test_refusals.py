"""Collapsing repeated sign-in refusals, and what that does and does not close.

An unauthenticated caller could write one durable fsynced audit entry per request against
`/auth/callback`, so a bare loop filled the log toward its refusal cap and left the audit
path unavailable at the next restart, with every register mutation answering 503. AUD-001
wants the failed-authentication record, so the entries are counted rather than dropped.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from complyops import create_app
from complyops.audit import normalise_fields
from complyops.views import refusals

#: Real key material, published here on purpose: it is not a credential.
SUITE_KEY = bytes(range(32)).hex()


@pytest.fixture
def app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Flask:
    """Return an application with a working audit chain on a fresh volume."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    return create_app()


@pytest.fixture
def client(app: Flask) -> FlaskClient:
    """Return an unauthenticated client."""
    return app.test_client()


def probe(client: FlaskClient) -> None:
    """Make one refusable unauthenticated request."""
    client.get("/auth/callback?code=x&state=forged")


# ============================ the tracker in isolation ============================


def test_the_first_few_refusals_are_recorded_individually() -> None:
    """Evidence first. A handful of refusals is a handful of rows."""
    decisions = [refusals.note("10.0.0.1", now=float(index)) for index in range(10)]

    assert sum(decision.record for decision in decisions) == refusals.RECORDED_PER_WINDOW
    assert all(decision.collapsed == 0 for decision in decisions)


def test_the_tail_is_reported_when_the_window_closes() -> None:
    """A flood that stops still leaves its count recorded, on the next refusal."""
    for index in range(10):
        refusals.note("10.0.0.1", now=float(index))

    after = refusals.note("10.0.0.1", now=refusals.WINDOW_SECONDS + 1)

    assert after.record is True, "a new window records individually again"
    assert after.collapsed == 10 - refusals.RECORDED_PER_WINDOW


def test_one_address_cannot_collapse_another() -> None:
    """The count is per source address, so a noisy one does not hide a quiet one."""
    for index in range(10):
        refusals.note("10.0.0.1", now=float(index))

    assert refusals.note("10.0.0.2", now=11.0).record is True


def test_the_tracker_itself_is_bounded() -> None:
    """Otherwise one entry per spoofed address is the exhaustion instead of the log."""
    for index in range(refusals.MAXIMUM_TRACKED + 200):
        refusals.note(f"10.0.{index // 256}.{index % 256}", now=float(index))

    assert len(refusals._windows) <= refusals.MAXIMUM_TRACKED


def test_the_least_recently_seen_address_is_the_one_dropped() -> None:
    """A live attacker must not be able to evict the record of a quiet one they replaced."""
    refusals.note("10.0.0.1", now=0.0)
    for index in range(refusals.MAXIMUM_TRACKED + 10):
        address = f"10.9.{index // 256}.{index % 256}"
        refusals.note(address, now=float(index + 1))

    assert "10.0.0.1" not in refusals._windows


# ============================ through the routes ============================


def test_a_flood_from_one_address_does_not_write_one_entry_per_request(
    app: Flask, client: FlaskClient
) -> None:
    """The whole point. Fifty unauthenticated requests must not be fifty durable rows."""
    for _ in range(50):
        probe(client)

    entries = app.extensions["complyops_chain"].entries
    assert len(entries) == refusals.RECORDED_PER_WINDOW


def test_the_collapsed_count_reaches_the_log(app: Flask, client: FlaskClient) -> None:
    """Counted, not dropped: AUD-001 asks for the record of a failed authentication."""
    for _ in range(20):
        probe(client)
    refusals.note("collapse-the-window", now=0.0)
    # Force the window closed the way time would, then make one more refusal.
    for window in refusals._windows.values():
        window.started -= refusals.WINDOW_SECONDS + 1
    probe(client)

    entries = app.extensions["complyops_chain"].entries
    summary = [entry for entry in entries if entry.action == "LOGIN_FAILED_REPEATED"]
    assert summary, "the suppressed count must be recorded"
    assert summary[0].new_state == f"REPEATED_{20 - refusals.RECORDED_PER_WINDOW}"
    assert summary[0].outcome == "FAILURE"


def test_a_collapsed_entry_still_satisfies_the_audit_boundary(
    app: Flask, client: FlaskClient
) -> None:
    """It is an entry like any other, so it is held to the same rules."""
    for _ in range(20):
        probe(client)
    for window in refusals._windows.values():
        window.started -= refusals.WINDOW_SECONDS + 1
    probe(client)

    for entry in app.extensions["complyops_chain"].entries:
        assert normalise_fields(entry.covered_fields())


def test_a_successful_sign_in_is_never_collapsed(app: Flask, client: FlaskClient) -> None:
    """Only refusals are counted. A real sign-in is always its own row."""
    for _ in range(10):
        probe(client)
    client.post(
        "/sign-in",
        data={
            "actor": "ash.higgins@bluestaq.uk",
            "csrf_token": client.get("/").headers["X-CSRF-Token"],
        },
    )

    entries = app.extensions["complyops_chain"].entries
    assert entries[-1].action == "LOGIN"
    assert entries[-1].actor.startswith("ash.higgins@bluestaq.uk")
