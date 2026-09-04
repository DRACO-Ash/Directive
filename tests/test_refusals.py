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
    assert all(decision.collapsed == () for decision in decisions)


def test_the_tail_is_reported_when_the_window_closes() -> None:
    """A flood that stops still leaves its count recorded, on the next refusal."""
    for index in range(10):
        refusals.note("10.0.0.1", now=float(index))

    after = refusals.note("10.0.0.1", now=refusals.WINDOW_SECONDS + 1)

    assert after.record is True, "a new window records individually again"
    assert after.collapsed == (refusals.Collapsed("10.0.0.1", 10 - refusals.RECORDED_PER_WINDOW),)


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


def test_the_least_recently_seen_survives_an_address_churn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The active caller survives an eviction; the genuinely stale one is dropped.

    Least recently SEEN, not first inserted, and the distinction is the whole bound. Two
    shapes of test fail to tell them apart and both were written here before this one.
    Noting each address once in increasing time order makes insertion and recency order
    identical. Re-noting the flooder AFTER every eviction also passes under insertion
    order, because re-noting reinserts it at the end of the dict.

    So the flooder is re-noted BEFORE the eviction and never again: under insertion order
    it is still the first key and goes first, and under recency it is the newest and stays.
    Under insertion order a sustained flooder is evicted while still active, its counter
    resets, and its next refusal buys a fresh window of individual rows. Measured over 200
    rounds: six rows under this policy, seventy-five under insertion order.
    """
    monkeypatch.setattr(refusals, "MAXIMUM_TRACKED", 8)
    refusals.note("sustained", now=0.0)
    for index in range(7):
        refusals.note(f"quiet-{index}", now=float(index + 1))
    assert len(refusals._windows) == 8, "the tracker is full and nothing has been evicted"

    # The flooder is now the FIRST key and the MOST recently seen at the same time.
    refusals.note("sustained", now=100.0)
    refusals.note("one-more", now=101.0)

    assert "sustained" in refusals._windows, "the active caller must survive the eviction"
    assert "quiet-0" not in refusals._windows, "the genuinely stale one goes"


def test_an_evicted_count_is_handed_back_rather_than_dropped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Otherwise churning through addresses erases a victim's count silently.

    Measured before this: 50 refusals from a victim, then 1029 other addresses, and 47
    refusals vanished with no summary entry written anywhere.
    """
    monkeypatch.setattr(refusals, "MAXIMUM_TRACKED", 4)
    for index in range(20):
        refusals.note("victim", now=float(index))
    pending = refusals._windows["victim"].suppressed
    assert pending == 20 - refusals.RECORDED_PER_WINDOW

    handed_back: list[refusals.Collapsed] = []
    for index in range(12):
        handed_back.extend(refusals.note(f"churn-{index}", now=float(index + 21)).collapsed)

    assert refusals.Collapsed("victim", pending) in handed_back


def test_a_burst_that_stops_is_flushed_by_any_later_refusal() -> None:
    """The caller must not decide whether their own burst is recorded.

    The count used to be emitted only by a later refusal from the SAME address, so an
    attacker who stopped left 497 of 500 refusals counted nowhere durable.
    """
    # Inside one window: spreading 500 calls over 500 seconds rolls the window mid-burst
    # and resets the count, which is correct behaviour and not what this test is about.
    for index in range(500):
        refusals.note("10.0.0.1", now=index * 0.1)

    later = refusals.note("10.0.0.9", now=refusals.WINDOW_SECONDS + 600.0)

    assert refusals.Collapsed("10.0.0.1", 500 - refusals.RECORDED_PER_WINDOW) in later.collapsed


def test_a_sweep_leaves_a_live_window_alone() -> None:
    """Only EXPIRED windows are swept, or a busy address would be flushed mid-window."""
    refusals.note("10.0.0.1", now=0.0)
    refusals.note("10.0.0.2", now=1.0)

    assert refusals.note("10.0.0.3", now=2.0).collapsed == ()
    assert "10.0.0.1" in refusals._windows


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


def test_a_burst_that_stops_reaches_the_log_through_another_caller(
    app: Flask, client: FlaskClient
) -> None:
    """End to end: the flush has to produce a real entry, not just a Decision."""
    for _ in range(30):
        probe(client)
    for window in refusals._windows.values():
        window.started -= refusals.WINDOW_SECONDS + 1

    other = app.test_client()
    other.get("/auth/callback?code=x&state=forged", environ_base={"REMOTE_ADDR": "10.9.9.9"})

    summary = [
        entry
        for entry in app.extensions["complyops_chain"].entries
        if entry.action == "LOGIN_FAILED_REPEATED"
    ]
    assert summary, "another caller's refusal must flush the stopped burst"
    assert summary[0].new_state == f"REPEATED_{30 - refusals.RECORDED_PER_WINDOW}"
    assert summary[0].source_ip == "127.0.0.1", "attributed to the address it came from"


def test_a_summary_entry_is_attributed_to_its_own_address(app: Flask, client: FlaskClient) -> None:
    """A merged total would collapse the attribution as well as the rows."""
    for address in ("10.1.1.1", "10.2.2.2"):
        for _ in range(10):
            client.get("/auth/callback?code=x&state=forged", environ_base={"REMOTE_ADDR": address})
    for window in refusals._windows.values():
        window.started -= refusals.WINDOW_SECONDS + 1
    client.get("/auth/callback?code=x&state=forged", environ_base={"REMOTE_ADDR": "10.3.3.3"})

    summaries = {
        entry.source_ip: entry.new_state
        for entry in app.extensions["complyops_chain"].entries
        if entry.action == "LOGIN_FAILED_REPEATED"
    }
    assert summaries == {
        "10.1.1.1": f"REPEATED_{10 - refusals.RECORDED_PER_WINDOW}",
        "10.2.2.2": f"REPEATED_{10 - refusals.RECORDED_PER_WINDOW}",
    }
