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


# ============================ the global budget ============================


def test_a_many_address_flood_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """`MAXIMUM_TRACKED` bounds memory and never bounded rows.

    This module once stated that the per-address cap held a many-address flood to about
    4096 entries and 1.66 MiB per window. Measurement disproved it: 6000 distinct addresses
    wrote 6000 entries, 1.46 times the stated ceiling, scaling linearly with addresses. The
    global budget is the bound that actually exists.
    """
    monkeypatch.setattr(refusals, "GLOBAL_ROWS_PER_WINDOW", 50)
    recorded = sum(refusals.note(f"10.0.{i // 256}.{i % 256}", now=0.0).record for i in range(400))

    assert recorded == 50, "rows are capped across all addresses, not per address"


def test_the_budget_does_not_bite_inside_normal_use() -> None:
    """A handful of addresses refusing a few times each must still be individually recorded."""
    recorded = sum(
        refusals.note(f"10.0.0.{address}", now=float(index)).record
        for address in range(5)
        for index in range(2)
    )
    assert recorded == 10, "ordinary refusals are unaffected by the flood bound"


def test_the_overflow_is_counted_not_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    """A bound that loses what it bounded records nothing, which is the failure it replaces."""
    monkeypatch.setattr(refusals, "GLOBAL_ROWS_PER_WINDOW", 10)
    for index in range(60):
        refusals.note(f"10.1.{index // 256}.{index % 256}", now=0.0)

    after = refusals.note("10.9.9.9", now=refusals.WINDOW_SECONDS + 1)

    assert after.flood is not None
    assert after.flood.refusals == 50, "every refusal past the budget is counted"
    assert after.flood.addresses == 50, "and the number of distinct addresses is kept"


def test_the_overflow_reaches_the_log(
    app: Flask, client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """End to end: the bound has to produce a real entry, not just a Decision."""
    monkeypatch.setattr(refusals, "GLOBAL_ROWS_PER_WINDOW", 5)
    for index in range(40):
        client.get(
            "/auth/callback?code=x&state=forged",
            environ_base={"REMOTE_ADDR": f"10.2.{index // 256}.{index % 256}"},
        )
    for window in refusals._windows.values():
        window.started -= refusals.WINDOW_SECONDS + 1
    refusals._budget.started -= refusals.WINDOW_SECONDS + 1
    client.get("/auth/callback?code=x&state=forged", environ_base={"REMOTE_ADDR": "10.3.3.3"})

    flood = [
        entry
        for entry in app.extensions["complyops_chain"].entries
        if entry.action == "LOGIN_FAILED_FLOOD"
    ]
    assert flood, "the overflow must be recorded"
    assert flood[0].new_state == "REPEATED_35"
    assert flood[0].source_ip == "multiple", "no per-address attribution past the budget"
    assert flood[0].resource_id == "addresses-35"


def test_a_flood_entry_satisfies_the_audit_boundary(
    app: Flask, client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """It is an entry like any other, so it is held to the same rules."""
    monkeypatch.setattr(refusals, "GLOBAL_ROWS_PER_WINDOW", 2)
    for index in range(12):
        client.get(
            "/auth/callback?code=x&state=forged",
            environ_base={"REMOTE_ADDR": f"10.4.0.{index}"},
        )
    for window in refusals._windows.values():
        window.started -= refusals.WINDOW_SECONDS + 1
    refusals._budget.started -= refusals.WINDOW_SECONDS + 1
    client.get("/auth/callback?code=x&state=forged", environ_base={"REMOTE_ADDR": "10.5.5.5"})

    for entry in app.extensions["complyops_chain"].entries:
        assert normalise_fields(entry.covered_fields())


def test_the_address_set_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    """The structure that replaced unbounded rows must not itself be unbounded.

    Uncapped, this traded unbounded ROWS for unbounded MEMORY, which is worse: the
    post-budget path does no disk writing, so it is the cheapest request the application
    serves. Measured at 300,000 addresses in one window: 26.1 MiB resident uncapped against
    0.3 MiB with the cap, while `_windows` correctly stayed at 1024 throughout. An
    unauthenticated caller could drive the single worker to an out-of-memory restart, and a
    restart discards every pending count, which is the loss this module exists to prevent.
    """
    monkeypatch.setattr(refusals, "GLOBAL_ROWS_PER_WINDOW", 5)
    monkeypatch.setattr(refusals, "MAXIMUM_TRACKED", 16)
    for index in range(400):
        refusals.note(f"10.{index // 256}.0.{index % 256}", now=0.0)

    assert len(refusals._budget.addresses_over) <= 16, "the set must not grow without bound"
    assert refusals._budget.addresses_capped is True
    assert refusals._budget.refusals_over > 300, "every refusal is still counted"


def test_a_capped_address_count_is_reported_as_a_floor(monkeypatch: pytest.MonkeyPatch) -> None:
    """An assessor reading an exact-looking 1024 when it was 300,000 is being misled."""
    monkeypatch.setattr(refusals, "GLOBAL_ROWS_PER_WINDOW", 2)
    monkeypatch.setattr(refusals, "MAXIMUM_TRACKED", 8)
    for index in range(100):
        refusals.note(f"10.1.0.{index % 256}", now=0.0)

    after = refusals.note("10.9.9.9", now=refusals.WINDOW_SECONDS + 1)

    assert after.flood is not None
    assert after.flood.exact is False, "a capped count is a floor, and must say so"


def test_a_floor_reaches_the_log_as_a_floor(
    app: Flask, client: FlaskClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """And the entry says `atleast`, so the number cannot be read as precise."""
    monkeypatch.setattr(refusals, "GLOBAL_ROWS_PER_WINDOW", 2)
    monkeypatch.setattr(refusals, "MAXIMUM_TRACKED", 4)
    for index in range(30):
        client.get(
            "/auth/callback?code=x&state=forged",
            environ_base={"REMOTE_ADDR": f"10.6.0.{index}"},
        )
    for window in refusals._windows.values():
        window.started -= refusals.WINDOW_SECONDS + 1
    refusals._budget.started -= refusals.WINDOW_SECONDS + 1
    client.get("/auth/callback?code=x&state=forged", environ_base={"REMOTE_ADDR": "10.7.7.7"})

    flood = [
        entry
        for entry in app.extensions["complyops_chain"].entries
        if entry.action == "LOGIN_FAILED_FLOOD"
    ]
    assert flood, "the overflow must still be recorded"
    assert flood[0].resource_id.startswith("addresses-atleast-")


def test_summary_rows_are_charged_to_the_budget(monkeypatch: pytest.MonkeyPatch) -> None:
    """A cap named 500 must mean 500, not 500 plus however many summaries follow.

    `_budget.written` counted only individual refusals, so the collapse and flood entries
    fell outside it. Measured under the strategy that maximises them: 666 rows per window
    against a named cap of 500, 33 per cent above the figure this module asserted, which
    put the log's refusal cap 19.5 hours away rather than the 1.1 days recorded.
    """
    monkeypatch.setattr(refusals, "GLOBAL_ROWS_PER_WINDOW", 20)
    rows = 0
    for window_number in range(4):
        base = window_number * (refusals.WINDOW_SECONDS + 1)
        for index in range(60):
            decision = refusals.note(f"10.8.0.{index % 256}", now=base)
            rows += int(decision.record) + len(decision.collapsed)
            rows += 1 if decision.flood is not None else 0

    assert rows <= 20 * 4, f"{rows} rows written against a cap of 20 per window"
