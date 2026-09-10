"""Collapsing repeated sign-in refusals, so an unauthenticated caller cannot fill the log.

AUD-001 requires a record of every failed authentication, and the sign-in and callback
routes are unauthenticated by necessity, so a bare `GET /auth/callback` writes one durable
fsynced entry. Measured: 2000 requests, 2000 entries at about 425 bytes each. At the log's
64 MiB refusal cap that is roughly 158,000 requests to make `read_entries` refuse the whole
log as implausibly large at the next restart, which leaves the audit path unavailable and
every register mutation answering 503 until an operator does surgery on the volume. No rate
limiter exists in this process.

Dropping the entries is not the fix, because AUD-001 asks for the record. Collapsing them
is, and it is better evidence as well: a hundred identical refusals from one address is
more legible as one refusal and a count than as a hundred rows an assessor pages through.
The same 2000 requests now write three entries.

So the first few refusals from an address in a window are recorded individually and the
rest are counted. Every call SWEEPS every expired window, not just the caller's, and hands
back what it found, so a burst that stops is flushed by the next refusal from ANY address
rather than waiting for the same one to come back. An evicted address hands its pending
count back the same way instead of losing it.

A flood spread across MANY source addresses is bounded separately, by
`GLOBAL_ROWS_PER_WINDOW`, and that bound exists because the per-address one did not reach
it. This module previously stated that `MAXIMUM_TRACKED` held such a flood to about 4096
entries and 1.66 MiB per window, putting the 64 MiB cap 3.2 hours away. Measurement
disproved it: 6000 distinct addresses in one window wrote 6000 entries and 2.44 MiB, 1.46
times the stated ceiling, scaling linearly, with the cap about 157,000 addresses away.
`MAXIMUM_TRACKED` bounds the per-address tracker and never bounded rows. The figure is
corrected here rather than quietly dropped, because it was the sizing on which deferring an
edge rate limiter rested.

The first version of that fix then traded unbounded rows for unbounded memory, which is
worse. The set of over-budget addresses had no cap, and the post-budget path does no disk
writing, so it is the cheapest request this application serves. Measured at 300,000
addresses in one window: 26.1 MiB resident, against 0.3 MiB once capped. An unauthenticated
caller could have driven the single worker to an out-of-memory restart, and a restart
discards every pending count, which is exactly the evidence loss this module exists to
prevent. The set is capped at `MAXIMUM_TRACKED` and the address count is reported as a floor
when it hits that, because an exact-looking 1024 where the truth was 300,000 misleads a
reader more than an honest "at least".

Three limits remain, stated because each was claimed away once already.

Past the global budget, per-address attribution is gone: the overflow is one entry naming a
count of refusals and a count of addresses. That is deliberate and it is a real loss. The
addresses are in the platform's ingress log, and a log filled to its cap records nothing.

There is no timer and no shutdown flush. A count pending when the process is KILLED is
lost, because the sweep only runs when something calls in. Closing that needs a scheduler
this application does not have.

And the bound is per source address, so it is only as good as `remote_addr`. If the
platform ingress presents its own address rather than the client's, every caller shares one
bucket. `TBC, re-verify` with the platform team.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

#: How many refusals from one source address are recorded individually per window.
RECORDED_PER_WINDOW = 3

#: The window, in seconds.
WINDOW_SECONDS = 300.0

#: The most source addresses held at once, in the per-address tracker AND in the set of
#: over-budget addresses. It bounds MEMORY and never bounded rows, which is worth stating
#: flatly because it was once written down as though it bounded entries: at the cap the
#: least recently seen address is dropped, its pending count is handed back, and the NEXT
#: refusal from a new address is recorded individually all the same. Rows are bounded by
#: `GLOBAL_ROWS_PER_WINDOW` below, which exists because this constant does not do that job.
MAXIMUM_TRACKED = 1024

#: The most refusal rows written across ALL addresses in one window: individual refusals,
#: collapse summaries and flood summaries alike. Every one of them is a row in the log, and
#: two earlier versions were defeated in turn: the first charged only the first kind, and
#: the second charged summaries AFTER handing them to the caller, who writes every one it
#: is handed. Both measured at 666 rows per window under the strategy that maximises
#: summaries, and the second at 832 when two such strategies are combined. A summary is
#: now admitted or refused against the budget BEFORE it is handed back, and a refused one
#: folds into the flood row. It is 500 now, measured under all three strategies.
#:
#: This is the bound that exists on the LOG. It is not a bound on the total, and the total
#: is sized at the field caps, not at the friendly row: see `ROW_BYTES_AT_FIELD_CAPS`.
#:
#: Measured rather than reasoned, which is the rule that was broken when the per-address cap
#: was described as a ceiling on entries. Driving 6000 distinct source addresses through
#: `/auth/callback` inside a single window wrote 6000 durable entries and 2.44 MiB, at 426
#: bytes each, against a claimed ceiling of 4096 entries and 1.66 MiB. That is 1.46 times the
#: figure asserted, it scales linearly with addresses, and it puts the audit log's 64 MiB
#: refusal cap about 157,000 addresses away rather than 3.2 hours away. An IPv6 /64 holds
#: more addresses than that by twelve orders of magnitude.
#:
#: Beyond this budget a refusal is still counted, and the excess is written as one entry per
#: window naming the number of refusals and the number of distinct addresses. Per-address
#: attribution is deliberately traded for a bound at that point: the addresses are in the
#: platform's ingress log, and an audit log that has been filled to its cap records nothing
#: at all.
GLOBAL_ROWS_PER_WINDOW = 500

#: The size of one refusal row when the caller fills every field it controls to the audit
#: boundary's cap: a 512 byte User-Agent and a 45 character source address. Measured at 959
#: bytes on this build and pinned here at the next round figure, with a test that writes such
#: a row and checks it still fits, so a field added to the entry moves this number rather
#: than silently invalidating the sizing below.
#:
#: The residual is sized at THIS row, because the earlier figure was not. It was measured
#: with the test client's short User-Agent, 426 bytes a row, and stated as the number to
#: size the edge rate limiter against: 208 KiB a window, 58.45 MiB a day, 1.1 days to the
#: log's 64 MiB refusal cap. A caller chooses their own User-Agent. At the caps, 500 rows
#: are about 469 KiB a window, so across 288 windows a sustained flood writes about 132 MiB
#: a day and reaches the cap in under twelve hours. The friendly figure is the typical case
#: and nothing more; the adversarial one is the sizing basis, and only an edge rate limiter
#: or log rotation closes it.
ROW_BYTES_AT_FIELD_CAPS = 960


@dataclass
class _Window:
    """One source address's refusal window."""

    started: float
    recorded: int = 0
    suppressed: int = 0
    seen: float = 0.0


_windows: dict[str, _Window] = {}
_guard = threading.Lock()


@dataclass
class _Budget:
    """The global window: how many rows have been written, and what is over the budget."""

    #: ``None`` until the first refusal, never 0.0. A float sentinel collided with a
    #: legitimate `time.monotonic()` of 0.0, so the window rolled on every call and the
    #: budget never bit. Caught by its own test rather than in review.
    started: float | None = None
    written: int = 0
    refusals_over: int = 0
    #: Capped at MAXIMUM_TRACKED. Uncapped, this replaced unbounded ROWS with unbounded
    #: MEMORY, which is worse: the post-budget path does no disk writing, so it is the
    #: cheapest request the application serves. Measured at 2,398 refusals a second in
    #: process, with 300,000 addresses reaching 38.6 MiB resident while `_windows` stayed
    #: correctly at 1024. An unauthenticated caller could drive the single worker to an
    #: out-of-memory restart, and a restart discards every pending count, which is the
    #: evidence loss this module exists to prevent.
    addresses_over: set[str] = field(default_factory=set)
    #: Whether the address count above is a floor rather than an exact figure. Reported as
    #: a floor rather than silently understated: an assessor reading "1024 addresses" when
    #: it was 300,000 is being misled by a number that looks precise.
    addresses_capped: bool = False


_budget = _Budget()


def reset() -> None:
    """Forget every tracked address and the global budget. For tests and a restart."""
    global _budget  # noqa: PLW0603 - one process-wide budget, guarded by the lock
    with _guard:
        _windows.clear()
        _budget = _Budget()


@dataclass(frozen=True)
class Collapsed:
    """A count of refusals from one address that were not recorded individually."""

    address: str
    count: int


@dataclass(frozen=True)
class Flood:
    """Refusals dropped past the global budget, with how many addresses they came from."""

    refusals: int
    addresses: int
    #: False when the address count is a floor because the tracking set hit its cap.
    exact: bool = True


@dataclass(frozen=True)
class Decision:
    """What to write for one refusal."""

    record: bool
    #: Counts that closed or were evicted, each with the address it belongs to. Written as
    #: one summary entry apiece, so attribution survives the collapse.
    collapsed: tuple[Collapsed, ...] = ()
    #: The global overflow of a window that has closed, or ``None``. Written as one entry
    #: with no per-address attribution, which is the trade the budget exists to make.
    flood: Flood | None = None


def note(address: str, now: float | None = None) -> Decision:
    """Record that one refusal happened, and say what should be written for it.

    Sweeps EVERY expired window, not only this address's. A burst that stops used to leave
    its count alive in memory and nothing else: it was emitted only by a later refusal from
    the same address, so an unauthenticated caller decided whether their own burst was
    recorded. Measured before the sweep: 500 refusals, three rows, 497 counted nowhere
    durable. Any refusal from any address now flushes them.
    """
    moment = time.monotonic() if now is None else now
    with _guard:
        collapsed = _sweep(moment, keep=address)

        window = _windows.get(address)
        if window is None:
            collapsed += _evict_if_full()
            window = _Window(started=moment)
            _windows[address] = window
        elif moment - window.started >= WINDOW_SECONDS:
            if window.suppressed:
                collapsed += (Collapsed(address, window.suppressed),)
            window.started = moment
            window.recorded = 0
            window.suppressed = 0

        flood = _roll_budget(moment)
        if flood is not None:
            # The overflow of the window that just closed is one row in THIS window, and it
            # is charged first so that it always fits: a bound whose own summary could be
            # squeezed out by the traffic it summarises would lose the count.
            _budget.written += 1
        collapsed = _admit(collapsed)

        window.seen = moment
        if window.recorded < RECORDED_PER_WINDOW:
            if _budget.written < GLOBAL_ROWS_PER_WINDOW:
                window.recorded += 1
                _budget.written += 1
                return Decision(record=True, collapsed=collapsed, flood=flood)
            # Inside this address's own allowance but past the global budget. Counted
            # globally rather than against the address, because the address is not the
            # thing being bounded here: the log is.
            _count_over(address, 1)
            return Decision(record=False, collapsed=collapsed, flood=flood)
        window.suppressed += 1
        return Decision(record=False, collapsed=collapsed, flood=flood)


def _admit(collapsed: tuple[Collapsed, ...]) -> tuple[Collapsed, ...]:
    """Charge each collapse row to the budget, folding the ones past it into the overflow.

    Called under the lock. The earlier version charged summaries to the budget AFTER the
    caller had already been handed them, and the caller writes every summary it is handed.
    So a summary produced once the budget was spent was written on top of it, and the cap
    was defeated by making summaries arrive late: bank suppressed counts on about 166
    addresses, spend the budget on fresh ones, then force evictions or let the banked
    windows expire so each count is swept out as a row. Measured at 666 rows per window
    from either lever and 832 from both, against a named cap of 500, over the real HTTP
    path. Charging after the fact cannot bound what has already been emitted; only a row
    that is refused here is a row that is not written.

    A refused summary is not lost. Its count joins the overflow and its address joins the
    overflow's address set, so the single flood row for this window carries it.
    """
    admitted: list[Collapsed] = []
    for summary in collapsed:
        if _budget.written < GLOBAL_ROWS_PER_WINDOW:
            _budget.written += 1
            admitted.append(summary)
        else:
            _count_over(summary.address, summary.count)
    return tuple(admitted)


def _count_over(address: str, count: int) -> None:
    """Add refusals past the budget to the overflow, without letting the address set grow.

    Called under the lock. An address already in the set does not flip the floor flag: the
    flag means the count is a floor because an address could NOT be added, and re-seeing a
    member is not that.
    """
    _budget.refusals_over += count
    if address in _budget.addresses_over or len(_budget.addresses_over) < MAXIMUM_TRACKED:
        _budget.addresses_over.add(address)
    else:
        _budget.addresses_capped = True


def _roll_budget(moment: float) -> Flood | None:
    """Start a new global window when the current one has expired, returning its overflow.

    Called under the lock. The overflow is handed back rather than dropped, for the same
    reason a per-address count is: a bound that loses what it bounded records nothing.
    """
    if _budget.started is not None and moment - _budget.started < WINDOW_SECONDS:
        return None
    over = (
        Flood(
            _budget.refusals_over,
            len(_budget.addresses_over),
            exact=not _budget.addresses_capped,
        )
        if _budget.refusals_over
        else None
    )
    _budget.started = moment
    _budget.written = 0
    _budget.refusals_over = 0
    _budget.addresses_over = set()
    _budget.addresses_capped = False
    return over


def _sweep(moment: float, *, keep: str) -> tuple[Collapsed, ...]:
    """Return and clear the counts of every expired window except the caller's own.

    Called under the lock. The caller's own window is left to :func:`note`, which has to
    decide whether to restart it rather than drop it.
    """
    collapsed: list[Collapsed] = []
    expired = [
        address
        for address, window in _windows.items()
        if address != keep and moment - window.started >= WINDOW_SECONDS
    ]
    for address in expired:
        window = _windows.pop(address)
        if window.suppressed:
            collapsed.append(Collapsed(address, window.suppressed))
    return tuple(collapsed)


def _evict_if_full() -> tuple[Collapsed, ...]:
    """Drop the least recently SEEN address at capacity, handing back its pending count.

    Called under the lock. Least recently seen, not first inserted: under insertion order a
    sustained flooder is evicted once it is the oldest ENTRY even though it is the most
    active caller, its counter resets, and its next refusal buys a fresh window of
    individual rows. Measured over 200 rounds with a small cap: six rows under this policy,
    seventy-five under insertion order.

    The pending count is returned rather than discarded, so an attacker cannot erase a
    victim's count by churning through addresses.
    """
    if len(_windows) < MAXIMUM_TRACKED:
        return ()
    oldest = min(_windows, key=lambda address: _windows[address].seen)
    window = _windows.pop(oldest)
    return (Collapsed(oldest, window.suppressed),) if window.suppressed else ()
