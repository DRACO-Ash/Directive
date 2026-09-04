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
`MAXIMUM_TRACKED` bounds memory and never bounded rows. The figure is corrected here rather
than quietly dropped, because it was the sizing on which deferring an edge rate limiter
rested.

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

#: The most source addresses tracked at once. This bounds MEMORY and nothing else, which
#: is worth stating flatly because it was once written down as though it bounded entries.
#: At the cap the least recently seen address is dropped and its pending count is handed
#: back, and the NEXT refusal from a new address is recorded individually all the same, so
#: refusal rows scale with distinct source addresses rather than with this number.
MAXIMUM_TRACKED = 1024

#: The most individual refusal rows written across ALL addresses in one window. This is the
#: bound that actually exists on the log, and it exists because the per-address one did not.
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
    addresses_over: set[str] = field(default_factory=set)


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

        window.seen = moment
        if window.recorded < RECORDED_PER_WINDOW and _budget.written < GLOBAL_ROWS_PER_WINDOW:
            window.recorded += 1
            _budget.written += 1
            return Decision(record=True, collapsed=collapsed, flood=flood)
        if window.recorded < RECORDED_PER_WINDOW:
            # Inside this address's own allowance but past the global budget. Counted
            # globally rather than against the address, because the address is not the
            # thing being bounded here: the log is.
            _budget.refusals_over += 1
            _budget.addresses_over.add(address)
            return Decision(record=False, collapsed=collapsed, flood=flood)
        window.suppressed += 1
        return Decision(record=False, collapsed=collapsed, flood=flood)


def _roll_budget(moment: float) -> Flood | None:
    """Start a new global window when the current one has expired, returning its overflow.

    Called under the lock. The overflow is handed back rather than dropped, for the same
    reason a per-address count is: a bound that loses what it bounded records nothing.
    """
    if _budget.started is not None and moment - _budget.started < WINDOW_SECONDS:
        return None
    over = (
        Flood(_budget.refusals_over, len(_budget.addresses_over)) if _budget.refusals_over else None
    )
    _budget.started = moment
    _budget.written = 0
    _budget.refusals_over = 0
    _budget.addresses_over = set()
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
