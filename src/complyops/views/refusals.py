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

Three limits, stated because each was claimed away once already.

A flood spread across MANY source addresses still writes one entry per address per window.
At the tracker's cap that is about 4096 entries and 1.66 MiB per five-minute window, so the
64 MiB cap is roughly 3.2 hours away. Narrowing that needs a real rate limiter at the edge
or in front of the process, which is the deferred control in `docs/DEPLOYMENT.md`.

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
from dataclasses import dataclass

#: How many refusals from one source address are recorded individually per window.
RECORDED_PER_WINDOW = 3

#: The window, in seconds.
WINDOW_SECONDS = 300.0

#: The most source addresses tracked at once. Bounded so the tracker cannot itself be the
#: thing an attacker exhausts: without this, one entry per spoofed address is unbounded
#: memory. At the cap the least recently seen address is dropped, and its pending count is
#: reported to the caller so it still reaches the log rather than being lost silently.
MAXIMUM_TRACKED = 1024


@dataclass
class _Window:
    """One source address's refusal window."""

    started: float
    recorded: int = 0
    suppressed: int = 0
    seen: float = 0.0


_windows: dict[str, _Window] = {}
_guard = threading.Lock()


def reset() -> None:
    """Forget every tracked address. For tests and for a deliberate restart."""
    with _guard:
        _windows.clear()


@dataclass(frozen=True)
class Collapsed:
    """A count of refusals from one address that were not recorded individually."""

    address: str
    count: int


@dataclass(frozen=True)
class Decision:
    """What to write for one refusal."""

    record: bool
    #: Counts that closed or were evicted, each with the address it belongs to. Written as
    #: one summary entry apiece, so attribution survives the collapse.
    collapsed: tuple[Collapsed, ...] = ()


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

        window.seen = moment
        if window.recorded < RECORDED_PER_WINDOW:
            window.recorded += 1
            return Decision(record=True, collapsed=collapsed)
        window.suppressed += 1
        return Decision(record=False, collapsed=collapsed)


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
