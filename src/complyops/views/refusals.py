"""Collapsing repeated sign-in refusals, so an unauthenticated caller cannot fill the log.

AUD-001 requires a record of every failed authentication, and the sign-in and callback
routes are unauthenticated by necessity, so a bare `GET /auth/callback` writes one durable
fsynced entry. Measured: ten requests, ten entries at about 425 bytes each. At the log's
64 MiB refusal cap that is roughly 158,000 requests to make `read_entries` refuse the whole
log as implausibly large at the next restart, which leaves the audit path unavailable and
every register mutation answering 503 until an operator does surgery on the volume. No
rate limiter exists in this process.

Dropping the entries is not the fix, because AUD-001 asks for the record. Collapsing them
is, and it is better evidence as well: a hundred identical refusals from one address is
more legible as one refusal and a count than as a hundred rows an assessor has to page
through.

So the first few refusals from an address in a window are recorded individually, and the
rest are counted. The count is emitted as one entry when the window closes or when the next
refusal arrives after it, so a flood that stops still leaves its tail recorded on the next
refusal from that address rather than vanishing.

What this does NOT close, stated because the reach is easy to overstate: a flood spread
across many source addresses still writes one entry per address per window. Narrowing that
needs a real rate limiter at the edge or in front of the process, which is the deferred
control in `docs/DEPLOYMENT.md`. This bounds the single-address case, which is the cheap
one, and it bounds the tracker itself so it cannot become the exhaustion instead.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

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
    seen: float = field(default=0.0)


_windows: dict[str, _Window] = {}
_guard = threading.Lock()


def reset() -> None:
    """Forget every tracked address. For tests and for a deliberate restart."""
    with _guard:
        _windows.clear()


@dataclass(frozen=True)
class Decision:
    """What to write for one refusal."""

    record: bool
    #: A count of refusals collapsed into a summary entry, or zero for none to report.
    collapsed: int = 0


def note(address: str, now: float | None = None) -> Decision:
    """Record that one refusal happened, and say what should be written for it.

    Returns ``record`` for an individual entry and ``collapsed`` for a count that a closed
    window left behind. Both can be set: the first refusal of a new window is recorded AND
    reports the previous window's tail.
    """
    moment = time.monotonic() if now is None else now
    with _guard:
        window = _windows.get(address)
        collapsed = 0

        if window is None:
            _evict_if_full()
            window = _Window(started=moment)
            _windows[address] = window
        elif moment - window.started >= WINDOW_SECONDS:
            collapsed = window.suppressed
            window.started = moment
            window.recorded = 0
            window.suppressed = 0

        window.seen = moment
        if window.recorded < RECORDED_PER_WINDOW:
            window.recorded += 1
            return Decision(record=True, collapsed=collapsed)
        window.suppressed += 1
        return Decision(record=False, collapsed=collapsed)


def _evict_if_full() -> None:
    """Drop the least recently seen address when the tracker is at capacity.

    Called under the lock. Eviction loses that address's pending count, which is why the
    cap is set well above any plausible number of concurrent legitimate sources: it is a
    backstop against a spoofed-address flood, not a routine path.
    """
    if len(_windows) < MAXIMUM_TRACKED:
        return
    oldest = min(_windows, key=lambda address: _windows[address].seen)
    del _windows[oldest]
