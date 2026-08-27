"""The registers, and the one path by which any of them changes.

Every mutation goes through :func:`mutate`, which writes one chained audit entry per
AUD-001 and refuses the change if the entry cannot be written. That ordering is the point:
the audit entry is derived and validated BEFORE the register is touched, so a record change
that could not be evidenced never happens at all. It is what makes the log an account of
what the application did rather than a best-effort side note.

The state vocabularies below are the closed sets the audit module has been waiting for.
Until now `old_state` and `new_state` were held to a character rule that rejects the common
shapes of record content without making it impossible; a closed vocabulary is the
structural version of that control, and it becomes definable at exactly this point, because
this is where the real states are decided. Values are taken from the v1 prototype where it
had them (`open`, `pending`, `closed`, `done`, `On Track`, `At Risk`, `Planned`) and are
otherwise the minimum the journeys need. TBC, re-verify the full vocabulary with the ISM.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, Protocol

from . import store
from .audit import AuditEntry

#: Task status, from the v1 prototype's own values.
TASK_STATES = ("OPEN", "PENDING", "DONE")

#: Incident phase. AUD-001 requires the phase change to be recorded with a before and after.
INCIDENT_STATES = ("TRIAGE", "INVESTIGATING", "CONTAINED", "CLOSED")

#: Risk treatment progress, from the prototype's `On Track`, `At Risk`, `Planned`.
RISK_STATES = ("PLANNED", "ON_TRACK", "AT_RISK", "ACCEPTED", "CLOSED")

#: Which register uses which vocabulary, and what an entry calls it.
REGISTERS: dict[str, dict[str, Any]] = {
    "tasks": {"states": TASK_STATES, "prefix": "TSK", "title": "Rhythm tasks"},
    "incidents": {"states": INCIDENT_STATES, "prefix": "INC", "title": "Incidents"},
    "risks": {"states": RISK_STATES, "prefix": "RSK", "title": "Risk register"},
}

#: Free-text fields are capped here as well as in the audit boundary, because a record is
#: not an audit entry and the two have different jobs. A record can be corrected; an entry
#: cannot.
FIELD_CAPS: dict[str, int] = {
    "title": 200,
    "summary": 2000,
    "owner": 120,
    "reference": 64,
    "notes": 4000,
    "category": 64,
}

_ID = re.compile(r"\A[A-Z]{3}-[0-9]{4}\Z")


class AppendsAudit(Protocol):
    """Whatever this module writes its entries through.

    A protocol rather than the concrete chain, because this module's requirement is
    exactly one method and nothing else. It lets the persistent chain, the in-memory one
    and a test double satisfy the same contract without this module knowing which is in
    front of it, and it keeps the ordering rule in :func:`mutate` independent of where the
    entry ends up.
    """

    def append(self, entry_fields: Mapping[str, object]) -> AuditEntry:
        """Validate, sign and record one entry, raising if it cannot be recorded."""
        ...


class RecordError(ValueError):
    """Raised when a record is not fit to store. Rejected at the boundary, never coerced."""


def now() -> str:
    """Return the current time as RFC 3339 in UTC, which the audit boundary requires."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def next_id(rows: list[dict[str, Any]], prefix: str) -> str:
    """Return the next identifier for a register, as PREFIX-0001."""
    used = [int(row["id"].split("-")[1]) for row in rows if _ID.match(str(row.get("id", "")))]
    return f"{prefix}-{max(used, default=0) + 1:04d}"


def check_fields(
    fields: Mapping[str, Any], *, register: str, complete: bool = True
) -> dict[str, Any]:
    """Validate a record's fields and return a clean copy, or raise :class:`RecordError`.

    ``complete`` is False for a partial update, where the caller sends only what changed.
    A state transition should not require resending the title, and requiring it would push
    callers towards read-modify-write round trips that lose concurrent edits.
    """
    if register not in REGISTERS:
        raise RecordError(f"{register!r} is not a register")
    clean: dict[str, Any] = {}
    for name, value in fields.items():
        if name in {"id", "created", "updated"}:
            continue
        if name == "state":
            clean["state"] = check_state(value, register=register)
            continue
        if not isinstance(value, str):
            raise RecordError(f"{name!r} must be text")
        cap = FIELD_CAPS.get(name)
        if cap is None:
            # The name is truncated before it is echoed. It is attacker-supplied and
            # unbounded, and a client error is not a mirror.
            raise RecordError(f"{name[:64]!r} is not a field of the {register} register")
        if len(value) > cap:
            raise RecordError(f"{name!r} is {len(value)} characters, over its cap of {cap}")
        clean[name] = value.strip()
    if complete and not clean.get("title"):
        raise RecordError("every record needs a title")
    if not clean:
        raise RecordError("nothing to change")
    return clean


def check_state(value: object, *, register: str) -> str:
    """Validate a workflow state against the register's closed vocabulary.

    A closed set, not a character rule. This is the structural control the audit module
    could not define on its own: a value outside this list cannot reach `old_state` or
    `new_state`, so record content cannot ride into an immutable log in a state field
    whatever a caller intends.
    """
    states = REGISTERS[register]["states"]
    if value not in states:
        raise RecordError(f"{value!r} is not a {register} state. One of: {', '.join(states)}")
    return str(value)


def mutate(  # noqa: PLR0913 - each argument is a distinct part of one audit entry
    *,
    data_dir: str,
    chain: AppendsAudit,
    register: str,
    action: str,
    actor: str,
    record_id: str | None = None,
    fields: Mapping[str, Any] | None = None,
    source_ip: str = "",
    user_agent: str = "",
) -> dict[str, Any]:
    """Create or update one record, writing its audit entry first.

    The audit entry is built and signed BEFORE the register is written, and any failure to
    do so aborts the whole operation with the register untouched. A change that cannot be
    evidenced does not happen.

    Returns the stored record.
    """
    if register not in REGISTERS:
        raise RecordError(f"{register!r} is not a register")
    clean = (
        check_fields(fields or {}, register=register, complete=record_id is None)
        if fields is not None
        else {}
    )

    holder = store.register(data_dir, register)
    with holder as rows:
        if record_id is None:
            record = _create(rows, clean, register=register)
            changed, before, after = sorted(clean), "", record.get("state", "")
        else:
            record, changed, before, after = _update(rows, record_id, clean, register=register)

        # Stage the register BEFORE the entry, commit it after. The serialisation, the disk
        # space and the flush all happen in the stage, so a full volume refuses the change
        # with nothing yet recorded; only the rename is left for the exit. That narrows the
        # window in which an immutable entry could describe a change that never landed, and
        # it does not close it: see `store.register` and `docs/DEPLOYMENT.md`.
        holder.stage()

        # The audit entry, before the register is committed. `store.register` commits on a
        # clean exit only, so a rejected entry leaves the register exactly as it was.
        chain.append(
            {
                "timestamp": now(),
                "actor": actor,
                "action": action,
                "resource": register,
                "resource_id": record["id"],
                "outcome": "SUCCESS",
                "source_ip": source_ip,
                "user_agent": user_agent,
                # Field NAMES only. The values never enter the log: an entry is immutable,
                # so no correction and no Article 17 erasure can reach it.
                "fields_changed": ",".join(changed),
                "old_state": before,
                "new_state": after,
            }
        )
    return record


def _create(rows: list[dict[str, Any]], clean: dict[str, Any], *, register: str) -> dict[str, Any]:
    """Append a new record to a register's rows."""
    stamp = now()
    record: dict[str, Any] = {
        "id": next_id(rows, REGISTERS[register]["prefix"]),
        "created": stamp,
        "updated": stamp,
        "state": clean.get("state", REGISTERS[register]["states"][0]),
        **clean,
    }
    rows.append(record)
    return record


def _update(
    rows: list[dict[str, Any]], record_id: str, clean: dict[str, Any], *, register: str
) -> tuple[dict[str, Any], list[str], str, str]:
    """Apply a change to an existing record, returning it and what changed."""
    record = store.find(rows, record_id)
    if record is None:
        raise RecordError(f"no record {record_id!r} in the {register} register")

    changed = sorted(name for name, value in clean.items() if record.get(name) != value)
    if not changed:
        # Nothing moved, so nothing is reported as having moved. Returning the current state
        # as both before and after wrote "OPEN to OPEN" into an immutable entry and the
        # console rendered it as a transition, which contradicts the rule six lines below.
        return record, [], "", ""

    before = str(record.get("state", ""))
    record.update(clean)
    record["updated"] = now()
    after = str(record.get("state", ""))
    # A state field is only reported as a transition when it actually moved, so an
    # unrelated edit does not claim one.
    return record, changed, (before if before != after else ""), (after if before != after else "")


def read(data_dir: str, register: str) -> list[dict[str, Any]]:
    """Return every record in one register, newest first."""
    if register not in REGISTERS:
        raise RecordError(f"{register!r} is not a register")
    rows = store.read(data_dir, register)
    return sorted(rows, key=lambda row: str(row.get("updated", "")), reverse=True)


def counts(data_dir: str) -> dict[str, dict[str, int]]:
    """Return a per-register count by state, for the dashboard."""
    summary: dict[str, dict[str, int]] = {}
    for name, spec in REGISTERS.items():
        rows = store.read(data_dir, name)
        summary[name] = dict.fromkeys(spec["states"], 0)
        summary[name]["total"] = len(rows)
        for row in rows:
            state = str(row.get("state", ""))
            if state in summary[name]:
                summary[name][state] += 1
    return summary
