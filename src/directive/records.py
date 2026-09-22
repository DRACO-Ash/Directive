"""The registers, and the one path by which any of them changes.

Every mutation goes through :func:`mutate`, which writes one chained audit entry per
AUD-001 and refuses the change if the entry cannot be written. The ordering is stage, sign,
commit: the register's new contents go to a temporary file first, the audit entry is derived
and validated second, and the staged file is renamed into place only on a clean exit. So a
record change that could not be evidenced never reaches the register, and the realistic
failures (space, permissions, serialisation) happen with nothing yet recorded. It is what
makes the log an account of what the application did rather than a best-effort side note.

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
from datetime import UTC, date, datetime
from typing import Any, Protocol

from . import store
from .audit import AuditEntry

#: Task status, from the v1 prototype's own values.
TASK_STATES = ("OPEN", "PENDING", "DONE")

#: Incident phase. AUD-001 requires the phase change to be recorded with a before and after.
INCIDENT_STATES = ("TRIAGE", "INVESTIGATING", "CONTAINED", "CLOSED")

#: Risk treatment progress, from the prototype's `On Track`, `At Risk`, `Planned`.
RISK_STATES = ("PLANNED", "ON_TRACK", "AT_RISK", "ACCEPTED", "CLOSED")

#: Transfer agreement lifecycle. An International Data Transfer Agreement (IDTA) is the
#: instrument, so its states are the instrument's, not a workflow's.
AGREEMENT_STATES = ("DRAFT", "IN_FORCE", "SUPERSEDED", "TERMINATED")

#: Transfer Risk Assessment (TRA) progress. `REVIEW_DUE` is a real state rather than a
#: derived one: an assessment whose review date has passed is not the same as one that was
#: never approved, and an assessor will ask which it is.
TRANSFER_STATES = ("DRAFT", "ASSESSED", "APPROVED", "REJECTED", "REVIEW_DUE")

#: How severe, on one scale, everywhere. A closed vocabulary for the same reason the state
#: vocabularies are closed: a severity that drifts into free text cannot be counted, sorted
#: or evidenced.
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

#: What the party receiving the data is, in UK GDPR terms. The distinction is not
#: bookkeeping: a SUB_PROCESSOR carries obligations a CONTROLLER does not, because the
#: processor that engaged it stays fully liable for it to the controller, and the controller
#: has to have authorised it in the first place.
IMPORTER_ROLES = ("CONTROLLER", "PROCESSOR", "SUB_PROCESSOR")

#: Whether the controller has authorised this sub-processor, and how. UK GDPR Article 28(2)
#: is the reason this is a field rather than an assumption: a processor may not engage
#: another processor without the controller's prior authorisation, which is either specific
#: to this sub-processor or general with a right to object. `NOT_OBTAINED` is a real and
#: recordable state, because the honest answer is sometimes that it has not been obtained
#: yet, and an assessment that cannot say so is worth less than one that can.
AUTHORISATIONS = ("SPECIFIC", "GENERAL", "NOT_OBTAINED", "NOT_APPLICABLE")

#: A field's KIND decides how it is validated. Until this existed every field was text with
#: a length cap, which is why the application could hold a compliance operating rhythm with
#: no concept of when anything was due.
#:
#: ``LINK`` is the interesting one. It names another register, and it is what turns
#: `reference`, which was 64 characters of free text, into an actual relationship. The
#: FORMAT is checked here; the EXISTENCE of the target is checked in :func:`mutate`, where
#: the data directory is already open. Keeping the two apart leaves this function pure.
TEXT, DATE, CHOICE, LINK = "text", "date", "choice", "link"

#: Every field this application understands, and how. A register declares which of these it
#: accepts, so a task cannot carry a transfer agreement and an assessment cannot carry a due
#: date it would never be read from.
FIELD_KINDS: dict[str, tuple[str, Any]] = {
    "title": (TEXT, None),
    "summary": (TEXT, None),
    "owner": (TEXT, None),
    "reference": (TEXT, None),
    "notes": (TEXT, None),
    "category": (TEXT, None),
    "due": (DATE, None),
    "review_by": (DATE, None),
    "severity": (CHOICE, SEVERITIES),
    "agreement": (LINK, "agreements"),
    "controller": (TEXT, None),
    "exporter": (TEXT, None),
    "importer": (TEXT, None),
    "importer_role": (CHOICE, IMPORTER_ROLES),
    "contract": (TEXT, None),
    "data_categories": (TEXT, None),
    "destination": (TEXT, None),
    "authorisation": (CHOICE, AUTHORISATIONS),
    "safeguards": (TEXT, None),
}

#: A state a register may not enter while one of its fields is unset or holds a named value.
#:
#: This is the first rule in the application that reasons about a record as a WHOLE rather
#: than field by field, and it exists because the Article 28(2) authorisation is exactly the
#: thing a one-person function misses under time pressure. A transfer risk assessment that
#: reaches APPROVED without recording whether the controller authorised the sub-processor
#: is an assessment that has skipped the question, and the application should not let it.
#: Declared here rather than written into a function, so the next rule is a row.
BLOCKED_STATES: dict[str, tuple[tuple[str, str, tuple[str, ...], str], ...]] = {
    "transfers": (
        (
            "APPROVED",
            "authorisation",
            ("", "NOT_OBTAINED"),
            "UK GDPR Article 28(2): a processor may not engage a sub-processor without the "
            "controller's prior authorisation. Record it as SPECIFIC or GENERAL, or say why "
            "it does not apply, before approving this assessment.",
        ),
    ),
}

#: The fields every register carries.
COMMON_FIELDS = ("title", "summary", "owner", "reference", "notes", "category")

#: Above this cap a text field gets a textarea rather than a single line. Measured against
#: the cap rather than listed by name, so a new long field gets the right control for free.
TEXTAREA_ABOVE = 500

#: Which register uses which vocabulary, what an entry calls it, and which fields it holds.
REGISTERS: dict[str, dict[str, Any]] = {
    "tasks": {
        "states": TASK_STATES,
        "prefix": "TSK",
        "title": "Rhythm tasks",
        "fields": (*COMMON_FIELDS, "due"),
    },
    "incidents": {
        "states": INCIDENT_STATES,
        "prefix": "INC",
        "title": "Incidents",
        "fields": (*COMMON_FIELDS, "severity"),
    },
    "risks": {
        "states": RISK_STATES,
        "prefix": "RSK",
        "title": "Risk register",
        "fields": (*COMMON_FIELDS, "severity", "review_by"),
    },
    "agreements": {
        "states": AGREEMENT_STATES,
        "prefix": "IDTA",
        "title": "Transfer agreements",
        #: The parties and their ROLES, because the instrument is the customer's rather than
        #: this company's. The chain that matters runs controller, to exporter, to importer,
        #: and the importer's role decides which obligations attach.
        "fields": (
            *COMMON_FIELDS,
            "review_by",
            "controller",
            "exporter",
            "importer",
            "importer_role",
            "contract",
        ),
    },
    "transfers": {
        "states": TRANSFER_STATES,
        "prefix": "TRA",
        "title": "Transfer risk assessments",
        #: `agreement` is REQUIRED, not optional. A transfer risk assessment that does not
        #: name the instrument it assesses is the thing this register exists to stop: the
        #: assessment and the agreement drift apart and neither evidences the other.
        "fields": (
            *COMMON_FIELDS,
            "severity",
            "review_by",
            "agreement",
            "data_categories",
            "destination",
            "authorisation",
            "safeguards",
        ),
        "requires": ("agreement",),
    },
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
    "controller": 200,
    "exporter": 200,
    "importer": 200,
    "contract": 120,
    "data_categories": 500,
    "destination": 120,
    "safeguards": 2000,
}


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
    """Return the next identifier for a register, as PREFIX-0001.

    Matched against the prefix ACTUALLY IN PLAY, never a general identifier shape. The
    previous version tested every row against `[A-Z]{3}-[0-9]{4}`, which was true of `TSK`,
    `INC` and `RSK` and false of the four-character `IDTA`. So no existing agreement ever
    matched, `used` was always empty, and every record in that register was issued
    `IDTA-0001`.

    Three controls failed together, which is why this is matched on the prefix rather than
    patched to four letters. An audit entry's `resource_id` is what says which record an
    action touched, and it said the same thing for every one. `store.find` returns the first
    match, so records after the first could not be read or corrected through any route the
    application exposes. And a transfer assessment's link passed referential integrity
    against an identifier that named several different agreements, which is the drift the
    link exists to stop.
    """
    pattern = re.compile(rf"\A{re.escape(prefix)}-([0-9]{{4,}})\Z")
    used = [
        int(found.group(1))
        for row in rows
        if (found := pattern.match(str(row.get("id", "")))) is not None
    ]
    return f"{prefix}-{max(used, default=0) + 1:04d}"


def field_schema(register: str) -> list[dict[str, Any]]:
    """Describe a register's fields so the console can render them.

    The interface used to hardcode five inputs for every register, which is why a transfer
    risk assessment could not be created through it at all: `agreement` is required and no
    form offered it. The schema is derived from `REGISTERS` and `FIELD_KINDS` rather than
    restated, so a field added to a register appears in the console without a second edit.
    """
    if register not in REGISTERS:
        raise RecordError(f"{str(register)[:64]!r} is not a register")
    required = REGISTERS[register].get("requires", ())
    described: list[dict[str, Any]] = []
    for name in REGISTERS[register]["fields"]:
        kind, detail = FIELD_KINDS[name]
        field: dict[str, Any] = {
            "name": name,
            "kind": kind,
            #: The label is derived, never invented: the field name with its underscores
            #: opened out. `data_categories` reads "Data categories".
            "label": name.replace("_", " ").capitalize(),
            "required": name in required or name == "title",
        }
        if kind == CHOICE:
            field["choices"] = list(detail)
        if kind == LINK:
            field["target"] = detail
        if kind == TEXT:
            field["cap"] = FIELD_CAPS[name]
            #: The two long ones get a textarea. Measured against the caps rather than
            #: listed by name, so a new long field gets the right control for free.
            field["long"] = FIELD_CAPS[name] >= TEXTAREA_ABOVE
        described.append(field)
    return described


def check_fields(
    fields: Mapping[str, Any], *, register: str, complete: bool = True
) -> dict[str, Any]:
    """Validate a record's fields and return a clean copy, or raise :class:`RecordError`.

    ``complete`` is False for a partial update, where the caller sends only what changed.
    A state transition should not require resending the title, and requiring it would push
    callers towards read-modify-write round trips that lose concurrent edits.
    """
    if register not in REGISTERS:
        raise RecordError(f"{str(register)[:64]!r} is not a register")
    clean: dict[str, Any] = {}
    for name, value in fields.items():
        if name in {"id", "created", "updated"}:
            continue
        if name == "state":
            clean["state"] = check_state(value, register=register)
            continue
        if not isinstance(value, str):
            # Capped for the same reason the unknown-name echo below is, and reached
            # BEFORE the kind lookup: an unknown name carrying a non-string value never
            # gets as far as the schema, so the truncation has to happen here too.
            # `str(name)` because a JSON object key is not guaranteed to be text either.
            raise RecordError(f"{str(name)[:64]!r} must be text")
        if name not in REGISTERS[register]["fields"]:
            # The name is truncated before it is echoed. It is attacker-supplied and
            # unbounded, and a client error is not a mirror. Scoped to the REGISTER now
            # rather than to the whole application, so a field one register understands is
            # still refused by a register that would never read it.
            raise RecordError(f"{name[:64]!r} is not a field of the {register} register")
        clean[name] = check_value(name, value)
    #: A required field must be present on a CREATE, and must not be emptied by an UPDATE
    #: that names it. The second half was missing, so a partial update carrying a blank
    #: title returned 200 and stored an empty one: the requirement held only at the moment
    #: of creation and provided no protection afterwards. `agreement` survived by accident,
    #: because the link format rejects an empty string before this is reached.
    for required in ("title", *REGISTERS[register].get("requires", ())):
        article = "an" if required[0] in "aeiou" else "a"
        if complete and not clean.get(required):
            raise RecordError(f"every {register} record needs {article} {required}")
        if not complete and required in clean and not clean[required]:
            raise RecordError(f"{required!r} cannot be emptied once a record has one")
    if not clean:
        raise RecordError("nothing to change")
    return clean


def check_value(name: str, value: str) -> str:
    """Validate one field against its kind, or raise :class:`RecordError`.

    Every kind fails closed. A date that is not a calendar date, a choice outside its
    vocabulary and a link that is not shaped like a record identifier are all refused rather
    than stored and interpreted later.
    """
    kind, detail = FIELD_KINDS[name]
    value = value.strip()
    if kind == DATE:
        #: The CANONICAL form first, then the calendar check. `fromisoformat` alone is not
        #: the strict parser this comment used to claim: since Python 3.11 it accepts the
        #: whole ISO 8601 grammar, so `2026-W01-1`, `2026W011` and `20260101` were all
        #: ACCEPTED and silently rewritten to a different-looking date. `2026-W01-1` stored
        #: as `2025-12-29`, a year earlier than the operator typed.
        #:
        #: That broke the hard rule directly: a field is rejected at the boundary, never
        #: coerced. It was worse in combination with the no-op guard below, because setting
        #: a review date to a week form that happened to resolve to the stored value
        #: returned HTTP 200 and wrote no audit entry at all: the operator believed they had
        #: moved the date, nothing had moved, and no line recorded the attempt.
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value):
            raise RecordError(f"{name!r} must be a date as YYYY-MM-DD, not {value[:64]!r}")
        #: And `fromisoformat` IS strict about real calendar dates, which is what it is for
        #: here: it refuses the 31st of February rather than rolling it forward.
        try:
            parsed = date.fromisoformat(value)
        except ValueError:
            raise RecordError(
                f"{name!r} must be a date as YYYY-MM-DD, not {value[:64]!r}"
            ) from None
        return parsed.isoformat()
    if kind == CHOICE:
        if value not in detail:
            raise RecordError(f"{str(value)[:64]!r} is not a {name}. One of: {', '.join(detail)}")
        return value
    if kind == LINK:
        prefix = REGISTERS[detail]["prefix"]
        if not re.fullmatch(rf"{prefix}-\d{{4,}}", value):
            raise RecordError(
                f"{name!r} must name a {detail} record as {prefix}-0001, not {value[:64]!r}"
            )
        return value
    cap = FIELD_CAPS[name]
    if len(value) > cap:
        raise RecordError(f"{name!r} is {len(value)} characters, over its cap of {cap}")
    return value


def check_invariants(record: Mapping[str, Any], *, register: str) -> None:
    """Refuse a record whose fields are each valid and jointly wrong.

    Field validation cannot see this: `state` and `authorisation` are both individually
    legitimate values, and it is the combination that is not.
    """
    for state, field, blocked, why in BLOCKED_STATES.get(register, ()):
        if record.get("state") == state and str(record.get(field, "")) in blocked:
            raise RecordError(f"this record cannot be {state} yet. {why}")


def check_state(value: object, *, register: str) -> str:
    """Validate a workflow state against the register's closed vocabulary.

    A closed set, not a character rule, and bounded to the REGISTER routes. State the reach
    rather than the totality, because the previous two versions of this docstring each
    over-claimed in a different direction: first that record content was structurally
    impossible, which CLAUDE.md forbids by name, then that no route reaches `old_state` or
    `new_state` without passing through here, which a shipped route falsifies.

    Every register mutation reaches those fields through this function. The authentication
    and refusal path does not: `views/auth_routes.py` writes a collapsed-count marker
    (`REPEATED_<n>`) straight into `new_state`, under the audit boundary's character rule
    only, and that is deliberate because the marker is an event count rather than a
    register state. It is the one declared exception, and `test_audit_state_coverage.py`
    holds both halves. The audit boundary ITSELF still accepts any token satisfying its
    character rule, so a caller that bypassed this function would not be stopped there.
    """
    states = REGISTERS[register]["states"]
    if value not in states:
        #: Capped at 64 the way `check_fields` caps its field-name echo, and for the same
        #: reason it gives there: a client error is not a mirror. Uncapped, a 200,000
        #: character state came back verbatim in the 400 body, bounded only by the request
        #: cap two layers out.
        raise RecordError(
            f"{str(value)[:64]!r} is not a {register} state. One of: {', '.join(states)}"
        )
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

    The register's new contents are staged first, then the audit entry is built and signed,
    then the staged file is committed on a clean exit. Any failure at any step aborts the
    whole operation with the stored register untouched. A change that cannot be
    evidenced does not happen.

    Returns the stored record.
    """
    if register not in REGISTERS:
        raise RecordError(f"{str(register)[:64]!r} is not a register")
    clean = (
        check_fields(fields or {}, register=register, complete=record_id is None)
        if fields is not None
        else {}
    )

    #: Referential integrity, before the register is opened. A link whose target does not
    #: exist is refused rather than stored: an assessment naming an agreement nobody can
    #: find evidences nothing, and the dangling reference would only be discovered by the
    #: assessor who asked to see it. Checked here rather than in `check_fields` because this
    #: is where the data directory is, and that function stays pure.
    for name, value in clean.items():
        #: `state` rides in `clean` alongside the declared fields and is not one of them, so
        #: it is looked up defensively rather than indexed. Indexing it raised a KeyError
        #: that reached the client as a 500 on every state transition.
        kind, target = FIELD_KINDS.get(name, (TEXT, None))
        if kind == LINK and store.find(store.read(data_dir, target), value) is None:
            raise RecordError(f"there is no {target} record {value[:64]!r} to link to")

    holder = store.register(data_dir, register)
    with holder as rows:
        if record_id is None:
            record = _create(rows, clean, register=register)
            changed, before, after = sorted(clean), "", record.get("state", "")
        else:
            record, changed, before, after = _update(rows, record_id, clean, register=register)
            if not changed:
                # Nothing moved, so nothing is recorded. `_update` already reports an empty
                # change list for a no-op, and this function used to stage and append
                # anyway, so a double click on a state button or any repeated identical
                # PATCH wrote a permanent, signed, chained entry with an empty
                # `fields_changed` and no transition. An entry is immutable, so that noise
                # could never be removed from the evidence an assessor reads, and it
                # contradicted the one claim the whole audit design exists to support: that
                # every entry describes a change that actually happened.
                #
                # Returning here skips the stage and the append. The context manager still
                # exits cleanly and rewrites the identical rows, which is a wasted write and
                # not a wrong one.
                return record

        # Stage the register BEFORE the entry, commit it after. The serialisation, the disk
        # space and the flush all happen in the stage, so a full volume refuses the change
        # with nothing yet recorded; only the rename is left for the exit. That narrows the
        # window in which an immutable entry could describe a change that never landed, and
        # it does not close it: see `store.register` and `docs/DEPLOYMENT.md`.
        check_invariants(record, register=register)

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
        #: Both halves capped, for two different reasons, and the first version of this
        #: comment gave the wrong one for `register`. `record_id` IS an attacker-supplied
        #: path segment reaching here unfiltered, bounded only by gunicorn's request-line
        #: default, which nothing in this repository asserts and the Dockerfile does not
        #: set. `register` is not: `mutate` refuses anything outside `REGISTERS` before
        #: this function is reached, so by this line it is one of three literals. Its cap
        #: is defence in depth behind that guard, exactly as `check_fields`'s own register
        #: guard is, and saying so is owed to the sibling that got the honest treatment.
        raise RecordError(
            f"no record {str(record_id)[:64]!r} in the {str(register)[:64]!r} register"
        )

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
        raise RecordError(f"{str(register)[:64]!r} is not a register")
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
