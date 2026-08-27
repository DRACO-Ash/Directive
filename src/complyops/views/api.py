"""The register API: read the registers, create and update records, verify the log.

Every mutating route is gated by `auth.required` and carries a cross-site request forgery
token. Every mutation goes through `records.mutate`, which writes the chained audit entry
before the register is touched, so there is no path from a request to a stored record that
skips the log.
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request
from werkzeug.wrappers.response import Response

from .. import auth, csrf, records, store
from ..audit import AuditFieldError, verify_log, verify_sample
from ..audit.journal import JournalChain, JournalError
from ..records import RecordError

api_bp = Blueprint("api", __name__, url_prefix="/api")

#: How many audit entries the read-out returns by default, and the most it will ever
#: return in one response. A log held for 24 months does not belong in one payload.
DEFAULT_AUDIT_PAGE = 200
MAXIMUM_AUDIT_PAGE = 2000


def _data_dir() -> str:
    """Return the configured data directory."""
    return str(current_app.config["COMPLYOPS_DATA_DIR"])


def _chain() -> JournalChain:
    """Return the process's audit chain, or raise if the audit path is unavailable."""
    chain = current_app.extensions.get("complyops_chain")
    if chain is None:
        # Fail closed: without a chain no mutation can be evidenced, and a change that
        # cannot be evidenced must not happen. A JournalError rather than a RecordError so
        # this answers 503: the caller's input is fine and the volume or the key is not.
        raise JournalError(
            "the audit chain is unavailable, so nothing can be read or changed. The reason "
            "is on /api/diagnostics under auditLog."
        )
    return chain  # type: ignore[no-any-return]


def _client_ip() -> str:
    """Return the caller's address, from the connection rather than a header."""
    return (request.remote_addr or "unknown")[:45]


def _user_agent() -> str:
    """Return the caller's user agent, capped to the audit field's limit."""
    return (request.headers.get("User-Agent") or "unknown")[:512]


@api_bp.errorhandler(RecordError)
def _record_error(error: RecordError) -> tuple[Response, int]:
    """Return a validation failure as a client error.

    The message is the boundary rule that was broken, which is safe to show: it describes
    the caller's own input, never another record's content and never anything server-side.
    """
    return jsonify({"error": str(error)}), 400


@api_bp.errorhandler(JournalError)
def _journal_error(error: JournalError) -> tuple[Response, int]:
    """Return a failure to persist the log as a server fault, because it is one.

    503 rather than 500: the change was refused because the evidence could not be written,
    the register is untouched, and retrying after an operator fixes the volume is the right
    response. The message names the volume fault, never a key or a record.
    """
    current_app.logger.error("audit log unavailable: %s", error)
    return jsonify({"error": f"the change was not made: {error}"}), 503


@api_bp.errorhandler(AuditFieldError)
def _audit_error(error: AuditFieldError) -> tuple[Response, int]:
    """Return an audit rejection as a client error, because the caller's input caused it."""
    return jsonify({"error": f"the change was refused by the audit boundary: {error}"}), 400


@api_bp.get("/registers")
@auth.required
def list_registers() -> Response:
    """Return every register's records and the dashboard counts."""
    directory = _data_dir()
    return jsonify(
        {
            "registers": {name: records.read(directory, name) for name in records.REGISTERS},
            "counts": records.counts(directory),
            "states": {name: spec["states"] for name, spec in records.REGISTERS.items()},
            "actor": auth.current_actor(),
            "actorVerified": auth.actor_is_verified(),
        }
    )


@api_bp.get("/registers/<register>")
@auth.required
def list_records(register: str) -> Response:
    """Return one register's records."""
    return jsonify({"records": records.read(_data_dir(), register)})


@api_bp.post("/registers/<register>")
@auth.required
@csrf.required
def create_record(register: str) -> tuple[Response, int]:
    """Create one record, writing its audit entry first."""
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        raise RecordError("the request body must be an object")
    record = records.mutate(
        data_dir=_data_dir(),
        chain=_chain(),
        register=register,
        action=f"{records.REGISTERS[register]['prefix']}_CREATED"
        if register in records.REGISTERS
        else "RECORD_CREATED",
        actor=auth.audit_actor(),
        fields=payload,
        source_ip=_client_ip(),
        user_agent=_user_agent(),
    )
    return jsonify({"record": record}), 201


@api_bp.patch("/registers/<register>/<record_id>")
@auth.required
@csrf.required
def update_record(register: str, record_id: str) -> Response:
    """Update one record, writing its audit entry first."""
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        raise RecordError("the request body must be an object")
    record = records.mutate(
        data_dir=_data_dir(),
        chain=_chain(),
        register=register,
        action=f"{records.REGISTERS[register]['prefix']}_UPDATED"
        if register in records.REGISTERS
        else "RECORD_UPDATED",
        actor=auth.audit_actor(),
        record_id=record_id,
        fields=payload,
        source_ip=_client_ip(),
        user_agent=_user_agent(),
    )
    return jsonify({"record": record})


@api_bp.get("/audit")
@auth.required
def audit_log() -> Response:
    """Return the active audit log, newest first, with the anchor it must end on.

    Read from the volume at boot and appended to as the process runs, so this is the whole
    active log rather than what one process happened to write. `pageOf` names the slice
    returned, because a log approaching its 24-month retention is longer than a screen.
    """
    chain = _chain()
    entries = chain.entries
    limit = min(
        max(request.args.get("limit", type=int) or DEFAULT_AUDIT_PAGE, 1), MAXIMUM_AUDIT_PAGE
    )
    return jsonify(
        {
            "entries": [entry.__dict__ for entry in reversed(entries[-limit:])],
            "pageOf": len(entries),
            "anchor": chain.anchor().__dict__,
        }
    )


@api_bp.post("/audit/verify")
@auth.required
@csrf.required
def verify() -> Response:
    """Verify the audit chain, and report a configuration fault as one.

    Uses `verify_log` against the live anchor, which is the only form that can detect a
    truncation. `verify_sample` exists for a mid-log run and cannot, by construction.
    """
    from ..audit import verification_keys  # noqa: PLC0415 - read at call time

    chain = _chain()
    keys = verification_keys() or {chain.signing_key_id: chain.signing_key}
    verdict = verify_log(chain.entries, keys, chain.anchor())
    return jsonify(
        {
            "ok": verdict.ok,
            "tampered": verdict.tampered,
            "invalidUnderCurrentRules": verdict.invalid_under_current_rules,
            "keyUnavailable": verdict.key_unavailable,
            "checked": verdict.checked,
            "summary": verdict.summary(),
        }
    )


@api_bp.get("/export")
@auth.required
def export() -> Response:
    """Export every register and the audit anchor as one standalone evidence pack.

    This is the file the Information Security Manager uploads to SharePoint by hand, and it
    is a security control rather than housekeeping: between exports the volume holds the
    only copy of the log and its anchor, so the pack is the off-volume corroboration the
    anchor's blind spot needs. It therefore carries the anchor, not just the records.
    """
    directory = _data_dir()
    chain = _chain()
    pack = {
        "exported": records.now(),
        "exportedBy": auth.audit_actor(),
        "registers": dict(store.iter_registers(directory)),
        "auditEntries": [entry.__dict__ for entry in chain.entries],
        "auditAnchor": chain.anchor().__dict__,
        "note": (
            "Keep the anchor with this pack. A pack without it proves the entries were "
            "internally consistent and nothing about whether any were removed."
        ),
    }
    response = jsonify(pack)
    response.headers["Content-Disposition"] = (
        f'attachment; filename="comply-ops-evidence-{records.now()[:10]}.json"'
    )
    return response


__all__ = ["api_bp", "verify_sample"]
