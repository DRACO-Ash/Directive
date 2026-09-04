"""The register API: read the registers, create and update records, verify the log.

Every mutating route is gated by `auth.required` and carries a cross-site request forgery
token. Every mutation goes through `records.mutate`, which stages the register, writes the
chained audit entry, then commits, so there is no path from a request to a stored record
that skips the log.
"""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, request
from werkzeug.wrappers.response import Response

from .. import auth, csrf, records, store
from ..audit import AuditFieldError, ChainVerdict, verify_log
from ..audit.anchor import (
    AnchorError,
    AnchorRollbackError,
    AnchorTamperError,
    read_anchor,
)
from ..audit.journal import JournalChain, JournalError, read_entries
from ..audit.keys import AuditKeyError
from ..audit.validation import recordable
from ..records import RecordError
from ..store import StoreError

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
    return recordable("source_ip", request.remote_addr or "unknown")


def _user_agent() -> str:
    """Return the caller's user agent, or a marker if it cannot be recorded.

    A caller must never be able to veto their own audit entry by choosing a header the
    audit boundary refuses. See `complyops.audit.validation.recordable`.
    """
    return recordable("user_agent", request.headers.get("User-Agent") or "unknown")


@api_bp.errorhandler(RecordError)
def _record_error(error: RecordError) -> tuple[Response, int]:
    """Return a validation failure as a client error.

    The message is the boundary rule that was broken, which is safe to show: it describes
    the caller's own input, never another record's content and never anything server-side.
    """
    return jsonify({"error": str(error)}), 400


#: What a caller is told when the volume is at fault. Deliberately fixed and uninformative:
#: the real message carries an absolute path and an OS error string, which is server-side
#: detail and belongs in the log, not in a response body. The operator reads the detail on
#: /api/diagnostics, which is authenticated.
VOLUME_FAULT = "the change was not made: the audit log is unavailable. See /api/diagnostics."


@api_bp.errorhandler(JournalError)
def _journal_error(error: JournalError) -> tuple[Response, int]:
    """Return a failure to persist the log as a server fault, because it is one.

    503 rather than 500: the change was refused because the evidence could not be written,
    the register is untouched, and retrying after an operator fixes the volume is the right
    response.
    """
    current_app.logger.error("audit log unavailable: %s", error)
    return jsonify({"error": VOLUME_FAULT}), 503


@api_bp.errorhandler(AnchorError)
def _anchor_error(error: AnchorError) -> tuple[Response, int]:
    """Return an unusable anchor as a server fault rather than an unhandled 500.

    `/api/export` reads the anchor from the volume, so a corrupt or rolled-back one used to
    escape as a traceback page. That is the wrong status and the wrong disclosure, and it
    broke the export at exactly the moment tampering had been detected, which is the moment
    the pack matters most.
    """
    current_app.logger.error("the stored anchor is unusable: %s", error)
    return jsonify({"error": "the audit anchor is unusable. See /api/diagnostics."}), 503


@api_bp.errorhandler(StoreError)
def _store_error(error: StoreError) -> tuple[Response, int]:
    """Return a register that could not be read or written as a server fault.

    Without this a full volume escapes as an unhandled 500 carrying a traceback, which is
    both the wrong status and the wrong disclosure.
    """
    current_app.logger.error("register unavailable: %s", error)
    return jsonify({"error": "the register is unavailable. See /api/diagnostics."}), 503


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
    """Create one record. The register is staged, the entry written, then committed."""
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
    """Update one record. The register is staged, the entry written, then committed."""
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
    try:
        keys = verification_keys() or {chain.signing_key_id: chain.signing_key}
    except AuditKeyError:
        # A verdict, never an exception. `key_unavailable` exists for exactly a mistyped
        # retired key, and reporting it as anything else would be a false tamper alarm.
        current_app.logger.exception("verification could not assemble the key set")
        return jsonify(
            {
                "ok": False,
                "tampered": False,
                "invalidUnderCurrentRules": False,
                "keyUnavailable": True,
                "anchorUnusable": False,
                "checked": 0,
                "summary": "a configured verification key could not be read",
                "note": "AUDIT_RETIRED_KEYS could not be read. See /api/diagnostics.",
            }
        )
    verdict, note = _verify_the_volume(chain, keys)
    return jsonify(
        {
            "ok": verdict.ok,
            "tampered": verdict.tampered,
            "invalidUnderCurrentRules": verdict.invalid_under_current_rules,
            "keyUnavailable": verdict.key_unavailable,
            "anchorUnusable": verdict.anchor_unusable,
            "checked": verdict.checked,
            "summary": verdict.summary(),
            "note": note,
        }
    )


def _verify_the_volume(chain: JournalChain, keys: dict[str, bytes]) -> tuple[ChainVerdict, str]:
    """Verify what is ON THE VOLUME, and confirm this process agrees with it.

    Reading the process's own entries and its own anchor was worse than useless: both come
    from the same memory, so the check passed while the file on disk was truncated to one
    line and the anchor was deleted. A control that cannot fail on an attacker-reachable
    input is not a control. Everything here is re-read from the volume.

    The in-memory head is then compared to the stored one, because a volume that verifies
    against a stale anchor while this process holds a longer chain is also a finding.
    """
    directory = _data_dir()
    try:
        entries = read_entries(directory)
    except JournalError:
        current_app.logger.exception("verification could not read the log")
        return ChainVerdict(ok=False, checked=0, reason="the log could not be read"), (
            "The audit log on the volume could not be read. See /api/diagnostics."
        )
    try:
        anchor = read_anchor(directory, chain.signing_key)
    except AnchorTamperError as error:
        # The anchor's STATE says interference: a genuine older anchor put back, an anchor
        # signed by a key this server does not hold, or an anchor deleted beside a marker
        # that survived. None of those happens by accident, and the last is the AUD-001
        # delete control's own signal. Reporting them as a fault to diagnose turned a true
        # positive into an all-clear on the read-out an assessor is shown.
        current_app.logger.exception("verification refused the stored anchor")
        # A FIXED reason per class, never the exception's own text: that carries the
        # anchor's absolute path, and the summary reaches an operator banner and an audit
        # record. The detail is in the log above.
        reason = (
            "an older anchor was restored"
            if isinstance(error, AnchorRollbackError)
            else "the anchor is not authenticated under the current key, or was removed"
        )
        return ChainVerdict(ok=False, checked=len(entries), reason=reason), (
            "The anchor on the volume shows interference. See /api/diagnostics."
        )
    except AnchorError:
        # An I/O error, a parse failure, an implausible size or an unreadable field. A fault
        # to diagnose, reported as its own class rather than as a tightened field rule,
        # which is a statement about an ENTRY and would be false here.
        current_app.logger.exception("verification could not read the stored anchor")
        return ChainVerdict(
            ok=False,
            checked=len(entries),
            anchor_unusable=True,
            reason="the anchor file could not be read",
        ), "The anchor on the volume could not be read. See /api/diagnostics."

    if anchor is None:
        return ChainVerdict(
            ok=False, checked=len(entries), reason="this volume holds no anchor"
        ), "The volume holds no anchor, so nothing can be verified against it."

    verdict = verify_log(entries, keys, anchor)
    if verdict.ok and anchor.head != chain.anchor().head:
        return ChainVerdict(
            ok=False,
            checked=len(entries),
            reason="the stored log does not match the chain this process is appending to",
        ), "The volume verifies against its own anchor but disagrees with this process."
    return verdict, "Verified against the log and anchor read from the volume."


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
    stored_anchor = read_anchor(directory, chain.signing_key)
    pack = {
        "exported": records.now(),
        "exportedBy": auth.audit_actor(),
        "registers": dict(store.iter_registers(directory)),
        # Read from the VOLUME, not from this process's memory. The pack is the off-volume
        # corroboration the anchor's blind spot rests on, so a pack assembled from memory
        # would corroborate the volume against nothing at all.
        "auditEntries": [entry.__dict__ for entry in read_entries(directory)],
        "auditAnchor": stored_anchor.__dict__ if stored_anchor else None,
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


__all__ = ["api_bp"]
