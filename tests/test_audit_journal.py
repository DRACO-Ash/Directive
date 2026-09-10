"""The persistent audit log: what survives a restart, and what refuses to.

The point of these tests is the second half. Persisting entries is easy; the value is that
a volume whose state cannot be reconciled leaves the audit path unavailable rather than
quietly starting a fresh chain, because a fresh chain is how evidence disappears without an
alarm. Every refusal below is asserted as a refusal, not as a fallback.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from complyops.audit import Anchor, AuditChain, read_anchor, write_anchor
from complyops.audit import journal as journal_module
from complyops.audit.anchor import anchor_path, marker_path
from complyops.audit.journal import (
    JournalChain,
    JournalError,
    append_entry,
    log_path,
    read_entries,
    resume,
)

#: Real key material, published here on purpose: it is not a credential.
KEY = bytes(range(32))
OTHER_KEY = bytes(range(32, 64))
KEYS = {"k1": KEY}


def fields(number: int, *, actor: str = "ash.higgins@bluestaq.uk") -> dict[str, str]:
    """Return one well-formed entry's fields."""
    return {
        "timestamp": f"2026-08-27T09:{number:02d}:00Z",
        "actor": actor,
        "action": "TSK_CREATED",
        "resource": "tasks",
        "resource_id": f"TSK-{number:04d}",
        "outcome": "SUCCESS",
        "source_ip": "10.0.0.1",
        "user_agent": "pytest",
        "fields_changed": "title",
        "old_state": "",
        "new_state": "OPEN",
    }


def opened(data_dir: Path) -> JournalChain:
    """Return a chain resumed from this volume, raising if it cannot be."""
    chain, _ = resume(str(data_dir), key=KEY, key_id="k1", keys=KEYS)
    return chain


def written(data_dir: Path, count: int) -> JournalChain:
    """Return a chain holding ``count`` entries on this volume."""
    chain = opened(data_dir)
    for number in range(1, count + 1):
        chain.append(fields(number))
    return chain


# ============================ the ordinary path ============================


def test_a_fresh_volume_starts_an_empty_chain_that_verifies(tmp_path: Path) -> None:
    """A genuinely fresh install is the only case that legitimately starts from genesis."""
    chain, verdict = resume(str(tmp_path), key=KEY, key_id="k1", keys=KEYS)
    assert verdict.ok
    assert chain.entries == []
    assert chain.anchor().length == 0


def test_an_entry_is_on_the_volume_before_append_returns(tmp_path: Path) -> None:
    """Not on process exit and not on a flush timer. AUD-001 retains for 24 months."""
    chain = opened(tmp_path)
    chain.append(fields(1))
    assert len(read_entries(str(tmp_path))) == 1


def test_the_anchor_advances_with_every_append(tmp_path: Path) -> None:
    """Nothing wrote the anchor before this module, so it could never detect anything."""
    chain = written(tmp_path, 3)
    stored = read_anchor(str(tmp_path), KEY)
    assert stored is not None
    assert stored.length == 3
    assert stored.head == chain.anchor().head


def test_the_chain_continues_across_a_restart(tmp_path: Path) -> None:
    """The whole point. A restart must not start a second chain beside the first."""
    first = written(tmp_path, 2)
    second = opened(tmp_path)
    assert [entry.entry_hash for entry in second.entries] == [
        entry.entry_hash for entry in first.entries
    ]

    second.append(fields(3))
    third = opened(tmp_path)
    assert len(third.entries) == 3
    assert third.entries[2].previous_hash == second.entries[1].entry_hash


def test_a_resumed_log_verifies_against_its_anchor(tmp_path: Path) -> None:
    """A restart must leave evidence that reads as intact, not as an unexplained break."""
    written(tmp_path, 4)
    _, verdict = resume(str(tmp_path), key=KEY, key_id="k1", keys=KEYS)
    assert verdict.ok
    assert verdict.checked == 4
    assert not verdict.tampered


# ============================ what must refuse ============================


def test_a_truncated_log_refuses_to_resume(tmp_path: Path) -> None:
    """The single thing the anchor exists to catch, now caught at boot."""
    written(tmp_path, 3)
    target = log_path(str(tmp_path))
    kept = target.read_text(encoding="utf-8").splitlines()[:2]
    target.write_text("\n".join(kept) + "\n", encoding="utf-8")

    with pytest.raises(JournalError, match="does not verify"):
        resume(str(tmp_path), key=KEY, key_id="k1", keys=KEYS)


def test_an_emptied_log_beside_a_live_anchor_refuses_to_resume(tmp_path: Path) -> None:
    """Deleting the contents is the same attack as deleting some of them."""
    written(tmp_path, 2)
    log_path(str(tmp_path)).write_text("", encoding="utf-8")

    with pytest.raises(JournalError, match="does not verify"):
        resume(str(tmp_path), key=KEY, key_id="k1", keys=KEYS)


def test_entries_with_no_anchor_refuse_to_resume(tmp_path: Path) -> None:
    """The anchor's own blind spot, detectable from this side for the first time.

    Corroborating a volume holding NEITHER still needs the last exported pack, which is
    stated in `docs/DEPLOYMENT.md` and not claimed here.
    """
    written(tmp_path, 2)
    anchor_path(str(tmp_path)).unlink()
    marker_path(str(tmp_path)).unlink()

    with pytest.raises(JournalError, match="holds no anchor"):
        resume(str(tmp_path), key=KEY, key_id="k1", keys=KEYS)


def test_a_rewritten_entry_refuses_to_resume(tmp_path: Path) -> None:
    """Editing a stored row is the tampering the keyed digest is for."""
    written(tmp_path, 2)
    target = log_path(str(tmp_path))
    lines = target.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[0])
    row["actor"] = "someone.else@bluestaq.uk"
    lines[0] = json.dumps(row, sort_keys=True, separators=(",", ":"))
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(JournalError, match="does not verify"):
        resume(str(tmp_path), key=KEY, key_id="k1", keys=KEYS)


def test_a_malformed_line_raises_rather_than_being_skipped(tmp_path: Path) -> None:
    """Skipping it would shorten the log silently, which is the truncation attack."""
    written(tmp_path, 1)
    with log_path(str(tmp_path)).open("a", encoding="utf-8") as handle:
        handle.write("{not json}\n")

    with pytest.raises(JournalError, match="line 2 is not readable JSON"):
        read_entries(str(tmp_path))


def test_a_line_missing_a_field_raises(tmp_path: Path) -> None:
    """A row without every field is not an entry, whatever else it is."""
    log_path(str(tmp_path)).parent.mkdir(parents=True, exist_ok=True)
    log_path(str(tmp_path)).write_text('{"actor": "a"}\n', encoding="utf-8")

    with pytest.raises(JournalError, match="missing"):
        read_entries(str(tmp_path))


def test_a_line_that_is_not_an_object_raises(tmp_path: Path) -> None:
    """A JSON array on a line is readable JSON and still not an audit entry."""
    log_path(str(tmp_path)).parent.mkdir(parents=True, exist_ok=True)
    log_path(str(tmp_path)).write_text("[1, 2, 3]\n", encoding="utf-8")

    with pytest.raises(JournalError, match="is not an audit entry"):
        read_entries(str(tmp_path))


def test_an_implausibly_large_log_is_refused_unread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refused by size before it is pulled into memory."""
    written(tmp_path, 1)
    monkeypatch.setattr(journal_module, "MAXIMUM_LOG_BYTES", 1)
    with pytest.raises(JournalError, match="implausibly large"):
        read_entries(str(tmp_path))


# ============================ the crash between two writes ============================


def test_an_unanchored_tail_is_repaired_at_boot(tmp_path: Path) -> None:
    """A crash after the log write and before the anchor write. The benign direction.

    Only benign because the write order makes it the only one that can happen: an anchor
    ahead of its log is indistinguishable from a truncation.
    """
    chain = written(tmp_path, 2)
    stray = AuditChain(chain.anchor(), key=KEY, key_id="k1").append(fields(3))
    append_entry(str(tmp_path), stray)

    resumed, verdict = resume(str(tmp_path), key=KEY, key_id="k1", keys=KEYS)
    assert verdict.ok
    assert len(resumed.entries) == 3
    stored = read_anchor(str(tmp_path), KEY)
    assert stored is not None
    assert stored.length == 3


def test_the_repair_refuses_a_tail_that_does_not_chain(tmp_path: Path) -> None:
    """The repair is a crash recovery, never a way to graft history on.

    The anchor assertion is the load-bearing half. Without the final verification inside
    `_repair_lag`, one appended line makes `resume` write an anchor recording the
    attacker's tail over the genuine one, authenticated under the real key, BEFORE
    refusing the boot. The durable head and length would be gone irrecoverably and the
    regression guard would then block the recovery.
    """
    written(tmp_path, 2)
    genuine = read_anchor(str(tmp_path), KEY)
    forged = AuditChain(None, key=KEY, key_id="k1").append(fields(9))
    append_entry(str(tmp_path), forged)

    with pytest.raises(JournalError, match="does not verify"):
        resume(str(tmp_path), key=KEY, key_id="k1", keys=KEYS)
    assert read_anchor(str(tmp_path), KEY) == genuine, "the genuine anchor must survive"


def test_the_repair_refuses_a_tail_signed_by_another_key(tmp_path: Path) -> None:
    """A key is retired because it may have leaked. It must not extend the log."""
    chain = written(tmp_path, 2)
    genuine = read_anchor(str(tmp_path), KEY)
    stray = AuditChain(chain.anchor(), key=OTHER_KEY, key_id="k0").append(fields(3))
    append_entry(str(tmp_path), stray)

    with pytest.raises(JournalError, match="does not verify"):
        resume(str(tmp_path), key=KEY, key_id="k1", keys={"k1": KEY, "k0": OTHER_KEY})
    assert read_anchor(str(tmp_path), KEY) == genuine, "the genuine anchor must survive"


def test_the_repair_leaves_an_untouched_anchor_alone(tmp_path: Path) -> None:
    """A log no longer than its anchor has nothing to repair, so the anchor is not rewritten."""
    written(tmp_path, 2)
    stored = read_anchor(str(tmp_path), KEY)
    resume(str(tmp_path), key=KEY, key_id="k1", keys=KEYS)
    assert read_anchor(str(tmp_path), KEY) == stored


# ============================ wedging ============================


def refuse_writes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the next log write fail the way a full or read-only volume would.

    Injected rather than produced by a `chmod`, because the suite runs as root in the
    container and root ignores the permission bits, so a `chmod` test would pass without
    ever exercising the failure.
    """

    def refuse(data_dir: str, entry: object) -> None:
        raise JournalError(f"the audit log at {log_path(data_dir)} could not be written")

    monkeypatch.setattr("complyops.audit.journal.append_entry", refuse)


def test_a_failed_persist_wedges_the_chain(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The head has advanced in memory, so continuing would fork the log.

    Refusing every later append is the fail-closed answer: a change that cannot be
    evidenced does not happen, and after an evidence write fails nothing else happens
    either until an operator looks.
    """
    chain = opened(tmp_path)
    chain.append(fields(1))

    refuse_writes(monkeypatch)
    with pytest.raises(JournalError, match="could not be persisted"):
        chain.append(fields(2))

    assert chain.wedged is not None
    monkeypatch.undo()
    with pytest.raises(JournalError, match="stopped accepting entries"):
        chain.append(fields(3))


def test_a_wedged_chain_leaves_the_volume_readable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An operator must be able to read what was recorded before the fault."""
    chain = opened(tmp_path)
    chain.append(fields(1))
    refuse_writes(monkeypatch)
    with pytest.raises(JournalError):
        chain.append(fields(2))
    monkeypatch.undo()

    assert len(read_entries(str(tmp_path))) == 1


def test_an_anchor_write_failure_wedges_the_chain(tmp_path: Path) -> None:
    """The log is then one entry ahead of the anchor, which the boot repair handles."""
    chain = opened(tmp_path)
    chain.append(fields(1))
    ahead = Anchor(
        head=chain.anchor().head, length=99, key_id="k1", total_length=99, pruned_head="0" * 64
    )
    write_anchor(str(tmp_path), ahead, KEY)

    with pytest.raises(JournalError, match="could not be persisted"):
        chain.append(fields(2))
    assert chain.wedged is not None
    # The ordering, asserted rather than only described. The entry reached the log before
    # the anchor write failed, which is the benign direction: a log longer than its anchor
    # is repairable at boot, and an anchor ahead of its log is indistinguishable from a
    # truncation. Reversing the two writes in `JournalChain.append` fails here.
    assert len(read_entries(str(tmp_path))) == 2, "journal first, anchor second"


def test_the_repair_writes_no_anchor_when_the_tail_is_not_clean(tmp_path: Path) -> None:
    """The stored anchor is only ever replaced by one the whole log verifies against."""
    written(tmp_path, 3)
    genuine = read_anchor(str(tmp_path), KEY)
    target = log_path(str(tmp_path))
    lines = target.read_text(encoding="utf-8").splitlines()
    target.write_text("\n".join([*lines, lines[-1]]) + "\n", encoding="utf-8")

    with pytest.raises(JournalError, match="does not verify"):
        resume(str(tmp_path), key=KEY, key_id="k1", keys=KEYS)
    assert read_anchor(str(tmp_path), KEY) == genuine, "a replayed tail must not re-anchor"


def test_a_log_byte_that_is_not_utf_8_fails_closed_as_a_journal_error(tmp_path: Path) -> None:
    """Every fault in this module is a JournalError, including a decode fault.

    A raw UnicodeDecodeError escaping `resume` would break the contract the app factory
    relies on to keep booting with the audit path unavailable.
    """
    written(tmp_path, 1)
    with log_path(str(tmp_path)).open("ab") as handle:
        handle.write(b"\xff\xfe not utf-8\n")

    with pytest.raises(JournalError, match="could not be read"):
        read_entries(str(tmp_path))


def test_the_repair_refuses_a_tail_on_a_corrupted_prefix(tmp_path: Path) -> None:
    """The third guard on the only function that overwrites the trusted anchor.

    An edited early entry with a genuine current-key tail appended after it: the tail
    chains cleanly from the tail's own predecessor, so only verifying the PREFIX against
    the stored anchor catches it.
    """
    chain = written(tmp_path, 3)
    genuine = read_anchor(str(tmp_path), KEY)
    stray = AuditChain(chain.anchor(), key=KEY, key_id="k1").append(fields(4))
    append_entry(str(tmp_path), stray)

    target = log_path(str(tmp_path))
    lines = target.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[0])
    row["actor"] = "someone.else@bluestaq.uk"
    lines[0] = json.dumps(row, sort_keys=True, separators=(",", ":"))
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(JournalError, match="does not verify"):
        resume(str(tmp_path), key=KEY, key_id="k1", keys=KEYS)
    assert read_anchor(str(tmp_path), KEY) == genuine, "the genuine anchor must survive"


def test_a_log_write_that_fails_is_a_journal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The OSError to JournalError conversion on the append itself, not only on the read."""
    written(tmp_path, 1)
    real = os.write

    def refuse(descriptor: int, payload: bytes) -> int:
        raise OSError("no space left on device")

    monkeypatch.setattr(os, "write", refuse)
    try:
        with pytest.raises(JournalError, match="could not be written"):
            append_entry(str(tmp_path), opened(tmp_path).entries[0])
    finally:
        monkeypatch.setattr(os, "write", real)


def test_appending_to_a_named_pipe_is_refused_rather_than_blocking(tmp_path: Path) -> None:
    """The write side of the guard the read side already had.

    Opening a FIFO for writing blocks until a reader appears, so `rm log.jsonl && mkfifo
    log.jsonl` after boot hung a mutation forever and permanently consumed one of the eight
    worker threads. Eight of those and the process serves nothing, health paths included.
    """
    written(tmp_path, 1)
    target = log_path(str(tmp_path))
    entry = opened(tmp_path).entries[0]
    target.unlink()
    os.mkfifo(target)

    # Two paths reach the same refusal and both matter. With no reader, `O_NONBLOCK` makes
    # the open itself fail with ENXIO; with a reader attached it succeeds and `fstat`
    # catches the FIFO. Either way it returns rather than blocking, which is the property.
    started = time.monotonic()
    with pytest.raises(JournalError, match=r"not a regular file|No such device"):
        append_entry(str(tmp_path), entry)
    assert time.monotonic() - started < 5, "it must return, not block on a reader"


def test_appending_through_a_symlink_is_refused(tmp_path: Path) -> None:
    """`O_NOFOLLOW`, so the log cannot be redirected somewhere else on the volume."""
    written(tmp_path, 1)
    target = log_path(str(tmp_path))
    entry = opened(tmp_path).entries[0]
    elsewhere = Path(tmp_path) / "elsewhere.jsonl"
    elsewhere.touch()
    target.unlink()
    target.symlink_to(elsewhere)

    with pytest.raises(JournalError, match=r"could not be written|not a regular file"):
        append_entry(str(tmp_path), entry)
    assert elsewhere.read_text(encoding="utf-8") == "", "nothing may be written through it"


def test_appending_to_a_pipe_with_a_reader_is_refused(tmp_path: Path) -> None:
    """The `fstat` guard, reached only when the open SUCCEEDS on a non-regular file.

    With no reader, `O_NONBLOCK` refuses the open outright and the check below is never
    reached, which is why it survived mutation until this test existed. Attach a reader and
    the open succeeds, so something has to notice the file is a pipe before writing an
    audit entry into it, where it would vanish into the reader instead of onto the volume.
    """
    written(tmp_path, 1)
    target = log_path(str(tmp_path))
    entry = opened(tmp_path).entries[0]
    target.unlink()
    os.mkfifo(target)

    drained: list[bytes] = []

    def drain() -> None:
        """Hold the read end open so the write end's `open` succeeds."""
        with contextlib.suppress(OSError):
            descriptor = os.open(str(target), os.O_RDONLY)
            try:
                drained.append(os.read(descriptor, 4096))
            finally:
                os.close(descriptor)

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    time.sleep(0.2)
    try:
        with pytest.raises(JournalError, match=r"not a regular file|No such device"):
            append_entry(str(tmp_path), entry)
    finally:
        with contextlib.suppress(OSError):
            os.close(os.open(str(target), os.O_WRONLY | os.O_NONBLOCK))
        reader.join(timeout=5)

    assert drained in ([], [b""]), "no audit entry may be written into a pipe"
