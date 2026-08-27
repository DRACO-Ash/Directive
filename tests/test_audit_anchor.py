"""Anchor tests: the outside reference that catches a wholesale rewrite."""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

import pytest

from complyops.audit import anchor as anchor_module
from complyops.audit.anchor import (
    Anchor,
    AnchorError,
    AnchorTamperError,
    marker_path,
    read_anchor,
    write_anchor,
)
from complyops.audit.hashing import GENESIS_HASH
from conftest import TEST_KEY, TEST_KEY_ID

OTHER_KEY = bytes.fromhex("cd" * 32)
KEYS = {TEST_KEY_ID: TEST_KEY}


def test_a_log_never_used_reads_as_no_anchor(tmp_path: Path) -> None:
    assert read_anchor(str(tmp_path), TEST_KEY) is None


def test_an_anchor_round_trips(tmp_path: Path) -> None:
    written = Anchor(head="a" * 64, length=42, key_id=TEST_KEY_ID)
    write_anchor(str(tmp_path), written, TEST_KEY)
    assert read_anchor(str(tmp_path), TEST_KEY) == written


def test_the_genesis_anchor_describes_an_empty_log() -> None:
    assert Anchor.genesis(TEST_KEY_ID) == Anchor(head=GENESIS_HASH, length=0, key_id=TEST_KEY_ID)


def test_the_anchor_is_authenticated_so_it_cannot_be_forged_without_the_key(
    tmp_path: Path,
) -> None:
    """The attack this closes needs no access to the record store at all.

    An actor with write access to the volume replays an earlier entry's genuine digest
    into the anchor, and a truncated log then verifies as intact. The authentication tag
    means writing an anchor requires the signing key.
    """
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=6, key_id=TEST_KEY_ID), TEST_KEY)
    stored = json.loads((tmp_path / anchor_module.ANCHOR_FILENAME).read_text(encoding="utf-8"))

    stored["length"] = 2
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(json.dumps(stored), encoding="utf-8")
    with pytest.raises(AnchorError, match="not authenticated"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_an_anchor_written_under_a_different_key_is_refused(tmp_path: Path) -> None:
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=1, key_id=TEST_KEY_ID), OTHER_KEY)
    with pytest.raises(AnchorError, match="not authenticated"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_a_deleted_anchor_is_a_tamper_alarm_not_a_fresh_install(tmp_path: Path) -> None:
    """One `rm` previously removed the only truncation control silently."""
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=6, key_id=TEST_KEY_ID), TEST_KEY)
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    with pytest.raises(AnchorError, match="deleted"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_the_first_use_marker_is_written(tmp_path: Path) -> None:
    write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    assert anchor_module.marker_path(str(tmp_path)).exists()


def test_the_write_leaves_no_temporary_file(tmp_path: Path) -> None:
    write_anchor(str(tmp_path), Anchor(head="b" * 64, length=1, key_id=TEST_KEY_ID), TEST_KEY)
    names = sorted(path.name for path in tmp_path.iterdir())
    assert names == sorted([anchor_module.ANCHOR_FILENAME, anchor_module.MARKER_FILENAME])


def test_the_temporary_file_is_uniquely_named_per_writer(tmp_path: Path) -> None:
    """A shared fixed temp name is not atomic across writers.

    Two writers sharing one temp path produced torn reads. The name must be unique, and
    the file must live in the target directory so the rename stays within one filesystem.
    """
    captured: list[str] = []
    real_mkstemp = anchor_module.tempfile.mkstemp

    def recording(**kwargs: object):  # noqa: ANN202
        handle, path = real_mkstemp(**kwargs)  # type: ignore[arg-type]
        captured.append(path)
        return handle, path

    anchor_module.tempfile.mkstemp = recording  # type: ignore[assignment]
    try:
        write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
        write_anchor(str(tmp_path), Anchor(head="c" * 64, length=1, key_id=TEST_KEY_ID), TEST_KEY)
    finally:
        anchor_module.tempfile.mkstemp = real_mkstemp  # type: ignore[assignment]

    # Four, not two: the marker is now written with the same mkstemp, fsync, rename, fsync
    # sequence as the anchor. A plain write_text left a zero-length marker beside a durable
    # anchor after a crash, and deleting the anchor then read as a fresh install, silently
    # disarming the alarm the marker exists to raise.
    assert len(captured) == 4
    assert len(set(captured)) == 4, "a shared temp name is not atomic across writers"
    assert all(Path(path).parent == tmp_path for path in captured)
    assert not list(tmp_path.glob("*.tmp")), "no temporary file survives a successful write"


def test_a_later_write_replaces_the_earlier_one(tmp_path: Path) -> None:
    write_anchor(str(tmp_path), Anchor(head="b" * 64, length=1, key_id=TEST_KEY_ID), TEST_KEY)
    write_anchor(str(tmp_path), Anchor(head="c" * 64, length=2, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(tmp_path), TEST_KEY)
    assert stored is not None
    assert (stored.head, stored.length) == ("c" * 64, 2)


def test_the_anchor_is_created_when_the_directory_does_not_exist(tmp_path: Path) -> None:
    target = tmp_path / "not-yet"
    write_anchor(str(target), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    assert read_anchor(str(target), TEST_KEY) == Anchor.genesis(TEST_KEY_ID)


def test_an_anchor_cannot_be_authenticated_without_a_key() -> None:
    with pytest.raises(AnchorError, match="without the signing key"):
        Anchor.genesis(TEST_KEY_ID).mac(b"")


def signed(document: dict[str, object]) -> str:
    """Return a document carrying a tag valid for its own contents."""
    anchor = Anchor(
        head=str(document["head"]),
        length=int(document["length"]),  # type: ignore[arg-type]
        key_id=str(document["keyId"]),
    )
    return json.dumps({**document, "mac": anchor.mac(TEST_KEY)})


@pytest.mark.parametrize(
    "contents",
    [
        "not json at all",
        "[]",
        "{}",
        json.dumps({"head": "short", "length": 1, "keyId": "k1"}),
        json.dumps({"head": "a" * 64, "length": -1, "keyId": "k1"}),
        json.dumps({"head": "a" * 64, "length": "many", "keyId": "k1"}),
        json.dumps({"head": "a" * 64, "length": 1}),
        json.dumps({"head": "a" * 64, "length": 1, "keyId": ""}),
        json.dumps({"head": "a" * 64, "length": 1, "keyId": "k1"}),
    ],
)
def test_a_corrupt_or_unauthenticated_anchor_fails_closed(tmp_path: Path, contents: str) -> None:
    """Treating a corrupt anchor as "no anchor yet" would drop the only rewrite control."""
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(contents, encoding="utf-8")
    with pytest.raises(AnchorError):
        read_anchor(str(tmp_path), TEST_KEY)


def test_a_boolean_length_is_refused(tmp_path: Path) -> None:
    """`isinstance(True, int)` is True, so `length=true` would match a one-entry log."""
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(
        signed({"schemaVersion": 1, "head": "a" * 64, "length": True, "keyId": "k1"}),
        encoding="utf-8",
    )
    with pytest.raises(AnchorError, match="not a usable anchor"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_an_anchor_rolled_back_within_a_run_is_refused(tmp_path: Path) -> None:
    """An authenticated anchor cannot be forged, but a genuine older one can be restored.

    The attacker keeps a copy of the six-entry anchor, truncates the log, and puts the
    old anchor back. Its tag is valid because the application wrote it, so only a
    monotonicity check catches the rollback.
    """
    anchor_module.reset_high_water_mark()
    six = Anchor(head="a" * 64, length=6, key_id=TEST_KEY_ID)
    write_anchor(str(tmp_path), six, TEST_KEY)
    kept = (tmp_path / anchor_module.ANCHOR_FILENAME).read_text(encoding="utf-8")

    write_anchor(str(tmp_path), Anchor(head="b" * 64, length=8, key_id=TEST_KEY_ID), TEST_KEY)
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(kept, encoding="utf-8")

    with pytest.raises(AnchorError, match="older anchor was restored"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_the_high_water_mark_is_per_data_directory(tmp_path: Path) -> None:
    anchor_module.reset_high_water_mark()
    first, second = tmp_path / "one", tmp_path / "two"
    write_anchor(str(first), Anchor(head="a" * 64, length=9, key_id=TEST_KEY_ID), TEST_KEY)
    write_anchor(str(second), Anchor(head="b" * 64, length=1, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(second), TEST_KEY)
    assert stored is not None
    assert stored.length == 1


def test_growing_the_log_is_not_a_rollback(tmp_path: Path) -> None:
    """The boundary in the other direction, or the check asserts nothing."""
    anchor_module.reset_high_water_mark()
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=3, key_id=TEST_KEY_ID), TEST_KEY)
    assert read_anchor(str(tmp_path), TEST_KEY) is not None
    write_anchor(str(tmp_path), Anchor(head="b" * 64, length=4, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(tmp_path), TEST_KEY)
    assert stored is not None
    assert stored.length == 4


def test_a_failed_write_leaves_no_temporary_file_behind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A crash mid-write must not leave a partial file that reads as a tamper alarm."""
    captured: list[str] = []
    real_mkstemp = anchor_module.tempfile.mkstemp

    def recording(**kwargs: object):  # noqa: ANN202
        handle, path = real_mkstemp(**kwargs)  # type: ignore[arg-type]
        captured.append(path)
        return handle, path

    def explode(_directory: Path) -> None:
        raise OSError("the directory could not be flushed")

    monkeypatch.setattr(anchor_module.tempfile, "mkstemp", recording)
    monkeypatch.setattr(anchor_module, "_fsync_directory", explode)
    with pytest.raises(OSError, match="could not be flushed"):
        write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)

    assert captured
    assert not Path(captured[0]).exists()


def test_an_anchor_with_no_usable_schema_version_is_refused(tmp_path: Path) -> None:
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(
        json.dumps({"schemaVersion": "one", "head": "a" * 64, "length": 1, "keyId": "k1"}),
        encoding="utf-8",
    )
    with pytest.raises(AnchorError, match="no usable schema version"):
        read_anchor(str(tmp_path), TEST_KEY)


ROTATED_KEY = bytes(range(16)) + bytes(range(240, 256))
ROTATED_KEYS = {TEST_KEY_ID: TEST_KEY, "k2": ROTATED_KEY}


def test_a_leaked_retired_key_cannot_forge_an_anchor(tmp_path: Path) -> None:
    """The reason the anchor trusts ONE key, and the worst finding of the build.

    Accepting any key still held was meant to stop a rotation raising a false alarm. What it
    actually did was hand the trusted reference to anybody holding a retired key: re-sign
    the whole log under it, write a matching anchor and marker, and wholly invented history
    was certified as intact, defeating the tail-key check in `verify_log` completely. A key
    is retired because it may have leaked, so it is exactly the key an anchor must not
    trust. Retired keys stay valid for stored ENTRIES, which is a different job.
    """
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=3, key_id=TEST_KEY_ID), TEST_KEY)

    forged = Anchor(head="f" * 64, length=20, key_id="k0")
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(
        forged.as_json(ROTATED_KEY), encoding="utf-8"
    )
    with pytest.raises(AnchorError, match="not authenticated under the current signing key"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_an_anchor_written_under_another_key_is_refused(tmp_path: Path) -> None:
    """The same rule for any key that is not the current one."""
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=1, key_id=TEST_KEY_ID), OTHER_KEY)
    with pytest.raises(AnchorError, match="not authenticated under the current signing key"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_a_planted_marker_under_a_retired_key_does_not_count(tmp_path: Path) -> None:
    """The marker is held to the same single-key rule as the anchor.

    Otherwise the forgery above simply plants its own marker and the deletion alarm cannot
    tell it from a genuine one.
    """
    genuine_tag = anchor_module._marker_tag(str(tmp_path), ROTATED_KEY)
    anchor_module.marker_path(str(tmp_path)).write_text(genuine_tag, encoding="utf-8")
    assert read_anchor(str(tmp_path), TEST_KEY) is None, "a retired-key marker is not evidence"


def test_a_write_that_would_shorten_the_record_is_refused(tmp_path: Path) -> None:
    """One bad write used to destroy the durable head irrecoverably.

    The high-water mark only guarded reads and only ever rose, so the process refused to
    read back an anchor it had itself overwritten, and the true head was gone for good.
    """
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=9, key_id=TEST_KEY_ID), TEST_KEY)
    with pytest.raises(AnchorError, match="would destroy the durable record"):
        write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)

    stored = read_anchor(str(tmp_path), TEST_KEY)
    assert stored is not None
    assert stored.length == 9


def test_an_operator_can_deliberately_re_anchor_shorter(tmp_path: Path) -> None:
    """Fail closed for security, and recoverable for operations."""
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=9, key_id=TEST_KEY_ID), TEST_KEY)
    write_anchor(
        str(tmp_path),
        Anchor(head="b" * 64, length=4, key_id=TEST_KEY_ID),
        TEST_KEY,
        allow_shortening=True,
    )
    anchor_module.reset_high_water_mark()
    stored = read_anchor(str(tmp_path), TEST_KEY)
    assert stored is not None
    assert stored.length == 4


def test_growing_the_record_is_not_a_regression(tmp_path: Path) -> None:
    """The boundary in the other direction, or the guard asserts nothing."""
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=4, key_id=TEST_KEY_ID), TEST_KEY)
    write_anchor(str(tmp_path), Anchor(head="b" * 64, length=4, key_id=TEST_KEY_ID), TEST_KEY)
    write_anchor(str(tmp_path), Anchor(head="c" * 64, length=5, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(tmp_path), TEST_KEY)
    assert stored is not None
    assert stored.length == 5


def test_a_planted_marker_cannot_wedge_the_audit_path(tmp_path: Path) -> None:
    """One touch by an actor with no key used to deny the whole write path permanently.

    Every read raised "it was deleted", with no code path to clear it, and nothing in the
    documentation told an operator that deleting the file the alarm names was the fix.
    """
    marker = tmp_path / anchor_module.MARKER_FILENAME
    marker.write_text("planted by somebody without a key", encoding="utf-8")
    assert read_anchor(str(tmp_path), TEST_KEY) is None

    marker.write_text("", encoding="utf-8")
    assert read_anchor(str(tmp_path), TEST_KEY) is None


def test_a_marker_from_another_volume_does_not_count(tmp_path: Path) -> None:
    """The tag is bound to the directory, so a genuine marker cannot be copied across."""
    other = tmp_path / "elsewhere"
    other.mkdir()
    write_anchor(str(other), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    copied = (other / anchor_module.MARKER_FILENAME).read_text(encoding="utf-8")
    (tmp_path / anchor_module.MARKER_FILENAME).write_text(copied, encoding="utf-8")
    assert read_anchor(str(tmp_path), TEST_KEY) is None


def test_the_marker_exists_whenever_an_anchor_does(tmp_path: Path) -> None:
    """A successful write leaves both files, so the deletion alarm has something to fire on.

    The marker is written AFTER the anchor rename, with the same durable sequence. Writing
    it first was worse in both directions: a failed anchor write left a marker on a virgin
    volume and every later read raised "it was deleted", and a non-durable write left a
    zero-length marker beside a good anchor. An anchor found without a valid marker is now
    repaired on read rather than read as evidence.
    """
    write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    assert (tmp_path / anchor_module.MARKER_FILENAME).exists()
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    with pytest.raises(AnchorError, match="deleted"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_a_deletion_alarm_survives_a_key_rotation(tmp_path: Path) -> None:
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=2, key_id=TEST_KEY_ID), TEST_KEY)
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    with pytest.raises(AnchorError, match="deleted"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_an_unknown_schema_version_fails_closed(tmp_path: Path) -> None:
    """A rolling deploy can put two image versions on one volume."""
    ahead = anchor_module.ANCHOR_SCHEMA_VERSION + 1
    later = Anchor(head="a" * 64, length=1, key_id=TEST_KEY_ID, schema_version=ahead)
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(later.as_json(TEST_KEY), encoding="utf-8")
    with pytest.raises(AnchorError, match=f"schema version {ahead}"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_an_implausibly_large_anchor_is_refused_unread(tmp_path: Path) -> None:
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(
        "x" * (anchor_module.MAXIMUM_ANCHOR_BYTES + 1), encoding="utf-8"
    )
    with pytest.raises(AnchorError, match="implausibly large"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_a_non_digest_authentication_tag_fails_closed_rather_than_raising(
    tmp_path: Path,
) -> None:
    """hmac.compare_digest raises on a non-ASCII string.

    That let an actor with volume write access and no key turn the tamper alarm into an
    unhandled exception, so a caller catching AnchorError got a 500 rather than the
    diagnosis.
    """
    stored = json.loads(Anchor.genesis(TEST_KEY_ID).as_json(TEST_KEY))
    for tag in ["é" * 64, "", "not a digest", "A" * 64, 7]:
        stored["mac"] = tag
        (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(json.dumps(stored), encoding="utf-8")
        with pytest.raises(AnchorError, match="not authenticated"):
            read_anchor(str(tmp_path), TEST_KEY)


def test_the_high_water_mark_ignores_how_the_path_is_spelt(tmp_path: Path) -> None:
    """The same directory spelt two ways used to be two separate marks."""
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=6, key_id=TEST_KEY_ID), TEST_KEY)
    assert read_anchor(str(tmp_path), TEST_KEY) is not None

    # An actor with volume write access restores a genuine older anchor, without a key.
    older = Anchor(head="b" * 64, length=2, key_id=TEST_KEY_ID)
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(older.as_json(TEST_KEY), encoding="utf-8")
    with pytest.raises(AnchorError, match="older anchor was restored"):
        read_anchor(f"{tmp_path}/", TEST_KEY)


@pytest.mark.parametrize("hostile", ["=cmd", "k 1", "k" * 33, "kéy"])
def test_an_anchor_naming_an_unusable_key_id_is_refused(tmp_path: Path, hostile: str) -> None:
    stored = json.loads(Anchor.genesis(TEST_KEY_ID).as_json(TEST_KEY))
    stored["keyId"] = hostile
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(json.dumps(stored), encoding="utf-8")
    with pytest.raises(AnchorError):
        read_anchor(str(tmp_path), TEST_KEY)


def test_the_marker_cannot_be_tagged_without_a_key(tmp_path: Path) -> None:
    with pytest.raises(AnchorError, match="without the signing key"):
        anchor_module._marker_tag(str(tmp_path), b"")


def test_an_unreadable_marker_counts_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A marker that cannot be read is not evidence the log was used."""
    write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    real_read = Path.read_text

    def refuse(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == anchor_module.MARKER_FILENAME:
            raise OSError("unreadable")
        return real_read(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", refuse)
    assert read_anchor(str(tmp_path), TEST_KEY) is None


def test_a_failed_rename_leaves_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: list[str] = []
    real_mkstemp = anchor_module.tempfile.mkstemp

    def recording(**kwargs: object):  # noqa: ANN202
        handle, path = real_mkstemp(**kwargs)  # type: ignore[arg-type]
        captured.append(path)
        return handle, path

    def explode(self: Path, _target: Path) -> None:
        raise OSError("rename refused")

    monkeypatch.setattr(anchor_module.tempfile, "mkstemp", recording)
    monkeypatch.setattr(Path, "replace", explode)
    with pytest.raises(OSError, match="rename refused"):
        write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    assert captured
    assert not Path(captured[0]).exists()


def test_a_corrupt_stored_anchor_blocks_a_write_rather_than_being_ignored(
    tmp_path: Path,
) -> None:
    """An anchor that exists but cannot be read is evidence of a record, not its absence.

    Reading it leniently collapsed "there is no anchor" and "there is one I cannot
    authenticate" into the same answer, and the second is exactly the state the alarm
    exists for. An operator who genuinely needs to write over it has allow_shortening.
    """
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text("not json", encoding="utf-8")
    with pytest.raises(AnchorError, match="could not be read"):
        write_anchor(str(tmp_path), Anchor(head="a" * 64, length=1, key_id=TEST_KEY_ID), TEST_KEY)

    write_anchor(
        str(tmp_path),
        Anchor(head="a" * 64, length=1, key_id=TEST_KEY_ID),
        TEST_KEY,
        allow_shortening=True,
    )
    stored = read_anchor(str(tmp_path), TEST_KEY)
    assert stored is not None
    assert stored.length == 1


def test_an_unauthenticated_stored_anchor_blocks_a_write(tmp_path: Path) -> None:
    """The deliberate trade, recorded so the cost is visible.

    An actor with volume write access and no key CAN plant an unauthenticated anchor and
    block ordinary writes, which is a denial of service on the audit path. The alternative
    was worse: ignoring an anchor that fails authentication let a shortening write through
    after a key rotation and destroyed the durable record. Availability is recovered with
    allow_shortening, which is the documented operator override; a destroyed record is not
    recoverable at all, so this is the right way round.
    """
    planted = Anchor(head="f" * 64, length=99, key_id=TEST_KEY_ID)
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(
        planted.as_json(OTHER_KEY), encoding="utf-8"
    )
    with pytest.raises(AnchorError, match="not authenticated"):
        write_anchor(str(tmp_path), Anchor(head="a" * 64, length=2, key_id=TEST_KEY_ID), TEST_KEY)


def test_a_fresh_anchor_reports_nothing_archived() -> None:
    anchor = Anchor(head="a" * 64, length=4, key_id=TEST_KEY_ID)
    assert anchor.total_length == 4
    assert anchor.archived_length == 0
    assert anchor.pruned_head == GENESIS_HASH


def test_pruning_moves_entries_without_moving_the_total() -> None:
    """AUD-001 prunes the active log annually. That is not a truncation.

    The entries leave the active log, not the chain, so the total stands and the archive
    boundary records what the remaining active log chains from.
    """
    before = Anchor(head="e" * 64, length=10, key_id=TEST_KEY_ID)
    after = before.after_prune(kept=4, pruned_head="a" * 64)

    assert after.length == 4
    assert after.total_length == 10, "the total is the figure a truncation would falsify"
    assert after.archived_length == 6
    assert after.pruned_head == "a" * 64
    assert after.head == before.head, "pruning the tail end of the archive leaves the head"


def test_pruning_everything_leaves_the_head_as_the_boundary() -> None:
    before = Anchor(head="e" * 64, length=10, key_id=TEST_KEY_ID)
    after = before.after_prune(kept=0, pruned_head="a" * 64)
    assert (after.length, after.total_length) == (0, 10)
    assert after.pruned_head == before.head
    assert after.head == before.head


@pytest.mark.parametrize("kept", [-1, 11])
def test_pruning_cannot_invent_entries(kept: int) -> None:
    before = Anchor(head="e" * 64, length=10, key_id=TEST_KEY_ID)
    with pytest.raises(AnchorError, match="never invents them"):
        before.after_prune(kept=kept, pruned_head="a" * 64)


def test_pruning_requires_a_real_archive_boundary() -> None:
    before = Anchor(head="e" * 64, length=10, key_id=TEST_KEY_ID)
    with pytest.raises(AnchorError, match="digest of the last archived entry"):
        before.after_prune(kept=4, pruned_head="not a digest")


def test_a_prune_is_a_legitimate_write_and_a_truncation_is_not(tmp_path: Path) -> None:
    """The regression guard must permit the one and refuse the other.

    Guarding the ACTIVE length would refuse a prune, which AUD-001 requires annually.
    Guarding the total refuses a truncation, which is what the control is for.
    """
    write_anchor(str(tmp_path), Anchor(head="e" * 64, length=10, key_id=TEST_KEY_ID), TEST_KEY)

    pruned = Anchor(head="e" * 64, length=10, key_id=TEST_KEY_ID).after_prune(
        kept=4, pruned_head="a" * 64
    )
    write_anchor(str(tmp_path), pruned, TEST_KEY)
    stored = read_anchor(str(tmp_path), TEST_KEY)
    assert stored is not None
    assert (stored.length, stored.total_length) == (4, 10)

    with pytest.raises(AnchorError, match="would destroy the durable record"):
        write_anchor(str(tmp_path), Anchor(head="b" * 64, length=4, key_id=TEST_KEY_ID), TEST_KEY)


def test_the_archive_boundary_survives_a_round_trip(tmp_path: Path) -> None:
    pruned = Anchor(
        head="e" * 64, length=3, key_id=TEST_KEY_ID, total_length=12, pruned_head="c" * 64
    )
    write_anchor(str(tmp_path), pruned, TEST_KEY)
    stored = read_anchor(str(tmp_path), TEST_KEY)
    assert stored == pruned


def test_an_anchor_claiming_fewer_entries_ever_than_it_holds_is_refused(tmp_path: Path) -> None:
    """A total below the active length is incoherent, so it is not read."""
    stored = json.loads(Anchor(head="a" * 64, length=5, key_id=TEST_KEY_ID).as_json(TEST_KEY))
    stored["totalLength"] = 2
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(json.dumps(stored), encoding="utf-8")
    with pytest.raises(AnchorError):
        read_anchor(str(tmp_path), TEST_KEY)


@pytest.mark.parametrize("field", ["totalLength", "prunedHead"])
def test_the_archive_boundary_is_covered_by_the_authentication_tag(
    tmp_path: Path, field: str
) -> None:
    """Otherwise an actor with volume write access edits the boundary and not the tag."""
    genuine = Anchor(
        head="e" * 64, length=3, key_id=TEST_KEY_ID, total_length=12, pruned_head="c" * 64
    )
    stored = json.loads(genuine.as_json(TEST_KEY))
    stored[field] = 99 if field == "totalLength" else "d" * 64
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(json.dumps(stored), encoding="utf-8")
    with pytest.raises(AnchorError, match="not authenticated"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_a_truncation_after_a_prune_is_refused_across_a_restart(tmp_path: Path) -> None:
    """The headline claim of the boundary change, which no test exercised.

    Guarding the active length instead of the total behaved identically in every existing
    test, because `after_prune` keeps the total constant, so the mutation survived.
    """
    write_anchor(str(tmp_path), Anchor(head="e" * 64, length=10, key_id=TEST_KEY_ID), TEST_KEY)
    pruned = Anchor(head="e" * 64, length=10, key_id=TEST_KEY_ID).after_prune(
        kept=4, pruned_head="a" * 64
    )
    write_anchor(str(tmp_path), pruned, TEST_KEY)

    anchor_module.reset_high_water_mark()
    with pytest.raises(AnchorError, match="entries ever over one recording 10"):
        write_anchor(
            str(tmp_path),
            Anchor(
                head="b" * 64, length=4, key_id=TEST_KEY_ID, total_length=5, pruned_head="a" * 64
            ),
            TEST_KEY,
        )


def test_a_rotation_needs_a_re_anchor_and_the_procedure_works(tmp_path: Path) -> None:
    """Rotation costs one explicit step, and that is the right price.

    The anchor authenticates under the current key only, so after a rotation the stored
    anchor no longer reads. The procedure is: read under the OUTGOING key, write under the
    INCOMING one. That is a documented operator step in docs/DEPLOYMENT.md, and it is the
    price of not trusting the anchor to a key that may have leaked.
    """
    write_anchor(str(tmp_path), Anchor(head="e" * 64, length=9, key_id=TEST_KEY_ID), TEST_KEY)
    anchor_module.reset_high_water_mark()

    # Immediately after the rotation, before the re-anchor, the new key cannot read it.
    with pytest.raises(AnchorError, match="not authenticated under the current signing key"):
        read_anchor(str(tmp_path), ROTATED_KEY)

    # The re-anchor: one named step, read under the outgoing key and write under the
    # incoming one. Executable rather than prose in a runbook, because the write path
    # deliberately refuses to read an anchor it cannot authenticate and would otherwise
    # block the very procedure that fixes that.
    carried = anchor_module.re_anchor(
        str(tmp_path), outgoing_key=TEST_KEY, incoming_key=ROTATED_KEY, expected_total=9
    )
    assert carried is not None
    assert carried.key_id == TEST_KEY_ID, (
        "key_id records the key that signed the last ENTRY, so a re-anchor must not move it"
    )

    reread = read_anchor(str(tmp_path), ROTATED_KEY)
    assert reread is not None
    assert reread.total_length == 9, "the re-anchor must carry the record forward, not reset it"
    assert reread.head == "e" * 64


def test_a_shortening_write_is_still_refused_after_a_re_anchor(tmp_path: Path) -> None:
    """The rotation must not become a way to shorten the record."""
    write_anchor(str(tmp_path), Anchor(head="e" * 64, length=9, key_id=TEST_KEY_ID), TEST_KEY)
    anchor_module.reset_high_water_mark()
    with pytest.raises(AnchorError, match="not authenticated under the current signing key"):
        write_anchor(str(tmp_path), Anchor.genesis("k2"), ROTATED_KEY)


def test_a_signed_but_incoherent_anchor_is_refused_by_the_coherence_guard(
    tmp_path: Path,
) -> None:
    """Signed, so the authentication tag cannot be what catches it.

    The existing test edited the field after signing, so the tag caught it and the
    coherence guard was never exercised: deleting the guard left the suite green.
    """
    coherent = Anchor(head="a" * 64, length=5, key_id=TEST_KEY_ID, total_length=9)
    document = json.loads(coherent.as_json(TEST_KEY))
    document["length"] = 12
    forged = Anchor(
        head="a" * 64, length=12, key_id=TEST_KEY_ID, total_length=12, pruned_head=GENESIS_HASH
    )
    document["mac"] = forged.mac(TEST_KEY)
    document["totalLength"] = 9
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(AnchorError):
        read_anchor(str(tmp_path), TEST_KEY)


def test_an_anchor_cannot_be_built_incoherent_in_the_first_place() -> None:
    """Cheaper than refusing to read one back, which is a self-inflicted lockout."""
    with pytest.raises(AnchorError, match="could never be read back"):
        Anchor(head="a" * 64, length=5, key_id=TEST_KEY_ID, total_length=2)


def test_a_signed_non_digest_boundary_is_refused_by_its_own_guard(tmp_path: Path) -> None:
    """Signed, so again the tag cannot be what catches it."""
    document = {
        "schemaVersion": anchor_module.ANCHOR_SCHEMA_VERSION,
        "head": "a" * 64,
        "length": 1,
        "keyId": TEST_KEY_ID,
        "totalLength": 1,
        "prunedHead": "not a digest",
    }
    message = json.dumps(document, sort_keys=True).encode("utf-8")
    document["mac"] = hmac.new(TEST_KEY, message, hashlib.sha256).hexdigest()
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(AnchorError, match="not a usable anchor"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_pruning_cannot_leave_a_genesis_boundary_with_archived_entries() -> None:
    """Genesis satisfies is_hash, so this wrote and read cleanly before failing later."""
    before = Anchor(head="e" * 64, length=10, key_id=TEST_KEY_ID)
    with pytest.raises(AnchorError, match="cannot be the genesis digest"):
        before.after_prune(kept=4, pruned_head=GENESIS_HASH)


def test_the_stored_schema_version_is_pinned_to_a_literal(tmp_path: Path) -> None:
    """Otherwise the on-disk contract can be bumped with no test noticing.

    The same reasoning as the golden vector on FIELD_ORDER: a version the code derives
    from itself pins nothing.
    """
    assert anchor_module.ANCHOR_SCHEMA_VERSION == 2
    write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    document = json.loads((tmp_path / anchor_module.ANCHOR_FILENAME).read_text(encoding="utf-8"))
    assert document["schemaVersion"] == 2
    assert set(document) == {
        "schemaVersion",
        "head",
        "length",
        "keyId",
        "totalLength",
        "prunedHead",
        "mac",
    }


def test_the_marker_is_repaired_rather_than_read_as_evidence(tmp_path: Path) -> None:
    """An anchor with no marker is a crash artefact, not a tamper signal.

    The marker used to be written BEFORE the anchor rename, so a failed anchor write left a
    marker on a virgin volume and every later read raised "it was deleted". Since no
    register write may happen without an audit entry, that wedged the whole write path over
    a control the anchor itself already satisfies.
    """
    write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    marker = tmp_path / anchor_module.MARKER_FILENAME
    marker.write_text("", encoding="utf-8")

    stored = read_anchor(str(tmp_path), TEST_KEY)
    assert stored is not None, "a genuine anchor must still be readable"
    assert marker.read_text(encoding="utf-8"), "the marker is repaired on the way past"

    # And the repaired marker still raises the alarm if the anchor is then deleted.
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    with pytest.raises(AnchorError, match="deleted"):
        read_anchor(str(tmp_path), TEST_KEY)


def test_a_failed_anchor_write_does_not_leave_a_marker_on_a_virgin_volume(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The forward half of the same invariant: no false alarm from a crashed first write."""

    def explode(self: Path, _target: Path) -> None:
        raise OSError("no space left on device")

    monkeypatch.setattr(Path, "replace", explode)
    with pytest.raises(OSError, match="no space left"):
        write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    monkeypatch.undo()

    assert not anchor_module.marker_path(str(tmp_path)).exists()
    assert read_anchor(str(tmp_path), TEST_KEY) is None, "a virgin volume must read as virgin"


def test_an_operator_re_anchor_does_not_wedge_the_next_write(tmp_path: Path) -> None:
    """allow_shortening lowers the mark, or the sanctioned recovery breaks the next write.

    The mark only ever rose, so after a deliberate re-anchor from 9 to 4 the next
    legitimate write of 5 was refused, and with it every register write in the process.
    """
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=9, key_id=TEST_KEY_ID), TEST_KEY)
    write_anchor(
        str(tmp_path),
        Anchor(head="b" * 64, length=4, key_id=TEST_KEY_ID),
        TEST_KEY,
        allow_shortening=True,
    )
    write_anchor(str(tmp_path), Anchor(head="c" * 64, length=5, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(tmp_path), TEST_KEY)
    assert stored is not None
    assert stored.total_length == 5


def test_the_write_side_floor_is_the_total_not_the_active_length(tmp_path: Path) -> None:
    """The high-water mark is the only floor once the anchor file is gone.

    Recording the ACTIVE length there left the mutation undetected: after a prune the mark
    would fall to the active count and a truncating write would then be accepted.
    """
    write_anchor(str(tmp_path), Anchor(head="e" * 64, length=10, key_id=TEST_KEY_ID), TEST_KEY)
    pruned = Anchor(head="e" * 64, length=10, key_id=TEST_KEY_ID).after_prune(
        kept=2, pruned_head="a" * 64
    )
    write_anchor(str(tmp_path), pruned, TEST_KEY)

    # Remove the anchor AND the marker, so only the in-process mark can refuse the next
    # write. With the marker present the write is refused earlier, by the deletion guard.
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    anchor_module.marker_path(str(tmp_path)).unlink()
    with pytest.raises(AnchorError, match="entries ever over one recording 10"):
        write_anchor(str(tmp_path), Anchor(head="f" * 64, length=3, key_id=TEST_KEY_ID), TEST_KEY)


def test_deleting_only_the_anchor_refuses_the_next_write(tmp_path: Path) -> None:
    """The write path must agree with the read path about the deletion alarm.

    `read_anchor` treats "anchor gone, marker valid" as a hard alarm, and the write path
    used to fail open on exactly that state: one deletion, then the next write laid down a
    clean genesis anchor, so a single `rm` produced a state indistinguishable from a fresh
    install. The module claims the marker raises the cost to two deletions; this is what
    makes that true.
    """
    write_anchor(str(tmp_path), Anchor(head="e" * 64, length=4, key_id=TEST_KEY_ID), TEST_KEY)
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    anchor_module.reset_high_water_mark()

    with pytest.raises(AnchorError, match="has been used before"):
        write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)

    # And the deliberate operator re-anchor is still available.
    write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY, allow_shortening=True)


def test_an_anchor_with_nothing_archived_must_carry_the_genesis_boundary() -> None:
    with pytest.raises(AnchorError, match="must carry the genesis boundary"):
        Anchor(head="a" * 64, length=3, key_id=TEST_KEY_ID, total_length=3, pruned_head="b" * 64)


def test_a_failed_marker_write_leaves_no_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The marker write has the same cleanup contract as the anchor write."""
    write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    real_replace = Path.replace
    calls: list[int] = []

    def explode_on_marker(self: Path, target: Path) -> None:
        calls.append(1)
        if anchor_module.MARKER_FILENAME in str(target):
            raise OSError("marker write refused")
        real_replace(self, target)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "replace", explode_on_marker)
    with pytest.raises(OSError, match="marker write refused"):
        write_anchor(str(tmp_path), Anchor(head="a" * 64, length=1, key_id=TEST_KEY_ID), TEST_KEY)
    monkeypatch.undo()
    assert not list(tmp_path.glob(".marker-*.tmp"))


def test_a_lenient_read_of_a_corrupt_anchor_returns_nothing(tmp_path: Path) -> None:
    """The lenient path still exists for the regression guard's own bookkeeping.

    It is reached only when the anchor file is absent, so a corrupt file raises rather than
    being ignored. This pins the branch so it cannot quietly become the strict path's
    fallback again.
    """
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text("not json", encoding="utf-8")
    assert anchor_module._read_stored(str(tmp_path), TEST_KEY, strict=False) is None

    planted = Anchor(head="f" * 64, length=9, key_id=TEST_KEY_ID)
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(
        planted.as_json(OTHER_KEY), encoding="utf-8"
    )
    assert anchor_module._read_stored(str(tmp_path), TEST_KEY, strict=False) is None


def test_a_re_anchor_on_a_virgin_volume_carries_nothing(tmp_path: Path) -> None:
    assert (
        anchor_module.re_anchor(
            str(tmp_path), outgoing_key=TEST_KEY, incoming_key=ROTATED_KEY, expected_total=0
        )
        is None
    )


def test_a_re_anchor_cannot_be_driven_by_the_wrong_outgoing_key(tmp_path: Path) -> None:
    """Otherwise it is a way to launder a forged anchor onto the current key."""
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=5, key_id=TEST_KEY_ID), TEST_KEY)
    with pytest.raises(AnchorError, match="not authenticated under the current signing key"):
        anchor_module.re_anchor(
            str(tmp_path), outgoing_key=OTHER_KEY, incoming_key=ROTATED_KEY, expected_total=5
        )


def test_a_re_anchor_preserves_the_archive_boundary(tmp_path: Path) -> None:
    pruned = Anchor(
        head="e" * 64, length=3, key_id=TEST_KEY_ID, total_length=12, pruned_head="c" * 64
    )
    write_anchor(str(tmp_path), pruned, TEST_KEY)
    carried = anchor_module.re_anchor(
        str(tmp_path), outgoing_key=TEST_KEY, incoming_key=ROTATED_KEY, expected_total=12
    )
    assert carried == pruned
    assert read_anchor(str(tmp_path), ROTATED_KEY) == pruned


def test_a_re_anchor_refuses_a_shortened_anchor(tmp_path: Path) -> None:
    """The hole this parameter exists to close, and it was a real one.

    An attacker holding the leaked OUTGOING key plus volume write plants a short forgery.
    Rotation is the documented response to a possibly-leaked key, so the operator then runs
    the re-anchor step and certifies the forgery under the new key. Measured before the fix:
    the record fell from nine entries to two, the invented log verified clean, and no alarm
    fired. The floor cannot come from the volume, because the volume is what the attacker
    controls.
    """
    write_anchor(str(tmp_path), Anchor(head="e" * 64, length=9, key_id=TEST_KEY_ID), TEST_KEY)

    # The forgery: genuine-looking, correctly signed under the outgoing key, but short.
    short = Anchor(head="f" * 64, length=2, key_id=TEST_KEY_ID)
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(short.as_json(TEST_KEY), encoding="utf-8")
    anchor_module.marker_path(str(tmp_path)).write_text(
        anchor_module._marker_tag(str(tmp_path), TEST_KEY), encoding="utf-8"
    )
    anchor_module.reset_high_water_mark()

    with pytest.raises(AnchorError, match="shortened or replaced under the outgoing key"):
        anchor_module.re_anchor(
            str(tmp_path), outgoing_key=TEST_KEY, incoming_key=ROTATED_KEY, expected_total=9
        )

    # And it stays unreadable under the new key, so nothing was laundered.
    with pytest.raises(AnchorError, match="not authenticated under the current signing key"):
        read_anchor(str(tmp_path), ROTATED_KEY)


def test_a_re_anchor_refuses_a_removed_anchor_that_should_exist(tmp_path: Path) -> None:
    """Deleting the anchor must not read as "nothing to carry" during a rotation."""
    write_anchor(str(tmp_path), Anchor(head="e" * 64, length=4, key_id=TEST_KEY_ID), TEST_KEY)
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    anchor_module.marker_path(str(tmp_path)).unlink()
    anchor_module.reset_high_water_mark()

    with pytest.raises(AnchorError, match="entries were expected"):
        anchor_module.re_anchor(
            str(tmp_path), outgoing_key=TEST_KEY, incoming_key=ROTATED_KEY, expected_total=4
        )


def test_a_re_anchor_accepts_a_longer_record_than_expected(tmp_path: Path) -> None:
    """The off-volume figure is a FLOOR, not an equality: entries are added between exports."""
    write_anchor(str(tmp_path), Anchor(head="e" * 64, length=9, key_id=TEST_KEY_ID), TEST_KEY)
    carried = anchor_module.re_anchor(
        str(tmp_path), outgoing_key=TEST_KEY, incoming_key=ROTATED_KEY, expected_total=6
    )
    assert carried is not None
    assert carried.total_length == 9


def test_a_negative_expected_total_is_refused(tmp_path: Path) -> None:
    with pytest.raises(AnchorError, match="cannot be negative"):
        anchor_module.re_anchor(
            str(tmp_path), outgoing_key=TEST_KEY, incoming_key=ROTATED_KEY, expected_total=-1
        )


@pytest.mark.parametrize(
    ("label", "payload"),
    [
        ("non-ASCII", "é" * 64),
        ("invalid UTF-8", b"\xff\xfe" * 32),
        ("not a digest", "planted by somebody without a key"),
        ("oversize", "a" * (anchor_module.MAXIMUM_ANCHOR_BYTES + 1)),
        ("empty", ""),
    ],
)
def test_a_hostile_marker_never_raises_out_of_the_read_or_the_write(
    tmp_path: Path, label: str, payload: str | bytes
) -> None:
    """The marker got the authentication tag and not the fail-closed guard.

    `hmac.compare_digest` raises TypeError on a non-ASCII string and `read_text` raises
    UnicodeDecodeError on invalid UTF-8, and neither was caught, so one hostile byte turned
    the tamper alarm into an unhandled exception out of BOTH `read_anchor` and the write
    guard. Since no register mutation may happen without an audit entry, a one-byte file
    denied the whole write path and returned a 500 instead of a diagnosis. This is the same
    bug class already fixed for the anchor's own tag.
    """
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=2, key_id=TEST_KEY_ID), TEST_KEY)
    marker = anchor_module.marker_path(str(tmp_path))
    if isinstance(payload, bytes):
        marker.write_bytes(payload)
    else:
        marker.write_text(payload, encoding="utf-8")

    # A genuine anchor still reads, and the marker is repaired on the way past.
    stored = read_anchor(str(tmp_path), TEST_KEY)
    assert stored is not None, f"{label}: a hostile marker must not deny a genuine anchor"

    # And with the anchor gone, the write guard gives a verdict rather than an exception.
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    marker.write_bytes(payload) if isinstance(payload, bytes) else marker.write_text(
        payload, encoding="utf-8"
    )
    anchor_module.reset_high_water_mark()
    write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)


def test_the_marker_is_not_consulted_without_a_key(tmp_path: Path) -> None:
    """No key means cannot verify, which fails closed as "no valid marker"."""
    write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    assert anchor_module._marker_is_valid(str(tmp_path), b"") is False


def test_an_access_fault_beside_a_marker_is_interference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A read that failed is interference, whatever kind of failure it was.

    The classification arm for OSError was split back out once and survived the suite,
    because `_refuse_irregular` catches the shapes a test can easily create (a directory, a
    pipe, a symlink) before the open ever happens. A permissions or device fault reaching
    the open itself is only producible by injection here, since the suite runs as root and
    root ignores the mode bits, so it is injected rather than left uncovered.
    """
    key = bytes(range(32))
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=1, key_id="k1", total_length=1), key)

    real = Path.read_text

    def refuse(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "audit-anchor.json":
            raise PermissionError(13, "Permission denied")
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", refuse)
    with pytest.raises(AnchorTamperError, match="could not be read although"):
        read_anchor(str(tmp_path), key)


def test_an_access_fault_with_no_marker_stays_a_fault(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without the marker nothing says the log was used, so it is a fault to diagnose.

    The recorded limit of the state rule, asserted so it cannot quietly become an alarm.
    """
    key = bytes(range(32))
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=1, key_id="k1", total_length=1), key)
    marker_path(str(tmp_path)).unlink()

    real = Path.read_text

    def refuse(self: Path, *args: object, **kwargs: object) -> str:
        if self.name == "audit-anchor.json":
            raise PermissionError(13, "Permission denied")
        return real(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "read_text", refuse)
    with pytest.raises(AnchorError, match="could not be read") as raised:
        read_anchor(str(tmp_path), key)
    assert not isinstance(raised.value, AnchorTamperError)
