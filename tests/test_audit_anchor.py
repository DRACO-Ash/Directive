"""Anchor tests: the outside reference that catches a wholesale rewrite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from complyops.audit import anchor as anchor_module
from complyops.audit.anchor import Anchor, AnchorError, read_anchor, write_anchor
from complyops.audit.hashing import GENESIS_HASH
from conftest import TEST_KEY, TEST_KEY_ID

OTHER_KEY = bytes.fromhex("cd" * 32)
KEYS = {TEST_KEY_ID: TEST_KEY}


def test_a_log_never_used_reads_as_no_anchor(tmp_path: Path) -> None:
    assert read_anchor(str(tmp_path), KEYS) is None


def test_an_anchor_round_trips(tmp_path: Path) -> None:
    written = Anchor(head="a" * 64, length=42, key_id=TEST_KEY_ID)
    write_anchor(str(tmp_path), written, TEST_KEY)
    assert read_anchor(str(tmp_path), KEYS) == written


def test_the_genesis_anchor_describes_an_empty_log() -> None:
    assert Anchor.genesis(TEST_KEY_ID) == Anchor(head=GENESIS_HASH, length=0, key_id=TEST_KEY_ID)


def test_the_anchor_is_authenticated_so_it_cannot_be_forged_without_the_key(
    tmp_path: Path,
) -> None:
    """The attack this closes needs no access to the SharePoint list at all.

    An actor with write access to the volume replays an earlier entry's genuine digest
    into the anchor, and a truncated log then verifies as intact. The authentication tag
    means writing an anchor requires the signing key.
    """
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=6, key_id=TEST_KEY_ID), TEST_KEY)
    stored = json.loads((tmp_path / anchor_module.ANCHOR_FILENAME).read_text(encoding="utf-8"))

    stored["length"] = 2
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(json.dumps(stored), encoding="utf-8")
    with pytest.raises(AnchorError, match="not authenticated"):
        read_anchor(str(tmp_path), KEYS)


def test_an_anchor_written_under_a_different_key_is_refused(tmp_path: Path) -> None:
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=1, key_id=TEST_KEY_ID), OTHER_KEY)
    with pytest.raises(AnchorError, match="not authenticated"):
        read_anchor(str(tmp_path), KEYS)


def test_a_deleted_anchor_is_a_tamper_alarm_not_a_fresh_install(tmp_path: Path) -> None:
    """One `rm` previously removed the only truncation control silently."""
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=6, key_id=TEST_KEY_ID), TEST_KEY)
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    with pytest.raises(AnchorError, match="deleted"):
        read_anchor(str(tmp_path), KEYS)


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

    assert len(captured) == 2
    assert captured[0] != captured[1]
    assert all(Path(path).parent == tmp_path for path in captured)


def test_a_later_write_replaces_the_earlier_one(tmp_path: Path) -> None:
    write_anchor(str(tmp_path), Anchor(head="b" * 64, length=1, key_id=TEST_KEY_ID), TEST_KEY)
    write_anchor(str(tmp_path), Anchor(head="c" * 64, length=2, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(tmp_path), KEYS)
    assert stored is not None
    assert (stored.head, stored.length) == ("c" * 64, 2)


def test_the_anchor_is_created_when_the_directory_does_not_exist(tmp_path: Path) -> None:
    target = tmp_path / "not-yet"
    write_anchor(str(target), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    assert read_anchor(str(target), KEYS) == Anchor.genesis(TEST_KEY_ID)


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
        read_anchor(str(tmp_path), KEYS)


def test_a_boolean_length_is_refused(tmp_path: Path) -> None:
    """`isinstance(True, int)` is True, so `length=true` would match a one-entry log."""
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(
        signed({"schemaVersion": 1, "head": "a" * 64, "length": True, "keyId": "k1"}),
        encoding="utf-8",
    )
    with pytest.raises(AnchorError, match="not a usable anchor"):
        read_anchor(str(tmp_path), KEYS)


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
        read_anchor(str(tmp_path), KEYS)


def test_the_high_water_mark_is_per_data_directory(tmp_path: Path) -> None:
    anchor_module.reset_high_water_mark()
    first, second = tmp_path / "one", tmp_path / "two"
    write_anchor(str(first), Anchor(head="a" * 64, length=9, key_id=TEST_KEY_ID), TEST_KEY)
    write_anchor(str(second), Anchor(head="b" * 64, length=1, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(second), KEYS)
    assert stored is not None
    assert stored.length == 1


def test_growing_the_log_is_not_a_rollback(tmp_path: Path) -> None:
    """The boundary in the other direction, or the check asserts nothing."""
    anchor_module.reset_high_water_mark()
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=3, key_id=TEST_KEY_ID), TEST_KEY)
    assert read_anchor(str(tmp_path), KEYS) is not None
    write_anchor(str(tmp_path), Anchor(head="b" * 64, length=4, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(tmp_path), KEYS)
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
        read_anchor(str(tmp_path), KEYS)


ROTATED_KEY = bytes(range(16)) + bytes(range(240, 256))
ROTATED_KEYS = {TEST_KEY_ID: TEST_KEY, "k2": ROTATED_KEY}


def test_an_anchor_written_before_a_rotation_still_authenticates_after_it(
    tmp_path: Path,
) -> None:
    """Verifying under the current key alone accused the volume over clean evidence.

    Worse, the only recovery was to re-anchor, and the trusted head and length were
    obtainable only from the anchor being refused, so the fail-closed control had no way
    back that did not itself depend on the thing that failed.
    """
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=3, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(tmp_path), ROTATED_KEYS)
    assert stored is not None
    assert stored.length == 3


def test_an_anchor_written_under_no_held_key_is_still_refused(tmp_path: Path) -> None:
    """Accepting any held key must not become accepting any key at all."""
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=1, key_id=TEST_KEY_ID), OTHER_KEY)
    with pytest.raises(AnchorError, match="not authenticated under any key still held"):
        read_anchor(str(tmp_path), ROTATED_KEYS)


def test_a_write_that_would_shorten_the_record_is_refused(tmp_path: Path) -> None:
    """One bad write used to destroy the durable head irrecoverably.

    The high-water mark only guarded reads and only ever rose, so the process refused to
    read back an anchor it had itself overwritten, and the true head was gone for good.
    """
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=9, key_id=TEST_KEY_ID), TEST_KEY)
    with pytest.raises(AnchorError, match="would destroy the durable head"):
        write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)

    stored = read_anchor(str(tmp_path), KEYS)
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
    stored = read_anchor(str(tmp_path), KEYS)
    assert stored is not None
    assert stored.length == 4


def test_growing_the_record_is_not_a_regression(tmp_path: Path) -> None:
    """The boundary in the other direction, or the guard asserts nothing."""
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=4, key_id=TEST_KEY_ID), TEST_KEY)
    write_anchor(str(tmp_path), Anchor(head="b" * 64, length=4, key_id=TEST_KEY_ID), TEST_KEY)
    write_anchor(str(tmp_path), Anchor(head="c" * 64, length=5, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(tmp_path), KEYS)
    assert stored is not None
    assert stored.length == 5


def test_a_planted_marker_cannot_wedge_the_audit_path(tmp_path: Path) -> None:
    """One touch by an actor with no key used to deny the whole write path permanently.

    Every read raised "it was deleted", with no code path to clear it, and nothing in the
    documentation told an operator that deleting the file the alarm names was the fix.
    """
    marker = tmp_path / anchor_module.MARKER_FILENAME
    marker.write_text("planted by somebody without a key", encoding="utf-8")
    assert read_anchor(str(tmp_path), KEYS) is None

    marker.write_text("", encoding="utf-8")
    assert read_anchor(str(tmp_path), KEYS) is None


def test_a_marker_from_another_volume_does_not_count(tmp_path: Path) -> None:
    """The tag is bound to the directory, so a genuine marker cannot be copied across."""
    other = tmp_path / "elsewhere"
    other.mkdir()
    write_anchor(str(other), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    copied = (other / anchor_module.MARKER_FILENAME).read_text(encoding="utf-8")
    (tmp_path / anchor_module.MARKER_FILENAME).write_text(copied, encoding="utf-8")
    assert read_anchor(str(tmp_path), KEYS) is None


def test_the_marker_exists_whenever_an_anchor_does(tmp_path: Path) -> None:
    """The marker is written before the rename, so the alarm cannot be silently disarmed.

    A kill between the rename and the marker used to leave an anchor with no marker, and
    deleting the anchor then read as a fresh install.
    """
    write_anchor(str(tmp_path), Anchor.genesis(TEST_KEY_ID), TEST_KEY)
    assert (tmp_path / anchor_module.MARKER_FILENAME).exists()
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    with pytest.raises(AnchorError, match="deleted"):
        read_anchor(str(tmp_path), KEYS)


def test_a_deletion_alarm_survives_a_key_rotation(tmp_path: Path) -> None:
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=2, key_id=TEST_KEY_ID), TEST_KEY)
    (tmp_path / anchor_module.ANCHOR_FILENAME).unlink()
    with pytest.raises(AnchorError, match="deleted"):
        read_anchor(str(tmp_path), ROTATED_KEYS)


def test_an_unknown_schema_version_fails_closed(tmp_path: Path) -> None:
    """A rolling deploy can put two image versions on one volume."""
    later = Anchor(head="a" * 64, length=1, key_id=TEST_KEY_ID, schema_version=2)
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(later.as_json(TEST_KEY), encoding="utf-8")
    with pytest.raises(AnchorError, match="schema version 2"):
        read_anchor(str(tmp_path), KEYS)


def test_an_implausibly_large_anchor_is_refused_unread(tmp_path: Path) -> None:
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(
        "x" * (anchor_module.MAXIMUM_ANCHOR_BYTES + 1), encoding="utf-8"
    )
    with pytest.raises(AnchorError, match="implausibly large"):
        read_anchor(str(tmp_path), KEYS)


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
            read_anchor(str(tmp_path), KEYS)


def test_the_high_water_mark_ignores_how_the_path_is_spelt(tmp_path: Path) -> None:
    """The same directory spelt two ways used to be two separate marks."""
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=6, key_id=TEST_KEY_ID), TEST_KEY)
    assert read_anchor(str(tmp_path), KEYS) is not None
    write_anchor(
        str(tmp_path),
        Anchor(head="b" * 64, length=2, key_id=TEST_KEY_ID),
        TEST_KEY,
        allow_shortening=True,
    )
    with pytest.raises(AnchorError, match="older anchor was restored"):
        read_anchor(f"{tmp_path}/", KEYS)


@pytest.mark.parametrize("hostile", ["=cmd", "k 1", "k" * 33, "kéy"])
def test_an_anchor_naming_an_unusable_key_id_is_refused(tmp_path: Path, hostile: str) -> None:
    stored = json.loads(Anchor.genesis(TEST_KEY_ID).as_json(TEST_KEY))
    stored["keyId"] = hostile
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(json.dumps(stored), encoding="utf-8")
    with pytest.raises(AnchorError):
        read_anchor(str(tmp_path), KEYS)


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
    assert read_anchor(str(tmp_path), KEYS) is None


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


def test_the_regression_guard_ignores_an_unreadable_stored_anchor(tmp_path: Path) -> None:
    """A corrupt anchor must not block a legitimate write.

    The guard reads the stored anchor leniently: a document it cannot authenticate is not
    evidence of a longer log, so the high-water mark remains the floor.
    """
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text("not json", encoding="utf-8")
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=1, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(tmp_path), KEYS)
    assert stored is not None
    assert stored.length == 1


def test_the_regression_guard_ignores_an_unauthenticated_stored_anchor(tmp_path: Path) -> None:
    """A document written under no held key is not evidence of a longer log.

    Reading it strictly here would let an actor with volume write access and no key block
    every legitimate write by planting a longer, unauthenticated anchor.
    """
    planted = Anchor(head="f" * 64, length=99, key_id=TEST_KEY_ID)
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(
        planted.as_json(OTHER_KEY), encoding="utf-8"
    )
    write_anchor(str(tmp_path), Anchor(head="a" * 64, length=2, key_id=TEST_KEY_ID), TEST_KEY)
    stored = read_anchor(str(tmp_path), KEYS)
    assert stored is not None
    assert stored.length == 2
