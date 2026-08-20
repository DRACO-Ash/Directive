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

    assert len(captured) == 2
    assert captured[0] != captured[1]
    assert all(Path(path).parent == tmp_path for path in captured)


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
