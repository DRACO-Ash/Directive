"""Anchor tests: the outside reference that catches a wholesale rewrite."""

from __future__ import annotations

from pathlib import Path

import pytest

from complyops.audit import anchor as anchor_module
from complyops.audit.anchor import Anchor, AnchorError, read_anchor, write_anchor
from complyops.audit.hashing import GENESIS_HASH


def test_no_anchor_yet_reads_as_none(tmp_path: Path) -> None:
    assert read_anchor(str(tmp_path)) is None


def test_an_anchor_round_trips(tmp_path: Path) -> None:
    written = Anchor(head="a" * 64, length=42, key_id="k1")
    write_anchor(str(tmp_path), written)
    assert read_anchor(str(tmp_path)) == written


def test_the_genesis_anchor_describes_an_empty_log() -> None:
    assert Anchor.genesis("k1") == Anchor(head=GENESIS_HASH, length=0, key_id="k1")


def test_the_write_is_atomic_and_leaves_no_temporary_file(tmp_path: Path) -> None:
    """Temp file then rename, so a crash never leaves a half-written anchor."""
    write_anchor(str(tmp_path), Anchor(head="b" * 64, length=1, key_id="k1"))
    assert [path.name for path in tmp_path.iterdir()] == [anchor_module.ANCHOR_FILENAME]


def test_a_later_write_replaces_the_earlier_one(tmp_path: Path) -> None:
    write_anchor(str(tmp_path), Anchor(head="b" * 64, length=1, key_id="k1"))
    write_anchor(str(tmp_path), Anchor(head="c" * 64, length=2, key_id="k1"))
    stored = read_anchor(str(tmp_path))
    assert stored is not None
    assert (stored.head, stored.length) == ("c" * 64, 2)


def test_the_anchor_is_created_when_the_directory_does_not_exist(tmp_path: Path) -> None:
    target = tmp_path / "not-yet"
    write_anchor(str(target), Anchor.genesis("k1"))
    assert read_anchor(str(target)) == Anchor.genesis("k1")


@pytest.mark.parametrize(
    "contents",
    [
        "not json at all",
        "{}",
        '{"head": "short", "length": 1, "keyId": "k1"}',
        '{"head": "' + "a" * 64 + '", "length": -1, "keyId": "k1"}',
        '{"head": "' + "a" * 64 + '", "length": "many", "keyId": "k1"}',
        '{"head": "' + "a" * 64 + '", "length": 1}',
    ],
)
def test_a_corrupt_anchor_fails_closed_rather_than_reading_as_absent(
    tmp_path: Path, contents: str
) -> None:
    """Treating a corrupt anchor as "no anchor yet" would drop the only rewrite control."""
    (tmp_path / anchor_module.ANCHOR_FILENAME).write_text(contents, encoding="utf-8")
    with pytest.raises(AnchorError):
        read_anchor(str(tmp_path))
