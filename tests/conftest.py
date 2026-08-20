"""Test configuration: put the src layout on the path and isolate the environment."""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

#: Every variable the app reads. Cleared per test so one test cannot leak into another
#: and so a value on the developer's machine cannot make a test pass spuriously.
MANAGED_VARIABLES = (
    "PORT",
    "DATA_DIR",
    "STORAGE_MOUNT_PATH",
    "BUILD_ID",
    "LOG_VIEW_EVENTS",
    "TENANT_ID",
    "CLIENT_ID",
    "CLIENT_SECRET",
    "SESSION_KEY",
    "SHAREPOINT_SITE_ID",
    "REDIRECT_URI",
)


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove every managed variable before each test."""
    for name in MANAGED_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    yield


@pytest.fixture()
def writable_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point the app at a writable temporary data directory."""
    target = tmp_path / "data"
    target.mkdir()
    monkeypatch.setenv("DATA_DIR", str(target))
    return target


@pytest.fixture()
def client(writable_data_dir: Path):
    """Return a Flask test client mounted in-process against a writable data directory."""
    # Imported here, not at module scope: the sys.path insert above must run first.
    from complyops import create_app  # noqa: PLC0415

    app = create_app()
    app.config.update(TESTING=True)
    with app.test_client() as test_client:
        yield test_client


def fixed_entry(index: int = 1) -> dict[str, str]:
    """Return a deterministic set of covered fields. Time is passed in, never read."""
    return {
        "timestamp": f"2026-08-20T09:0{index}:00Z",
        "actor": "ash.higgins@bluestaq.uk",
        "action": "TASK_COMPLETE",
        "resource": "lst-Tasks",
        "resource_id": f"D-0{index}",
    }
