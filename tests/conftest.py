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
    "AUDIT_HMAC_KEY",
    "AUDIT_KEY_ID",
    "AUDIT_RETIRED_KEYS",
)

#: A test signing key, as the application requires it: real key material decoding to at
#: least 32 bytes. Deterministic and published in this file on purpose, so it is not a
#: credential and the secret scanner has nothing to flag.
TEST_KEY_HEX = bytes(range(32)).hex()
TEST_KEY = bytes.fromhex(TEST_KEY_HEX)
TEST_KEY_ID = "test-k1"


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove every managed variable and clear process state before each test."""
    from complyops.audit import anchor  # noqa: PLC0415 - after the sys.path insert
    from complyops.views import health  # noqa: PLC0415 - after the sys.path insert

    for name in MANAGED_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    anchor.reset_high_water_mark()
    health.reset_diagnostics_cache()
    health.reset_probe_registry()
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
        "timestamp": f"2026-08-20T09:{index:02d}:00Z",
        "actor": "ash.higgins@bluestaq.uk",
        "action": "TASK_COMPLETE",
        "resource": "lst-Tasks",
        "resource_id": f"D-{index:02d}",
    }


def new_chain(anchor: object = None) -> object:
    """Return a chain signed with the suite's test key."""
    from complyops.audit import AuditChain  # noqa: PLC0415 - after the sys.path insert

    return AuditChain(anchor, key=TEST_KEY, key_id=TEST_KEY_ID)


def anchored(chain: object) -> object:
    """Return the chain's current anchor."""
    return chain.anchor()


def keys_for_verification() -> dict[str, bytes]:
    """Return the verification key mapping for the suite's test key.

    Deliberately not named with a ``test_`` prefix: pytest would collect it as a test.
    """
    return {TEST_KEY_ID: TEST_KEY}
