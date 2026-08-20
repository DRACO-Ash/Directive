"""Factory tests: the app is built without listening, and boot states its verdict."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from complyops import create_app


def test_the_factory_returns_an_app_without_listening(writable_data_dir: Path) -> None:
    app = create_app()
    assert app.name == "complyops"
    assert writable_data_dir.is_dir()


def test_boot_logs_that_storage_accepted_a_write(
    writable_data_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO):
        create_app()
    assert any("storage accepted a write" in record.getMessage() for record in caplog.records)


def test_boot_warns_loudly_when_storage_is_unusable(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """An unusable mount must leave a narrative, not a bare "listening" line."""
    monkeypatch.setenv("DATA_DIR", "relative/data")
    with caplog.at_level(logging.WARNING):
        create_app()
    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert warnings
    assert "storage refused a write" in (warnings[-1].getMessage())
