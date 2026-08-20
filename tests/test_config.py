"""Configuration tests: normalisation, the port contract, and path resolution."""

from __future__ import annotations

import pytest

from complyops import config


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("  /data  ", "/data"),
        ('"/data"', "/data"),
        ("'/data'", "/data"),
        ("/data\n", "/data"),
        ("/da\tta", "/data"),
        ("/data\r\n", "/data"),
        (None, ""),
        ("", ""),
    ],
)
def test_normalise_strips_console_noise(raw: str | None, expected: str) -> None:
    assert config.normalise(raw) == expected


def test_env_returns_the_default_when_the_variable_is_blank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BUILD_ID", "   ")
    assert config.env("BUILD_ID", "unknown") == "unknown"


def test_port_defaults_to_the_platform_port() -> None:
    assert config.port() == config.DEFAULT_PORT == 8080


@pytest.mark.parametrize("value", ["3000", "8080", "1", "65535"])
def test_port_honours_an_injected_value(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("PORT", value)
    assert config.port() == int(value)


@pytest.mark.parametrize("value", ["0", "65536", "-1", "eighty-eighty", "80.5", ""])
def test_port_falls_back_on_an_unusable_value(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv("PORT", value)
    assert config.port() == config.DEFAULT_PORT


def test_data_dir_prefers_the_explicit_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATA_DIR", "/explicit")
    monkeypatch.setenv("STORAGE_MOUNT_PATH", "/injected")
    assert config.data_dir() == "/explicit"


def test_data_dir_falls_back_to_the_injected_variable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STORAGE_MOUNT_PATH", "/injected")
    assert config.data_dir() == "/injected"


def test_data_dir_defaults_when_nothing_is_injected() -> None:
    assert config.data_dir() == config.DEFAULT_DATA_DIR == "/data"


@pytest.mark.parametrize(
    ("path", "fragment"),
    [
        ("", "no data directory"),
        ("relative/path", "not absolute"),
        ("/", "filesystem root"),
        ("//", "filesystem root"),
    ],
)
def test_validate_data_dir_rejects_an_unusable_path(path: str, fragment: str) -> None:
    reason = config.validate_data_dir(path)
    assert reason is not None
    assert fragment in reason


def test_validate_data_dir_accepts_an_absolute_path() -> None:
    assert config.validate_data_dir("/data") is None


def test_settings_snapshot_reads_the_current_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("BUILD_ID", "abc123")
    monkeypatch.setenv("DATA_DIR", "/srv/data")
    monkeypatch.setenv("PORT", "8080")
    settings = config.Settings.from_environment()
    assert settings.build_id == "abc123"
    assert settings.data_dir == "/srv/data"
    assert settings.port == 8080
    assert settings.log_view_events is False


@pytest.mark.parametrize(
    ("value", "expected"),
    [("true", True), ("TRUE", True), ("false", False), ("1", False), ("", False)],
)
def test_view_event_logging_is_off_unless_explicitly_enabled(
    monkeypatch: pytest.MonkeyPatch, value: str, expected: bool
) -> None:
    """Data minimisation is the default: only the exact string "true" turns it on."""
    monkeypatch.setenv("LOG_VIEW_EVENTS", value)
    assert config.Settings.from_environment().log_view_events is expected
