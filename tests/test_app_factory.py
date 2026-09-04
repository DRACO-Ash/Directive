"""Factory tests: the app is built without listening, and boot states its verdict."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from complyops import create_app
from complyops.version import __version__


def test_the_factory_returns_an_app_without_listening(writable_data_dir: Path) -> None:
    app = create_app()
    assert app.name == "complyops"
    assert writable_data_dir.is_dir()


def test_the_static_folder_serves_the_console_assets(writable_data_dir: Path) -> None:
    """The console needs its stylesheet and script, so the static folder is enabled.

    It was disabled while the app served only health paths, on the principle that surface
    you do not need is surface you do not defend. Re-enabling it is a deliberate decision
    recorded here: the directory holds two authored files, `send_from_directory` refuses
    traversal, and nothing generated is served from it.
    """
    app = create_app()
    assert app.static_folder is not None
    assert Path(app.static_folder).name == "static"
    assert sorted(path.name for path in Path(app.static_folder).iterdir()) == [
        "console.css",
        "console.js",
    ]


@pytest.mark.parametrize(
    "traversal",
    ["../__init__.py", "..%2f__init__.py", "....//__init__.py", "%2e%2e/records.py"],
)
def test_the_static_route_refuses_traversal(writable_data_dir: Path, traversal: str) -> None:
    """The cost of re-enabling it, measured rather than assumed."""
    response = create_app().test_client().get(f"/static/{traversal}")
    assert response.status_code in {400, 404}
    assert b"complyops" not in response.data


def test_json_keys_are_not_reordered(writable_data_dir: Path) -> None:
    """Flask 3 reads app.json.sort_keys; the old config key is silently ignored."""
    assert create_app().json.sort_keys is False


def test_the_version_matches_the_project_manifest() -> None:
    """Pin the version against the project manifest.

    The two must not drift: the container never installs the project, so package
    metadata is unavailable at runtime and the constant is the only source.
    """
    import tomllib  # noqa: PLC0415 - only needed here

    manifest = Path(__file__).resolve().parents[1] / "pyproject.toml"
    with manifest.open("rb") as handle:
        assert tomllib.load(handle)["project"]["version"] == __version__


def test_boot_survives_a_probe_that_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A probe failure must never prevent boot.

    The diagnostics read-out is the recovery channel for a misconfigured value, so a
    fault while establishing the boot narrative must not take down the one endpoint
    that would explain it.
    """
    import complyops  # noqa: PLC0415 - patched on the module object

    monkeypatch.setenv("COMPLYOPS_ENV", "development")

    def explode(_path: str, *args: object, **kwargs: object) -> None:
        raise RuntimeError("the probe blew up")

    monkeypatch.setattr(complyops, "probe_storage", explode)
    app = create_app()
    with app.test_client() as client:
        assert client.get("/livez").status_code == 200


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
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    with caplog.at_level(logging.WARNING):
        create_app()
    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert warnings
    assert "storage refused a write" in (warnings[-1].getMessage())
