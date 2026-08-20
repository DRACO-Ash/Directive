"""Health, readiness, and diagnostics tests, driven in-process through the factory."""

from __future__ import annotations

import errno
import os
import time
from pathlib import Path

import pytest

from complyops.views import health

#: A read-only directory does not stop the root user, so the two permission-denied
#: assertions below are skipped when the suite runs as root and are honest skips, never
#: silent passes. They are real on the container (UID 10001) and on the CI runner.
running_as_root = os.geteuid() == 0
needs_non_root = pytest.mark.skipif(
    running_as_root, reason="a read-only directory does not deny the root user"
)


def test_root_returns_200_and_never_redirects(client) -> None:
    """The platform router probes GET / and treats a redirect as unhealthy."""
    response = client.get("/")
    assert response.status_code == 200
    assert "Location" not in response.headers


@pytest.mark.parametrize("path", ["/livez", "/ping", "/health"])
def test_liveness_paths_return_200_unauthenticated(client, path: str) -> None:
    response = client.get(path)
    assert response.status_code == 200
    assert response.data == b"ok\n"


def test_liveness_does_not_depend_on_storage(client, monkeypatch: pytest.MonkeyPatch) -> None:
    """A liveness probe that checks a downstream restarts a healthy container."""

    def explode(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("liveness must not touch storage")

    monkeypatch.setattr(health, "probe_storage", explode)
    assert client.get("/livez").status_code == 200


def test_readiness_returns_200_when_storage_accepts_a_write(client) -> None:
    response = client.get("/readyz")
    assert response.status_code == 200
    assert response.get_json()["ready"] is True


@needs_non_root
def test_readiness_returns_503_with_the_path_and_errno_when_storage_refuses(
    client, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    read_only = tmp_path / "read-only"
    read_only.mkdir()
    read_only.chmod(0o500)
    monkeypatch.setenv("DATA_DIR", str(read_only))
    try:
        response = client.get("/readyz")
        body = response.get_json()
        assert response.status_code == 503
        assert body["ready"] is False
        assert body["dataDir"] == str(read_only)
        assert body["errno"] == errno.EACCES
        assert body["detail"] == "EACCES"
    finally:
        read_only.chmod(0o700)


def test_readiness_fails_closed_on_a_path_that_is_not_absolute(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DATA_DIR", "relative/data")
    response = client.get("/readyz")
    assert response.status_code == 503
    assert "not absolute" in response.get_json()["detail"]


@needs_non_root
def test_the_storage_probe_proves_a_write_rather_than_existence(tmp_path: Path) -> None:
    """Prove a write, never mere existence.

    Mkdir on an existing directory succeeds without write permission, so only a real
    write distinguishes a usable mount from a root-owned one.
    """
    read_only = tmp_path / "ro"
    read_only.mkdir()
    read_only.chmod(0o500)
    try:
        verdict = health.probe_storage(str(read_only))
        assert verdict.writable is False
        assert verdict.errno == errno.EACCES
    finally:
        read_only.chmod(0o700)


def test_the_storage_probe_leaves_no_file_behind(tmp_path: Path) -> None:
    verdict = health.probe_storage(str(tmp_path))
    assert verdict.writable is True
    assert list(tmp_path.iterdir()) == []


def test_the_storage_probe_races_a_hard_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stalled mount must fail the probe with a diagnosis, never hang it."""

    def stall(_path: str) -> health.StorageVerdict:
        time.sleep(5)
        raise AssertionError("the probe should have timed out before this line")

    monkeypatch.setattr(health, "_write_probe", stall)
    verdict = health.probe_storage(str(tmp_path), timeout_seconds=0.05)
    assert verdict.writable is False
    assert verdict.errno == errno.ETIMEDOUT
    assert "0.05 seconds" in (verdict.detail or "")


def test_the_probe_creates_the_directory_when_it_is_absent(tmp_path: Path) -> None:
    target = tmp_path / "not-yet"
    verdict = health.probe_storage(str(target))
    assert verdict.writable is True
    assert target.is_dir()


def test_the_verdict_log_line_states_the_outcome(tmp_path: Path) -> None:
    good = health.probe_storage(str(tmp_path))
    assert "accepted a write" in good.log_line()
    bad = health.StorageVerdict(writable=False, path="/data", errno=13, detail="EACCES")
    assert "refused a write at /data" in bad.log_line()
    assert "errno=13" in bad.log_line()


def test_diagnostics_reports_presence_and_length_never_the_value(
    client, monkeypatch: pytest.MonkeyPatch
) -> None:
    injected = "a-client-credential-value-that-must-not-leak"
    monkeypatch.setenv("CLIENT_SECRET", injected)
    monkeypatch.setenv("BUILD_ID", "sha-abc123")
    response = client.get("/api/diagnostics")
    body = response.get_json()

    assert response.status_code == 200
    assert body["inputs"]["CLIENT_SECRET"] == {"present": True, "length": len(injected)}
    assert body["inputs"]["TENANT_ID"] == {"present": False, "length": 0}
    assert body["buildId"] == "sha-abc123"
    assert body["storageWritable"] is True
    assert injected not in response.get_data(as_text=True)


def test_diagnostics_covers_every_critical_input(client) -> None:
    body = client.get("/api/diagnostics").get_json()
    assert set(body["inputs"]) == set(health.CRITICAL_INPUTS)


def test_the_probe_timeout_is_shorter_than_a_platform_probe() -> None:
    """The platform kills a hanging probe silently, so ours must fail first."""
    assert 0 < health.PROBE_TIMEOUT_SECONDS < 10


def test_the_probe_reports_the_errno_when_a_path_component_is_a_file(tmp_path: Path) -> None:
    """A misconfigured mount path is reported by errno, not swallowed as a crash."""
    blocker = tmp_path / "a-file"
    blocker.write_text("not a directory", encoding="utf-8")
    verdict = health.probe_storage(str(blocker / "below"))
    assert verdict.writable is False
    assert verdict.errno == errno.ENOTDIR
    assert verdict.detail == "ENOTDIR"
