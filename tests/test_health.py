"""Health, readiness, and diagnostics tests, driven in-process through the factory."""

from __future__ import annotations

import errno
import json
import os
import threading
import time
from pathlib import Path

import pytest

from complyops.version import __version__
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


@pytest.mark.parametrize("path", ["/healthz", "/livez", "/ping", "/health"])
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
    """A stalled mount must fail the probe with a diagnosis, never hang it.

    The elapsed time is the assertion. Returning the right verdict only after the stall
    has finished is exactly the hang this control exists to prevent, and asserting the
    verdict alone cannot tell the two apart.
    """
    stall_seconds = 3.0
    timeout = 0.05

    def stall(_path: str) -> health.StorageVerdict:
        time.sleep(stall_seconds)
        raise AssertionError("the probe should have been abandoned before this line")

    monkeypatch.setattr(health, "_write_probe", stall)
    started = time.monotonic()
    verdict = health.probe_storage(str(tmp_path), timeout_seconds=timeout)
    elapsed = time.monotonic() - started

    assert verdict.writable is False
    assert verdict.errno == errno.ETIMEDOUT
    assert f"{timeout} seconds" in (verdict.detail or "")
    assert elapsed < timeout * 10, f"the probe took {elapsed:.2f}s against a {timeout}s timeout"
    assert elapsed < stall_seconds / 2, "the probe waited for the stalled write to finish"


def test_the_probe_contains_a_failure_that_is_not_an_os_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The recovery channel must survive any configuration value.

    A deeply nested path raises RecursionError out of pathlib. Uncaught it takes down
    readiness, diagnostics, and boot: the whole channel that would explain the fault.
    """

    def explode(_path: str) -> health.StorageVerdict:
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(health, "_write_probe", explode)
    verdict = health.probe_storage(str(tmp_path))
    assert verdict.writable is False
    assert verdict.detail == "RecursionError"


def test_a_deeply_nested_path_does_not_break_readiness_or_diagnostics(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATA_DIR", "/" + "/".join("x" * 4000))
    health.reset_diagnostics_cache()
    assert client.get("/readyz").status_code == 503
    assert client.get("/api/diagnostics").status_code == 200


def test_the_permission_denied_branch_is_reachable_without_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cover the EACCES path deterministically, whoever the suite runs as.

    The real-permission tests below are skipped as root, which left the write-proof
    control provable only on the CI runner. This asserts the same branch by making the
    write itself refuse, so it holds everywhere.
    """
    real_open = Path.open

    def refuse(self: Path, *args: object, **kwargs: object):  # noqa: ANN202
        if self.name.startswith(".readyz-"):
            raise PermissionError(errno.EACCES, "Permission denied")
        return real_open(self, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(Path, "open", refuse)
    verdict = health.probe_storage(str(tmp_path))
    assert verdict.writable is False
    assert verdict.errno == errno.EACCES
    assert verdict.detail == "EACCES"


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
    signed_in_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    injected = "a-client-credential-value-that-must-not-leak"
    monkeypatch.setenv("CLIENT_SECRET", injected)
    monkeypatch.setenv("BUILD_ID", "sha-abc123")
    response = signed_in_client.get("/api/diagnostics")
    body = response.get_json()

    assert response.status_code == 200
    assert body["inputs"]["CLIENT_SECRET"] == {"present": True, "lengthBucket": "32+"}
    assert body["inputs"]["TENANT_ID"] == {"present": False, "lengthBucket": "0"}
    assert body["buildId"] == "sha-abc123"
    assert body["version"] == __version__
    assert body["storageWritable"] is True
    assert injected not in response.get_data(as_text=True)
    # Scoped to the inputs block. Matching the exact length against the WHOLE body caught
    # the pytest temp directory ("/tmp/bt44/..."), which is a flake, not a leak.
    assert str(len(injected)) not in json.dumps(body["inputs"])


@pytest.mark.parametrize(
    ("length", "expected"),
    [(0, "0"), (1, "1-15"), (15, "1-15"), (16, "16-31"), (31, "16-31"), (32, "32+"), (99, "32+")],
)
def test_the_length_bucket_bands_rather_than_reveals(length: int, expected: str) -> None:
    """A band distinguishes a stale value from a correct one without an exact oracle."""
    assert health.length_bucket(length) == expected


def test_diagnostics_reuses_a_cached_verdict_rather_than_writing_per_request(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An unauthenticated route must not do real filesystem work on every request."""
    health.reset_diagnostics_cache()
    probes = []
    real = health.probe_storage

    def counting(path: str, *args: object, **kwargs: object) -> health.StorageVerdict:
        probes.append(path)
        return real(path, *args, **kwargs)

    monkeypatch.setattr(health, "probe_storage", counting)
    for _ in range(5):
        assert client.get("/api/diagnostics").status_code == 200
    assert len(probes) == 1


def test_the_cache_window_is_measured_from_after_the_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Stamping before the probe makes a served verdict older than the window claims.

    Every other test supplies the clock, which makes both orderings identical, so
    swapping the two lines back left the suite green: the fix asserted nothing.
    """
    probe_seconds = 0.4
    real = health._write_probe

    def slow(path: str) -> health.StorageVerdict:
        time.sleep(probe_seconds)
        return real(path)

    monkeypatch.setattr(health, "_write_probe", slow)
    health.reset_diagnostics_cache()
    started = time.monotonic()
    first = health.cached_storage_verdict(str(tmp_path))
    stamped_at = health._cached[0] if health._cached else 0.0

    assert first.writable is True
    assert stamped_at >= started + probe_seconds, (
        "the window was stamped before the probe, so the verdict is already "
        f"{stamped_at - started:.2f}s into its life when it is stored"
    )


def test_the_cached_verdict_expires(tmp_path: Path) -> None:
    health.reset_diagnostics_cache()
    first = health.cached_storage_verdict(str(tmp_path), now=1000.0)
    again = health.cached_storage_verdict(str(tmp_path), now=1000.0 + 1)
    later = health.cached_storage_verdict(
        str(tmp_path), now=1000.0 + health.DIAGNOSTICS_CACHE_SECONDS + 1
    )
    assert first is again
    assert later is not first


def test_the_cache_does_not_serve_a_verdict_for_a_different_path(tmp_path: Path) -> None:
    health.reset_diagnostics_cache()
    first = health.cached_storage_verdict(str(tmp_path), now=1000.0)
    other = health.cached_storage_verdict(str(tmp_path / "elsewhere"), now=1000.0)
    assert other is not first
    assert other.path != first.path


def test_diagnostics_covers_every_critical_input(signed_in_client) -> None:
    body = signed_in_client.get("/api/diagnostics").get_json()
    assert set(body["inputs"]) == set(health.CRITICAL_INPUTS)


def test_the_unauthenticated_read_out_discloses_nothing(client) -> None:
    """An operator needs the version, the port and whether storage works. Nothing else.

    The credential-presence map, the resolved data directory and the audit log's path and
    entry count are all signed-in only: this route is unauthenticated and reachable by
    anybody who can reach the pod.
    """
    body = client.get("/api/diagnostics").get_json()
    assert body["authenticated"] is False
    assert set(body) == {
        "version",
        "buildId",
        "port",
        "storageWritable",
        "storageErrno",
        "logViewEvents",
        "authenticated",
    }


def test_signing_in_reveals_the_operator_half(signed_in_client) -> None:
    """And the half that appears is the half an operator needs to diagnose a fault."""
    body = signed_in_client.get("/api/diagnostics").get_json()
    assert body["authenticated"] is True
    assert "dataDir" in body
    assert "auditLog" in body
    assert "inputs" in body


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


def test_the_audit_signing_key_is_among_the_reported_inputs(signed_in_client) -> None:
    """The deployment notes rest the recovery path for that secret on this read-out."""
    assert "AUDIT_HMAC_KEY" in health.CRITICAL_INPUTS
    assert "AUDIT_HMAC_KEY" in signed_in_client.get("/api/diagnostics").get_json()["inputs"]


def test_the_probe_is_single_flight_so_one_thread_serves_every_waiting_caller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unauthenticated path must not abandon one thread per request.

    Measured before this control existed: 300 requests against a stalled mount left 300
    live threads, while liveness stayed 200 so the platform never restarted the pod. At
    the container thread ceiling the process could no longer create threads at all.
    """
    started: list[str] = []
    release = threading.Event()

    def stall(path: str) -> health.StorageVerdict:
        started.append(path)
        release.wait(timeout=5)
        return health.StorageVerdict(writable=True, path=path)

    monkeypatch.setattr(health, "_write_probe", stall)
    before = threading.active_count()
    callers = [
        threading.Thread(target=lambda: health.probe_storage(str(tmp_path), timeout_seconds=0.05))
        for _ in range(25)
    ]
    for thread in callers:
        thread.start()
    peak = threading.active_count()
    for thread in callers:
        thread.join()
    release.set()

    assert len(started) == 1, f"{len(started)} probes started for 25 callers"
    assert peak - before <= 27, "the callers themselves are threads; the probe must add one"
    assert threading.active_count() - before <= 2


def test_the_probe_reports_a_refusal_to_start_rather_than_raising(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """At the thread ceiling the probe must still return a verdict.

    Raising here destroys readiness and diagnostics at exactly the moment an operator
    needs them, which is the recovery channel the read-out exists to be.
    """

    def refuse(_self: object) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(health._Probe, "start", refuse)
    verdict = health.probe_storage(str(tmp_path))
    assert verdict.writable is False
    assert "could not start" in (verdict.detail or "")


def test_readiness_and_diagnostics_survive_a_refusal_to_start_a_thread(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(_self: object) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(health._Probe, "start", refuse)
    health.reset_diagnostics_cache()
    assert client.get("/readyz").status_code == 503
    assert client.get("/api/diagnostics").status_code == 200
    assert client.get("/livez").status_code == 200
