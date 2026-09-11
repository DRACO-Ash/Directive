"""The packaging script's refusals, exercised rather than asserted.

`scripts/build-package.sh` decides what leaves this repository, and nothing tested it. The
verification loop never invokes it, so every one of its controls could be deleted and
`LOOP: PASS` would still print. That is why this one file produced a MAJOR finding at three
consecutive security gates: each fix was written, reasoned about, and defeated by the next
reviewer, because no test held the previous one in place.

Each test below commits a hostile change in a throwaway clone and asserts the build refuses
it. They are subprocess tests by necessity: the control is a shell script, and testing a
reimplementation of it in Python would pin the reimplementation.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: The probe credential, assembled from parts so the literal never appears in this file.
#: Written whole, the packaging script's own content sweep flags this module and refuses to
#: build, which is the sweep working correctly and the test being careless. Marking the
#: lines exempt would have been the wrong fix: the exemption count is pinned at one on
#: purpose, and spending it here to test the sweep would blunt the control being tested.
_PROBE_NAME = "CLIENT_" + "SECRET"
PROBE_CREDENTIAL = _PROBE_NAME + "=" + chr(34) + "hunter2-a-real-looking-secret" + chr(34)


def _tool(name: str) -> str:
    """Return the absolute path of a tool, so no lookup depends on PATH order."""
    found = shutil.which(name)
    if found is None:
        pytest.skip(f"{name} is not available")
    return found


def _run(argv: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    """Run one command with an absolute executable and a fixed argument list.

    Every argument below is a literal or a pytest temporary path. There is no shell, no
    string interpolation and no caller-supplied input, which is what S603 asks about.
    """
    return subprocess.run(  # noqa: S603
        argv, cwd=cwd, capture_output=True, text=True, check=False
    )


def _clone(tmp_path: Path) -> Path:
    """Return a throwaway clone of this repository, ready to commit into."""
    work = tmp_path / "clone"
    git = _tool("git")
    cloned = _run([git, "clone", "--quiet", "--no-hardlinks", str(ROOT), str(work)])
    assert cloned.returncode == 0, cloned.stderr
    for name, value in (("user.email", "suite@example.invalid"), ("user.name", "suite")):
        _run([git, "-C", str(work), "config", name, value])
    # The clone carries the COMMITTED scripts, and these tests exist to hold the script in
    # the working tree in place. Without this sync they would pass against the previous
    # version of the control while the edit under test went unexercised, which is the exact
    # shape of the gap they were written to close.
    for script in sorted((ROOT / "scripts").glob("*.sh")):
        shutil.copy2(script, work / "scripts" / script.name)
    # Only when the copy actually changed something. With the scripts already committed the
    # sync is a no-op, and `git commit` exits non-zero on an empty one.
    if _run([git, "-C", str(work), "status", "--porcelain"]).stdout.strip():
        _commit(work, "suite: exercise the working tree's scripts")
    return work


def _commit(work: Path, message: str) -> None:
    """Stage and commit everything in the clone."""
    git = _tool("git")
    _run([git, "-C", str(work), "add", "-A"])
    committed = _run([git, "-C", str(work), "commit", "--quiet", "-m", message])
    assert committed.returncode == 0, committed.stderr


def _build(work: Path) -> subprocess.CompletedProcess[str]:
    """Run the real packaging script in the clone and return its result."""
    return _run([_tool("sh"), "scripts/build-package.sh"], cwd=work)


@pytest.fixture
def clone(tmp_path: Path) -> Path:
    """Return a clone, skipping rather than failing where the tools are absent."""
    for tool in ("git", "zip"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} is not available")
    return _clone(tmp_path)


def test_a_clean_clone_builds_and_matches_head(clone: Path) -> None:
    """The positive control. Without it a refusal test could pass for the wrong reason."""
    result = _build(clone)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "package verified against HEAD" in result.stdout
    assert "credential sweep" in result.stdout
    assert list(clone.glob("dist/*.zip")), "no artefact was produced"


def test_an_export_ignore_cannot_quietly_remove_a_file(clone: Path) -> None:
    """`git archive` honours the archived tree's own `.gitattributes`.

    One committed line removed the AMD-001 10.6 security header test from the package while
    the build exited 0 and the pipeline simulation passed on the result. The artefact is now
    compared against the object database, so a path in HEAD and not in the package fails.
    """
    (clone / ".gitattributes").write_text(
        "tests/test_security_headers.py export-ignore\n", encoding="utf-8"
    )
    _commit(clone, "probe: export-ignore")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "in HEAD and not in the package" in result.stdout


def test_an_export_subst_cannot_rewrite_a_shipped_byte(clone: Path) -> None:
    """The same mechanism, substituting attacker-chosen text into a shipped file."""
    (clone / ".gitattributes").write_text("README.md export-subst\n", encoding="utf-8")
    readme = clone / "README.md"
    readme.write_text(readme.read_text(encoding="utf-8") + "\n$Format:%s$\n", encoding="utf-8")
    _commit(clone, "probe: export-subst")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "in HEAD" in result.stdout


def test_a_committed_symlink_is_refused(clone: Path) -> None:
    """`zip -r` without `-y` stores what a link points at, so no link may ship."""
    link = clone / "docs" / "probe-link.md"
    link.symlink_to("/etc/hostname")
    _commit(clone, "probe: symlink")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "may not ship" in result.stdout or "symlink" in result.stdout


def test_a_credential_in_a_file_the_sweep_cannot_decode_is_caught(clone: Path) -> None:
    """A single trailing byte used to defeat the whole credential control.

    `read_text` raised, the sweep moved on, and the secret shipped in a package the build
    called clean. The same held for a credential inside a binary file.
    """
    probe = clone / "docs" / "probe-binary.md"
    probe.write_bytes(PROBE_CREDENTIAL.encode("utf-8") + b"\n\xff")
    _commit(clone, "probe: non-utf8 credential")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "Generic API key assignment" in result.stdout


def test_an_exemption_marker_outside_the_suite_is_refused(clone: Path) -> None:
    """The exemption is a seven-character bypass for anyone who can commit.

    Appending `# nosec` to a credential line made it ship. It is honoured only inside
    `tests/*.py`, and the count of honoured lines is pinned.
    """
    probe = clone / "docs" / "probe-exempt.md"
    probe.write_text(f"{PROBE_CREDENTIAL}  # nosec\n", encoding="utf-8")
    _commit(clone, "probe: exemption abuse")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "exemption marker outside" in result.stdout


def test_a_credential_split_across_lines_is_caught(clone: Path) -> None:
    """The pre-write hook matches a joined blob; a line-based sweep alone did not."""
    probe = clone / "docs" / "probe-split.md"
    split = PROBE_CREDENTIAL.replace("=", " =\n    ", 1)
    probe.write_text(f"{split}\n", encoding="utf-8")
    _commit(clone, "probe: split credential")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "split across lines" in result.stdout
