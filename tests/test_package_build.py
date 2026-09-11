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

import hashlib
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
    """Return a clone, skipping rather than failing where it cannot be made.

    The platform runs this suite against the UNPACKED PACKAGE, which is a directory of
    files and not a repository, so there is nothing to clone and nothing to build. Skipping
    there is honest; failing there would turn a green local loop into a red upload for a
    reason that has nothing to do with the code. Caught by the pipeline simulation on the
    first run after these tests were written, which is what that simulation is for.
    """
    for tool in ("git", "zip"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} is not available")
    if not (ROOT / ".git").exists():
        pytest.skip("not a git repository; the packaging script cannot run here")
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


def test_the_exemption_cannot_be_claimed_from_a_nested_tests_directory(clone: Path) -> None:
    """`"tests" in path.parts` matched any component of the ABSOLUTE stage path.

    So `docs/tests/probe.py` with a marked credential satisfied it, and the credential
    shipped in a clean-stamped package while the build printed one honoured exemption. The
    check is anchored to the package root now.
    """
    nested = clone / "docs" / "tests"
    nested.mkdir(parents=True)
    (nested / "probe.py").write_text(f"{PROBE_CREDENTIAL}  # nosec\n", encoding="utf-8")
    _commit(clone, "probe: nested tests directory")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "exemption marker outside" in result.stdout


def test_a_utf16_credential_is_caught(clone: Path) -> None:
    """The commonest non-UTF-8 text encoding carried a plain credential straight through.

    Decoded as UTF-8 with replacement the credential is NUL-separated, which no ASCII rule
    matches. PowerShell's `Out-File` and `>` produce exactly this, so it is a paste away.
    """
    probe = clone / "docs" / "probe-utf16.md"
    probe.write_bytes(PROBE_CREDENTIAL.encode("utf-16-le"))
    _commit(clone, "probe: utf-16 credential")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "NUL-separated" in result.stdout


def test_a_credential_in_a_filename_is_caught(clone: Path) -> None:
    """A key pasted as a filename never reaches a body scan."""
    # Assembled from parts, for the same reason as PROBE_CREDENTIAL: written whole, the
    # filename rule this test exercises flags this very module and refuses the build.
    probe_key = "AKIA" + "ABCDEFGHIJKLMNOP"
    (clone / "docs" / f"{probe_key}.md").write_text("notes\n", encoding="utf-8")
    _commit(clone, "probe: credential in a filename")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "in a path component" in result.stdout


def test_a_second_exemption_is_refused(clone: Path) -> None:
    """The count is pinned at the one line that needs it, so a second is a reviewed change."""
    suite = clone / "tests" / "test_entra_sign_in.py"
    suite.write_text(
        suite.read_text(encoding="utf-8") + f"\nSECOND = {PROBE_CREDENTIAL!r}  # nosec\n",
        encoding="utf-8",
    )
    _commit(clone, "probe: second exemption")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "exemptions claimed" in result.stdout


def test_a_credential_named_file_is_refused_by_name(clone: Path) -> None:
    """The name sweep, which the body sweep does not subsume."""
    (clone / "docs" / "deploy.pem").write_text("not actually a key\n", encoding="utf-8")
    _commit(clone, "probe: credential-shaped name")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "looks like a credential" in result.stdout


def test_a_nested_dockerfile_is_refused(clone: Path) -> None:
    """A nested Dockerfile breaks App Store template detection and the build context."""
    (clone / "src" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    _commit(clone, "probe: nested Dockerfile")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "nested Dockerfile" in result.stdout


def test_an_implausible_version_is_refused(clone: Path) -> None:
    """A slash in the version makes the recorded path and the written path disagree."""
    manifest = clone / "pyproject.toml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace('version = "2.2"', 'version = "2.2/../x"'),
        encoding="utf-8",
    )
    _commit(clone, "probe: implausible version")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "implausible version" in result.stdout


def test_a_missing_required_file_is_refused(clone: Path) -> None:
    """The suite reads these from the package root, so a package without one fails stage 5.

    Removing `.env.example` tripped the earlier allowlist-existence check instead, so this
    test passed without ever reaching the control it names. `docs/DEPLOYMENT.md` sits inside
    an allowlisted DIRECTORY, so the directory still exists and the required-file loop is
    what refuses it.
    """
    _run([_tool("git"), "-C", str(clone), "rm", "--quiet", "docs/DEPLOYMENT.md"])
    _commit(clone, "probe: remove a required file")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "the suite reads docs/DEPLOYMENT.md from the package root" in result.stdout


def test_the_builder_records_a_digest_beside_the_pointer(clone: Path) -> None:
    """The simulation binds the pointer to the bytes, so the builder must write the digest."""
    result = _build(clone)

    assert result.returncode == 0, result.stdout
    digest = (clone / "dist" / "latest.sha256").read_text(encoding="utf-8").strip()
    package = Path((clone / "dist" / "latest").read_text(encoding="utf-8").strip())
    assert len(digest) == 64, digest
    assert digest == hashlib.sha256((clone / package).read_bytes()).hexdigest()


def test_the_simulation_refuses_a_pointer_with_no_digest(clone: Path) -> None:
    """A MISSING digest was a skip, so the actor the check exists to stop removed it.

    Repoint `dist/latest` at a foreign archive, delete `dist/latest.sha256`, and the
    simulation unpacked it. It is a refusal now.
    """
    assert _build(clone).returncode == 0
    (clone / "dist" / "latest.sha256").unlink()
    result = _run([_tool("sh"), "scripts/simulate-pipeline.sh"], cwd=clone)

    assert result.returncode != 0, result.stdout
    assert "cannot be trusted" in result.stdout


def test_the_simulation_refuses_a_package_whose_bytes_changed(clone: Path) -> None:
    """The pointer is a file in `dist/`; anything that can write there can rename an archive."""
    assert _build(clone).returncode == 0
    package = clone / (clone / "dist" / "latest").read_text(encoding="utf-8").strip()
    package.write_bytes(package.read_bytes() + b"tampered")
    result = _run([_tool("sh"), "scripts/simulate-pipeline.sh"], cwd=clone)

    assert result.returncode != 0, result.stdout
    assert "does not match the digest" in result.stdout


def test_the_simulation_refuses_a_tree_with_a_skip_bit_set(clone: Path) -> None:
    """`git ls-files -v` reports `S` for skip-worktree, which `^[a-z]` silently missed.

    With the bit set, a gutted control is invisible to `git status` and the stale package
    returned SIMULATION: PASS.
    """
    assert _build(clone).returncode == 0
    git = _tool("git")
    _run([git, "-C", str(clone), "update-index", "--skip-worktree", "src/complyops/records.py"])
    (clone / "src" / "complyops" / "records.py").write_text("# gutted\n", encoding="utf-8")
    result = _run([_tool("sh"), "scripts/simulate-pipeline.sh"], cwd=clone)

    assert result.returncode != 0, result.stdout
    assert "skip-worktree" in result.stdout


def test_one_exempt_line_cannot_suppress_several_credentials(clone: Path) -> None:
    """The budget counted LINES, so one exempt line bought an unbounded number of secrets.

    A tuple of three credentials on the one permitted line shipped an AWS key, an LLM
    provider key and a GitLab token while the banner still read one exemption honoured.
    """
    suite = clone / "tests" / "test_entra_sign_in.py"
    second = "sk-" + "a" * 24
    suite.write_text(
        suite.read_text(encoding="utf-8")
        + f'\nLEAK = ({PROBE_CREDENTIAL!r}, "{second}")  # noqa: S105\n',
        encoding="utf-8",
    )
    _commit(clone, "probe: several credentials on one exempt line")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "exemptions claimed" in result.stdout


def test_the_exemption_cannot_be_relocated_to_another_test_module(clone: Path) -> None:
    """The budget was a total, so it could be spent anywhere under `tests/`.

    Shortening the legitimate double until it no longer matched and adding a marked
    credential elsewhere kept the total at one, and the build output was byte-identical to
    a clean build. The allowance names the path now.
    """
    nested = clone / "tests" / "nested"
    nested.mkdir()
    (nested / "probe.py").write_text(f"{PROBE_CREDENTIAL}  # nosec\n", encoding="utf-8")
    _commit(clone, "probe: exemption relocated")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "outside the allowed paths" in result.stdout


def test_a_credential_in_a_directory_name_is_caught(clone: Path) -> None:
    """The scan saw the leaf only, so a token in a directory component shipped."""
    token = "glpat-" + "a" * 21
    nested = clone / "docs" / token
    nested.mkdir()
    (nested / "notes.md").write_text("notes\n", encoding="utf-8")
    _commit(clone, "probe: credential in a directory name")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "in a path component" in result.stdout


def test_a_dirty_tree_stamps_the_package(clone: Path) -> None:
    """The stamp is the artefact's own declaration that it does not match the tree."""
    (clone / "src" / "complyops" / "records.py").write_text("# edited\n", encoding="utf-8")
    result = _build(clone)

    assert result.returncode == 0, result.stdout
    assert "-dirty.zip" in result.stdout


def test_a_failed_build_leaves_no_pointer(clone: Path) -> None:
    """The pointer is invalidated BEFORE the build, not only written after a good one.

    Written only on success and never cleared, it survived a failure and pointed at the
    previous commit's package, which the simulation would then have tested and passed.
    """
    assert _build(clone).returncode == 0
    (clone / "src" / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
    _commit(clone, "probe: make the build fail")
    assert _build(clone).returncode != 0

    assert not (clone / "dist" / "latest").exists()


def test_the_simulation_refuses_a_dirty_stamped_package(clone: Path) -> None:
    """A package built from a dirty tree is stale the moment anything changes again."""
    (clone / "src" / "complyops" / "records.py").write_text("# edited\n", encoding="utf-8")
    assert _build(clone).returncode == 0
    result = _run([_tool("sh"), "scripts/simulate-pipeline.sh"], cwd=clone)

    assert result.returncode != 0, result.stdout
    assert "built from a dirty tree" in result.stdout


def test_the_simulation_refuses_a_package_from_another_commit(clone: Path) -> None:
    """The filename carries the commit, and the tree under test must be that commit."""
    assert _build(clone).returncode == 0
    (clone / "docs" / "later.md").write_text("later\n", encoding="utf-8")
    _commit(clone, "probe: move the tree on")
    result = _run([_tool("sh"), "scripts/simulate-pipeline.sh"], cwd=clone)

    assert result.returncode != 0, result.stdout
    assert "not built from the current commit" in result.stdout


def test_the_simulation_refuses_a_tree_edited_after_the_build(clone: Path) -> None:
    """Commit granularity alone admitted a package built before an uncommitted edit."""
    assert _build(clone).returncode == 0
    (clone / "src" / "complyops" / "records.py").write_text("# gutted\n", encoding="utf-8")
    result = _run([_tool("sh"), "scripts/simulate-pipeline.sh"], cwd=clone)

    assert result.returncode != 0, result.stdout
    assert "working tree has changed" in result.stdout
