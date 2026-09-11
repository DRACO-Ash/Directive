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

import contextlib
import hashlib
import shutil
import signal
import subprocess
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# EVERY probe in this module is assembled from parts, and that is not fussiness. The build
# sweeps the package for credentials and this module SHIPS inside it, so a probe written
# whole makes the script refuse its own test suite. It has happened four times in this file
# alone: the credential, the AWS filename, the path-component token and the private-key
# block. If you add a rule, add its probe in pieces.

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
    assert "in the path" in result.stdout


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
    assert "in the path" in result.stdout


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


def test_the_simulation_refuses_a_red_suite(clone: Path) -> None:
    """The simulation's central guard, held by no test until now.

    Deleted, a genuinely failing suite returned `SIMULATION: PASS` and exit 0 while the
    twenty-seven packaging tests stayed green. That is the one answer this script exists to
    never give, and nothing was holding it.
    """
    failing = clone / "tests" / "test_deliberately_red.py"
    failing.write_text("def test_red() -> None:\n    raise AssertionError\n", encoding="utf-8")
    _commit(clone, "probe: a red suite")
    assert _build(clone).returncode == 0
    result = _run([_tool("sh"), "scripts/simulate-pipeline.sh"], cwd=clone)

    assert result.returncode != 0, result.stdout
    assert "SIMULATION: PASS" not in result.stdout
    assert "SIMULATION: FAIL" in result.stdout


def test_the_simulation_refuses_when_no_package_exists(clone: Path) -> None:
    """Nothing to test is a refusal, not a pass."""
    result = _run([_tool("sh"), "scripts/simulate-pipeline.sh"], cwd=clone)

    assert result.returncode != 0, result.stdout
    assert "no package" in result.stdout


def test_several_credentials_on_the_one_exempt_line_are_refused(clone: Path) -> None:
    """The budget counted RULE LABELS, so three secrets of one shape scored one.

    All three shipped with the banner still reading a single exemption honoured.
    """
    suite = clone / "tests" / "test_entra_sign_in.py"
    text = suite.read_text(encoding="utf-8")
    extra = f"; OTHER = {PROBE_CREDENTIAL!r}; THIRD = {PROBE_CREDENTIAL!r}"
    suite.write_text(text.replace("  # noqa: S105", f"{extra}  # noqa: S105", 1), encoding="utf-8")
    _commit(clone, "probe: several credentials on one exempt line")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "exemptions claimed" in result.stdout or "exempt line has changed" in result.stdout


def test_substituting_a_real_secret_for_the_declared_double_is_refused(clone: Path) -> None:
    """The allowance pins the line by digest, so an edit to it is a reviewed change."""
    suite = clone / "tests" / "test_entra_sign_in.py"
    suite.write_text(
        suite.read_text(encoding="utf-8").replace(
            '"not-a-real-secret"', '"P@ssw0rd-prod-entra-2026"'
        ),
        encoding="utf-8",
    )
    _commit(clone, "probe: substitute the declared double")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "the exempt line has changed" in result.stdout


def test_a_credential_split_across_path_components_is_caught(clone: Path) -> None:
    """Components were scanned one by one, so a token spanning a separator was invisible."""
    # Assembled from parts, like the other probes: written whole, the rule under test
    # matches this module and the build refuses.
    opening = "tok" + "en=" + chr(39) + "abcdefgh"
    closing = "ijklmnop" + chr(39) + ".md"
    nested = clone / "docs" / opening
    nested.mkdir()
    (nested / closing).write_text("notes\n", encoding="utf-8")
    _commit(clone, "probe: credential across path components")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "in the path" in result.stdout


def test_the_pointer_is_never_a_symlink_after_a_build(clone: Path) -> None:
    """Three attempts at this race were defeated in turn.

    The pointer is written inside a 0700 directory now, so the path the shell re-opens is
    one no other user can reach.
    """
    assert _build(clone).returncode == 0

    for name in ("latest", "latest.sha256"):
        assert not (clone / "dist" / name).is_symlink(), name
    assert not list((clone / "dist").glob(".latest.??????")), "the private directory leaked"


def test_a_planted_symlink_cannot_redirect_a_build_write(clone: Path) -> None:
    """The race controls were shipped unheld three releases running, and each was undone.

    A build with no adversary present asserts a property the BROKEN version also satisfies,
    which is why reverting the pointer fix left every test green. This plants the symlink
    from a racer thread against every predictable name in `dist/`, and asserts the file
    outside the repository is byte-intact afterwards.
    """
    victim = clone.parent / "outside-the-repository"
    victim.write_text("untouched\n", encoding="utf-8")
    # Every predictable name the build has EVER used, including the current scheme's work
    # directory. The previous version of this list held only the old names, so replacing the
    # `mktemp -d` with a fixed `dist/.build` left the suite green while a symlink planted
    # there destroyed a file outside the repository.
    targets = ["latest", "latest.sha256", ".stage.manifest", ".stage", ".build", "package.zip"]
    stop = threading.Event()

    def plant() -> None:
        while not stop.is_set():
            for name in targets:
                path = clone / "dist" / name
                with contextlib.suppress(OSError):
                    if not path.is_symlink():
                        path.symlink_to(victim)

    (clone / "dist").mkdir(exist_ok=True)
    racer = threading.Thread(target=plant, daemon=True)
    racer.start()
    try:
        built = _build(clone)
    finally:
        stop.set()
        racer.join(timeout=5)

    # The build must SUCCEED as well as leave the victim alone, or an edit that makes it die
    # early under the racer would satisfy this test for the wrong reason.
    assert built.returncode == 0, built.stdout
    assert victim.read_text(encoding="utf-8") == "untouched\n", "a build write followed a symlink"


def test_one_credential_shape_repeated_spends_the_whole_budget(clone: Path) -> None:
    """The count must come from the MATCHES, not from the rule labels or the digest.

    Reverting `sum(len(rule.findall(line)) ...)` to `+= 1` left the suite green, because the
    test that named this control was satisfied by the digest pin instead. This one asserts
    the count message specifically.
    """
    suite = clone / "tests" / "test_entra_sign_in.py"
    text = suite.read_text(encoding="utf-8")
    extra = f"; A = {PROBE_CREDENTIAL!r}; B = {PROBE_CREDENTIAL!r}"
    suite.write_text(text.replace("  # noqa: S105", f"{extra}  # noqa: S105", 1), encoding="utf-8")
    _commit(clone, "probe: repeated credential shape")
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "exemptions claimed" in result.stdout, "the count, not the digest, must catch this"


def test_the_simulation_asserts_the_coverage_artefact(clone: Path) -> None:
    """The quality gate reads `coverage.xml` at exactly that path.

    A suite that passes without writing it still fails stage 6.
    """
    manifest = clone / "pyproject.toml"
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            'output = "coverage.xml"', 'output = "elsewhere.xml"'
        ),
        encoding="utf-8",
    )
    _commit(clone, "probe: write the coverage report somewhere else")
    assert _build(clone).returncode == 0
    result = _run([_tool("sh"), "scripts/simulate-pipeline.sh"], cwd=clone)

    # Asserting the artefact's own message, not the `echo` beneath it: `wc -c < missing`
    # leaves an empty substitution and `echo` still succeeds, so "coverage.xml:" appeared
    # in the output with the guard deleted and this test held nothing.
    assert result.returncode != 0, result.stdout
    assert "coverage.xml was not written" in result.stdout
    assert "SIMULATION: PASS" not in result.stdout


def test_the_work_directory_is_private(clone: Path) -> None:
    """The intermediates live in a mode-0700 directory, and nothing asserted the mode.

    Replacing `mktemp -d` with a fixed `dist/.build` left every test green, and a symlink
    planted at that name then destroyed a file outside the repository with the build exiting
    0. A predictable name is the whole vulnerability, so both halves are asserted: the name
    is not the fixed one, and the directory is unreadable by anyone else.
    """
    # Name AND mode captured inside the watcher: the trap removes the directory when the
    # build ends, so anything read afterwards is gone.
    seen: dict[str, int] = {}
    stop = threading.Event()

    def watch() -> None:
        while not stop.is_set():
            for candidate in (clone / "dist").glob(".build.*"):
                with contextlib.suppress(OSError):
                    seen.setdefault(candidate.name, candidate.stat().st_mode & 0o777)
            # Not a busy spin: this runs for the whole of a build under a 60 second
            # per-test timeout, and holding a core at 100% on a shared runner is rude.
            time.sleep(0.01)

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        assert _build(clone).returncode == 0
    finally:
        stop.set()
        watcher.join(timeout=5)

    assert seen, "no mktemp work directory was created; is the name fixed again?"
    # The MODE, which the docstring claimed and the test never read. `chmod 755` after the
    # `mktemp -d` left the whole suite green.
    for name, mode in seen.items():
        assert mode == 0o700, f"{name} is mode {mode:o}, traversable by others"


@pytest.mark.parametrize(
    ("label", "probe"),
    [
        ("private key", "-----BEGIN " + "RSA PRIVATE KEY-----"),
        ("access gate", "ADMIN_" + "PIN = " + chr(39) + "9911" + chr(39)),
        ("provider key", "sk-" + "a" * 24),
        ("forge token", "glpat-" + "b" * 21),
        ("chat token", "xoxb-" + "1234567890" + "-abcdef"),
        ("cloud key", "AIza" + "C" * 35),
        ("bearer", "Bea" + "rer " + "D" * 24),
    ],
)
def test_each_sweep_rule_can_refuse(clone: Path, label: str, probe: str) -> None:
    """Eight of the nine rules were unexercised and could be deleted silently.

    The access-gate rule is the sweep's arm of a CLAUDE.md hard rule; it had no test at all.
    """
    (clone / "docs" / f"probe-{label.replace(' ', '-')}.md").write_text(
        f"notes\n{probe}\n", encoding="utf-8"
    )
    _commit(clone, f"probe: {label}")
    result = _build(clone)

    assert result.returncode != 0, f"{label} was not refused: {result.stdout}"


def test_the_work_directory_name_is_unpredictable(clone: Path) -> None:
    """Asserted as a property, because the previous test compared against one literal.

    `WORK="dist/.build"` was caught; `WORK="dist/.build.fixed"` was not, and a symlink
    planted at that name wrote the staged copy of HEAD and the manifest into a directory
    outside the repository with the build exiting 0. Two builds must not agree on a name.
    """
    names: list[set[str]] = []
    for _ in range(2):
        seen: set[str] = set()
        stop = threading.Event()

        def watch(into: set[str] = seen, halt: threading.Event = stop) -> None:
            while not halt.is_set():
                into.update(p.name for p in (clone / "dist").glob(".build.*"))
                time.sleep(0.01)

        watcher = threading.Thread(target=watch, daemon=True)
        watcher.start()
        try:
            assert _build(clone).returncode == 0
        finally:
            stop.set()
            watcher.join(timeout=5)
        assert seen, "no work directory was observed"
        names.append(seen)

    assert names[0] != names[1], f"two builds used the same work directory name: {names[0]}"


def test_the_cleanup_trap_survives_a_signal(clone: Path) -> None:
    """Dash runs an EXIT trap for neither a signal nor a closed pipe.

    A piped build left a full copy of HEAD behind at mode 0700, and one such orphan was
    sitting in `dist/` when the security gate looked. Deleting the trap, or reducing it back
    to `EXIT` alone, left the whole suite green.
    """
    build = subprocess.Popen(  # noqa: S603
        [_tool("sh"), "scripts/build-package.sh"],
        cwd=clone,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if list((clone / "dist").glob(".build.*")):
                break
            if build.poll() is not None:
                pytest.skip("the build finished before the work directory could be observed")
            time.sleep(0.01)
        else:
            pytest.skip("the work directory was never observed")
        build.send_signal(signal.SIGTERM)
        build.wait(timeout=30)
    finally:
        if build.poll() is None:
            build.kill()

    assert not list((clone / "dist").glob(".build*")), "a signal left the work directory behind"


def test_a_symlinked_dist_is_refused(clone: Path) -> None:
    """`mkdir -p dist` follows a link, and every artefact then lands wherever it points."""
    outside = clone.parent / "outside-dist"
    outside.mkdir()
    shutil.rmtree(clone / "dist", ignore_errors=True)
    (clone / "dist").symlink_to(outside)
    result = _build(clone)

    assert result.returncode != 0, result.stdout
    assert "dist is a symlink" in result.stdout
    assert not list(outside.iterdir()), "the build wrote through the link"
