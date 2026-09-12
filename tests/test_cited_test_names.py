r"""Every test named in a shipped file must be a test that exists.

A comment or a document that names a test and says it holds something is a claim about the
suite, and nothing ran it. Four consecutive gate rounds failed on a sentence of that kind, and the
round that deleted a redundant test left two files pointing a maintainer at it: the
docstring of the function someone edits before breaking the credential sweep's normaliser,
and the accreditation record that sends an assessor to that module. The property was still
held elsewhere; the signposts were not corrected.

So the class is closed here rather than audited by eye each round. A cited name is now a
machine-checkable reference: if it does not resolve to a collected test, this is red.
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: A backticked `test_…` name, which is how this project cites one in prose, in a comment
#: and in a document. Anything not in backticks is narrative rather than a reference.
_CITATION = re.compile(r"`(test_[a-z0-9_]+)`")

#: Names cited in this tree that are deliberately NOT tests of this suite. A declared list,
#: reviewable line by line, so an exception is a decision rather than a loosened check.
#:
#: The four below are in `.claude/skills/appstore-python-gate/references/`, which is a
#: recipe for a project adopting this baseline. It PRESCRIBES tests a consuming project
#: should write; it does not describe this suite. That directory does not ship in the
#: package and is not assessor-facing, which is the whole difference: the defect this module
#: exists for is a SHIPPED file pointing a reader at a control that is not there.
NOT_A_TEST = frozenset(
    {
        "test_the_environment_check_is_the_first_leg_of_the_loop",
        "test_the_loop_never_invokes_a_tool_by_bare_name",
        "test_the_loop_routes_every_tool_through_one_resolved_interpreter",
        "test_no_verification_script_pipes_a_gating_command_into_another",
    }
)


def _tracked() -> list[Path]:
    """Every file `git add -A` would stage, or a skip where there is no repository."""
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not available, so the tracked set cannot be read")
    listed = subprocess.run(  # noqa: S603
        [git, "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=False,
    )
    if listed.returncode != 0:
        pytest.skip("not a repository; this is the unpacked package")
    return [ROOT / name for name in listed.stdout.split() if (ROOT / name).is_file()]


def _defined_tests() -> set[str]:
    """Every test function the suite defines, read from the source rather than collected.

    Parsing beats importing here: a module that skips at import time, as two in this suite
    do outside the repository, would otherwise contribute nothing and every name it defines
    would read as dangling.
    """
    names = set()
    for path in sorted((ROOT / "tests").glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        names |= {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")
        }
    return names


def _citations() -> dict[str, list[str]]:
    """Every backticked test name cited in a tracked file, and where it is cited."""
    found: dict[str, list[str]] = {}
    for path in _tracked():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for name in _CITATION.findall(text):
            found.setdefault(name, []).append(str(path.relative_to(ROOT)))
    return found


def test_every_cited_test_name_resolves() -> None:
    """A citation that resolves to nothing is a signpost to a control that is not there."""
    defined = _defined_tests()
    dangling = {
        name: sorted(set(where))
        for name, where in _citations().items()
        if name not in defined and name not in NOT_A_TEST
    }

    assert not dangling, "these files cite a test that does not exist:\n  " + "\n  ".join(
        f"{name} in {', '.join(where)}" for name, where in sorted(dangling.items())
    )


def test_the_citation_check_reads_this_repository() -> None:
    """The guard above is vacuous if it finds nothing to check, so the corpus is asserted.

    A citation pattern that stopped matching, or a tracked set that came back empty, would
    make the test green and meaningless.
    """
    assert _defined_tests(), "no test functions were parsed out of tests/"
    assert _citations(), "no test citations were found, so the pattern no longer matches"
