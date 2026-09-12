r"""Every test named in a shipped file must be a test that exists.

A comment or a document that names a test and says it holds something is a claim about the
suite, and nothing ran it. Four consecutive gate rounds failed on a sentence of that kind, and the
round that deleted a redundant test left two files pointing a maintainer at it: the
docstring of the function someone edits before breaking the credential sweep's normaliser,
and the accreditation record that sends an assessor to that module. The property was still
held elsewhere; the signposts were not corrected.

So the class is closed here rather than audited by eye each round. A cited name is now a
machine-checkable reference: if it does not resolve to a test this suite defines, this
is red.
"""

from __future__ import annotations

import ast
import re
import subprocess
from pathlib import Path

import pytest

import sweep_rules
from sweep_rules import tracked_files

ROOT = Path(__file__).resolve().parents[1]

#: A backticked test name, in either form this project writes. The bare name is the common
#: one; the node id, a module path and a name joined by a double colon, is what the runbook
#: gives a reader to paste into pytest, and the first guard could not see it. Renaming the
#: test that document cites left the whole suite green, with an assessor-facing runbook
#: pointing at a control that was not there, which is the exact defect this module exists
#: for. The file part is captured too, so a node id is resolved in the file it names.
_CITATION = re.compile(r"`(?:(?P<file>[\w./-]+)::)?(?P<name>test_[a-z0-9_]+)`")

#: Citations that are deliberately NOT of a test in this suite, keyed by the path they are
#: allowed to appear in as well as the name. Keyed by name alone, the exemption applied
#: everywhere: citing one of these from `docs/GATE-RECORDS.md`, which ships, passed green,
#: while the comment justifying it appealed to the path.
#:
#: These four are in a recipe for a project adopting this baseline. It PRESCRIBES tests a
#: consuming project should write; it does not describe this suite. That directory does not
#: ship in the package and is not assessor-facing, which is the whole difference: the defect
#: this module exists for is a SHIPPED file pointing a reader at a control that is not there.
NOT_A_TEST = {
    ".claude/skills/appstore-python-gate/references/": frozenset(
        {
            "test_the_environment_check_is_the_first_leg_of_the_loop",
            "test_the_loop_never_invokes_a_tool_by_bare_name",
            "test_the_loop_routes_every_tool_through_one_resolved_interpreter",
            "test_no_verification_script_pipes_a_gating_command_into_another",
        }
    )
}


#: This module's own path. The span scan below writes an unreadable node-id shape as a
#: LITERAL in its own pattern, so it self-matches and must skip itself. Extracted to a
#: named predicate rather than left inline, because the sibling module already records what
#: an inline skip costs: widening it to every path under `tests/` retired that sweep over
#: every shipped test module with the suite green, and `tests/` ships in the package. The
#: same widening here was measured green, with the pass count unchanged byte for byte.
SELF = str(Path(__file__).resolve().relative_to(ROOT))


def _is_this_module(where: str) -> bool:
    """Report whether this is the module itself, which self-matches its own span pattern."""
    return where == SELF


def _exempt(name: str, where: str) -> bool:
    """Report whether this name is a declared exception FOR THIS PATH."""
    return any(where.startswith(prefix) and name in names for prefix, names in NOT_A_TEST.items())


def _defined_tests() -> dict[str, set[str]]:
    """Every test function the suite DEFINES, by file, read from source.

    Defined rather than collected, and the wording matters: this parses, so a `def test_…`
    nested inside a class or another function counts here where pytest would not collect it.
    The two sets coincide today, measured. Parsing is still the right call, because
    collecting would mean running pytest inside a test. The earlier reason given here, that
    modules skip at import time, was simply false: the two that skip do so at call time,
    which does not remove a name from collection.

    `rglob`, so a future `tests/<subdir>/` is not invisible, and `AsyncFunctionDef` as well
    as `FunctionDef`, because an async test would otherwise read as undefined and every
    citation of it as dangling.
    """
    names: dict[str, set[str]] = {}
    for path in sorted((ROOT / "tests").rglob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        names[str(path.relative_to(ROOT))] = {
            node.name
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name.startswith("test_")
        }
    return names


def _citations() -> list[tuple[str, str, str]]:
    """Every backticked test citation: the name, the module it names if any, and the citer."""
    found = []
    for path in tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        where = str(path.relative_to(ROOT))
        found += [
            (match.group("name"), match.group("file") or "", where)
            for match in _CITATION.finditer(text)
        ]
    return found


def test_every_cited_test_name_resolves() -> None:
    """A citation that resolves to nothing is a signpost to a control that is not there.

    A citation naming a module must resolve IN THAT MODULE. The deployment runbook gives a
    reader a node id to paste into pytest, and one naming the wrong module sends them
    nowhere even when the test exists elsewhere.
    """
    defined = _defined_tests()
    everywhere: set[str] = set().union(*defined.values())
    dangling = []
    for name, in_file, where in _citations():
        if _exempt(name, where):
            continue
        if in_file:
            if name not in defined.get(in_file, set()):
                dangling.append(f"{in_file}::{name} cited in {where}")
        elif name not in everywhere:
            dangling.append(f"{name} cited in {where}")

    assert not dangling, "these files cite a test that does not exist:\n  " + "\n  ".join(
        sorted(set(dangling))
    )


def test_the_citation_check_reads_this_repository() -> None:
    """The guard above is vacuous if it finds nothing to check, so the corpus is asserted.

    A citation pattern that stopped matching, or a tracked set that came back empty, would
    make the test green and meaningless.
    """
    defined = _defined_tests()
    citations = _citations()

    assert set().union(*defined.values()), "no test functions were parsed out of tests/"
    assert citations, "no test citations were found, so the pattern no longer matches"
    # And a node-id citation specifically. The first guard could not read that form at all,
    # so without one in the corpus the widening would itself be untested.
    assert any(in_file for _, in_file, _ in citations), "no node-id citation was read"


def test_every_node_id_span_is_read_by_the_pattern() -> None:
    """A citation form the pattern cannot read is unchecked rather than red.

    The first version of this guard could read only a bare name, so the node-id form the
    deployment runbook uses went unchecked and renaming the test it cites was green. The
    same gap would reopen for a parametrised id, a class-scoped one, or a whole pytest
    invocation written inside one span, none of which the pattern reads today. This asserts
    the corpus contains no such span: a form entering the tree is red here rather than
    silently unread. A legitimate command in a runbook trips it too, which is fail-closed
    and deliberate; the message says what to do about it.
    """
    unread = []
    for path in tracked_files():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        where = str(path.relative_to(ROOT))
        if _is_this_module(where):
            continue
        for span in re.findall(r"`[^`\n]*::test_[^`\n]*`", text):
            if not _CITATION.fullmatch(span):
                unread.append(f"{span} in {where}")

    assert not unread, (
        "these carry a node id the pattern cannot read, so they are unchecked:\n  "
        + "\n  ".join(sorted(set(unread)))
        + "\n\nTwo ways out: reword it as a bare backticked name or a plain node id, which "
        "is what a citation should be, or widen `_CITATION` to read the new form and prove "
        "the widening with a mutant."
    )


def test_the_tracked_reader_survives_a_path_with_a_space(monkeypatch: pytest.MonkeyPatch) -> None:
    """The NUL-delimited read, which nothing else holds.

    Splitting the listing on whitespace drops a tracked path containing a space out of every
    corpus built on it: the citation scan, the figure sweep, and the credential sweep over
    the tracked tree that `scripts/build-package.sh` now names as the control covering files
    that do not ship. No such path exists today, so no mutation of the real tree can redden
    this; the listing is faked instead, which is the honest way to hold a property the tree
    cannot currently exhibit.
    """
    # The patches reach the real `shutil`, `subprocess` and `Path` objects rather than a
    # narrow seam, because `sweep_rules` holds the modules themselves. `monkeypatch` undoes
    # all three, and the suite runs serially, so the breadth is bounded to this call; it is
    # noted so nobody widens it further.
    listing = "docs/a file with spaces.md\0docs/plain.md\0"
    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout=listing, stderr="")
    monkeypatch.setattr(sweep_rules.shutil, "which", lambda _name: "/usr/bin/git")
    monkeypatch.setattr(sweep_rules.subprocess, "run", lambda *_a, **_k: completed)
    monkeypatch.setattr(Path, "is_file", lambda _self: True)

    names = [path.name for path in tracked_files()]

    assert names == ["a file with spaces.md", "plain.md"]


def test_only_this_module_is_skipped_by_the_span_scan() -> None:
    """The scan's one exemption, asserted rather than inlined.

    Widening it to every path under `tests/` excludes every shipped test module from the
    scan, and an unreadable node id planted in one of them then passes: measured green with
    the suite count unchanged. The sibling module carries the same test for the same reason.
    """
    skipped = [
        str(path.relative_to(ROOT))
        for path in tracked_files()
        if _is_this_module(str(path.relative_to(ROOT)))
    ]

    assert skipped == [SELF]
