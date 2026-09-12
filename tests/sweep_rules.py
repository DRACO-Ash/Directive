r"""Read the packaging sweep's own definitions out of `scripts/build-package.sh`.

A helper rather than a test module, so `python_files` does not collect it.

Three test modules need the same three things from that script: its credential rules, which
of them must not fold case, and the list of credential-shaped FILENAMES it refuses. Each was
copied by hand into a test at least once, and each copy drifted. The hook's rules drifted
until a parity test read them from the source; the filename list drifted in the add
direction, where a new pattern with no probe left the suite green; and the measured cost of
the widenings the rules deliberately do not make went stale four times.

So nothing here is transcribed. The script is a shell file with a quoted heredoc, which
means the Python inside it is the text that runs, and a literal read out of that text is the
same object the build uses.
"""

from __future__ import annotations

import ast
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SWEEP = ROOT / "scripts" / "build-package.sh"

#: The alternation every credential rule shares, DERIVED from the rules rather than copied,
#: because the module docstring says nothing here is transcribed and a hand-copy would have
#: made that sentence false. An experiment built on top of a rule needs it to find the name
#: part without matching a fragment of some other rule.
_KEYWORD_GROUP = re.compile(r"\(\?:SECRET\|[A-Z|]+\)\[A-Z0-9_\]\*")


def keyword_group() -> str:
    """Return the shared keyword alternation, read out of the rules that carry it."""
    found = {
        match for pattern in load_rules().values() for match in _KEYWORD_GROUP.findall(pattern)
    }
    assert len(found) == 1, f"the rules no longer share one keyword group: {sorted(found)}"
    return found.pop()


_CASE_SENSITIVE_MARKER = "]\n#: The rules that must NOT fold case"
#: `-iname` as well as `-name`: adding `-o -iname '*.asc'` with no probe beside it left the
#: bijection test green, where the `-name` spelling reddened it. The count of predicates is
#: asserted against the count of parsed patterns below, so a third spelling cannot slip past
#: this regex silently either.
_NAME_PATTERN = re.compile(r"-i?name '([^']+)'")
_NAME_PREDICATE = re.compile(r"-i?name ")


def load_rules() -> dict[str, str]:
    """Return the sweep's credential rules as label to pattern, in file order."""
    source = SWEEP.read_text(encoding="utf-8")
    literal = source[
        source.index("RULES = [") + len("RULES = ") : source.index(_CASE_SENSITIVE_MARKER) + 1
    ]
    rules: list[tuple[str, str]] = ast.literal_eval(literal)
    assert len(dict(rules)) == len(rules), "the sweep carries two rules under one label"
    return dict(rules)


def load_case_sensitive() -> set[str]:
    """Return the labels the sweep compiles without IGNORECASE."""
    source = SWEEP.read_text(encoding="utf-8")
    block = source[source.index("CASE_SENSITIVE = {") :]
    value = ast.literal_eval(block[len("CASE_SENSITIVE = ") : block.index("}") + 1])
    return set(value)


def load_swept_filenames() -> set[str]:
    """Return the `-name` patterns of the filename sweep, minus the one exemption.

    The `find` expression is read rather than copied for the same reason the rules are: a
    pattern added to it with no probe beside it left the whole suite green, and five of
    those patterns were added in one commit.
    """
    source = SWEEP.read_text(encoding="utf-8")
    start = source.index('SECRET="$(find "$STAGE"')
    expression = source[start : source.index("-print -quit)", start)]
    found = _NAME_PATTERN.findall(expression)
    patterns = set(found)
    assert patterns, "no -name patterns were parsed out of the filename sweep"
    predicates = len(_NAME_PREDICATE.findall(expression))
    assert len(found) == predicates, (
        f"the filename sweep carries {predicates} name predicates and this reader parsed "
        f"{len(found)}; one of them is in a spelling the regex above does not read"
    )
    # The one name that must ship. It appears in the expression as the `! -name` exemption
    # rather than as a refusal, so it is removed here rather than probed as a refusal.
    return patterns - {".env.example"}


def tracked_files() -> list[Path]:
    """Every file `git add -A` would stage, or a skip where there is no repository.

    `--others` as well as `--cached`, because the verification loop runs BEFORE the commit
    while every figure describes the committed tree: a new file was untracked when the loop
    read it and tracked a second later, and a loop that passed on one count failed on the
    next at the commit it had just blessed.

    NUL-delimited, because splitting on whitespace drops a tracked path containing a space
    out of the corpus silently, which would quietly narrow every sweep built on this.

    Shared rather than copied: two modules need it, and this suite has twice had a copied
    helper drift from its original.

    `shutil.which` rather than a hardcoded path, and that matters beyond tidiness: this
    module SHIPS, so it runs at the platform's test stage, where `/usr/bin/git` raises
    `FileNotFoundError` on any image that puts git elsewhere. That is a red stage 5 and a
    failed upload with every later stage skipped. No test holds this, so this sentence is
    the only record of why it is written this way.
    """
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not available, so the tracked set cannot be read")
    listed = subprocess.run(  # noqa: S603
        [git, "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        capture_output=True,
        text=True,
        check=False,
    )
    if listed.returncode != 0:
        pytest.skip("not a repository; this is the unpacked package")
    names = [name for name in listed.stdout.split("\0") if name]
    return [ROOT / name for name in names if (ROOT / name).is_file()]
