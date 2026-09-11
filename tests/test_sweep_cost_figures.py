r"""The measured costs of the widenings the credential sweep deliberately does NOT make.

Three figures justify three open gaps, and all three ship: in `scripts/build-package.sh`
beside the rules, in `docs/GATE-RECORDS.md` under Open in scope, and in `CHANGELOG.md`. A
figure is the whole argument for leaving a gap open, so a stale one is an argument nobody
can check, and this project has shipped a wrong one ten times. Twice the same number was
written three ways because the experiment behind it was never recorded, and once one file
contradicted itself about one experiment 154 lines apart.

Prose cannot hold a number. This module re-runs each experiment against the live rules and
the live tree and asserts the figure, so changing either turns the suite red and the number
is re-measured rather than carried forward. The experiments are the documentation: read them
here, not in a comment.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from sweep_rules import keyword_group, load_case_sensitive, load_rules

ROOT = Path(__file__).resolve().parents[1]

#: What each widening costs, measured at `1bdbdb8`. Each entry is (findings, lines).
EXPECTED = {
    "prose rule folded to ignore case": (26, 18),
    "unquoted rule with spaces around the equals": (22, 22),
    "unquoted rule with the leading part of the name optional": (14, 14),
}

#: The part of the third figure that names WHICH findings, because "9 in `src/`" was once
#: written as "twelve indented `key_id=` arguments" and neither half was right.
EXPECTED_IN_SRC = 9
EXPECTED_KEY_ID_IN_SRC = 8

#: The size of the tree every figure above is measured over. It is quoted in all three
#: reporting files and it went stale in the commit that added the two modules that changed
#: it, which is why it is pinned here beside the figures rather than left to prose.
EXPECTED_TRACKED = 159


def _tracked() -> list[Path]:
    """Every tracked file, or a skip where there is no repository to ask.

    `shutil.which`, not a hardcoded path. This module SHIPS, so it runs at the platform's
    test stage, where a hardcoded `/usr/bin/git` raises `FileNotFoundError` on any image
    that puts git elsewhere: five errors, a red stage 5, and the upload fails with every
    later stage skipped. Every other module in this suite resolves a tool this way.
    """
    git = shutil.which("git")
    if git is None:
        pytest.skip("git is not available, so the tracked set cannot be read")
    listed = subprocess.run(  # noqa: S603
        [git, "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=False
    )
    if listed.returncode != 0:
        pytest.skip("not a repository; this is the unpacked package")
    return [ROOT / name for name in listed.stdout.split() if (ROOT / name).is_file()]


def _scan(pattern: str, flags: int, files: list[Path]) -> list[tuple[str, int, str]]:
    """Return one entry per match, carrying the path, the line number and the text."""
    compiled = re.compile(pattern, flags)
    found = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            found += [
                (str(path.relative_to(ROOT)), number, match.group(0).strip())
                for match in compiled.finditer(line)
            ]
    return found


def _widenings() -> dict[str, tuple[str, int]]:
    """Build each experiment from the LIVE rules, so a rule edit changes the experiment."""
    rules = load_rules()
    group = keyword_group()
    prose = rules["Credential written into prose"]
    unquoted = rules["Unquoted environment-file credential"]
    return {
        # Exactly the shipped rule, compiled with IGNORECASE, which is the one flag it does
        # not carry. Nothing else about it changes.
        "prose rule folded to ignore case": (prose, re.MULTILINE | re.IGNORECASE),
        # The shipped rule with `=` replaced by an equals that tolerates surrounding spaces.
        "unquoted rule with spaces around the equals": (
            unquoted.replace("=(?!", "[ \t]*=[ \t]*(?!", 1),
            re.MULTILINE | re.IGNORECASE,
        ),
        # The shipped rule with the name's leading component made optional, which is what
        # would be needed to catch a name that BEGINS with one of the keywords.
        "unquoted rule with the leading part of the name optional": (
            unquoted.replace("[A-Z][A-Z0-9_]*" + group, "(?:[A-Z][A-Z0-9_]*)?" + group, 1),
            re.MULTILINE | re.IGNORECASE,
        ),
    }


@pytest.mark.parametrize("experiment", sorted(EXPECTED))
def test_the_cost_of_each_widening_is_what_the_records_say(experiment: str) -> None:
    """Re-measure, and fail rather than let a shipped figure drift."""
    pattern, flags = _widenings()[experiment]
    found = _scan(pattern, flags, _tracked())
    lines = {(path, number) for path, number, _ in found}

    assert (len(found), len(lines)) == EXPECTED[experiment], (
        f"{experiment} now costs {len(found)} findings on {len(lines)} lines, not "
        f"{EXPECTED[experiment]}. Re-measure and update the figure in "
        "scripts/build-package.sh, docs/GATE-RECORDS.md and CHANGELOG.md, all three."
    )


def test_the_leading_part_figure_is_broken_down_as_the_records_say() -> None:
    """The `src/` share and the `key_id=` share, both of which were once written wrong."""
    pattern, flags = _widenings()["unquoted rule with the leading part of the name optional"]
    found = _scan(pattern, flags, _tracked())
    in_src = [entry for entry in found if entry[0].startswith("src/")]
    key_id = [entry for entry in in_src if entry[2].startswith("key_id=")]

    assert len(in_src) == EXPECTED_IN_SRC, [entry[:2] for entry in in_src]
    assert len(key_id) == EXPECTED_KEY_ID_IN_SRC, [entry[:2] for entry in key_id]


def test_the_shipped_rules_themselves_cost_nothing() -> None:
    """The claim every record makes about the rules as they actually ship: zero."""
    files = _tracked()
    findings = []
    for label, pattern in load_rules().items():
        flags = re.MULTILINE | (0 if label in load_case_sensitive() else re.IGNORECASE)
        findings += [(label, *entry) for entry in _scan(pattern, flags, files)]

    # One, and it is the pinned and declared test double the exemption ledger allows.
    assert len(findings) == 1, findings
    assert findings[0][1] == "tests/test_entra_sign_in.py", findings


#: The three shipped files that report these figures. All three are inside the package, and
#: `docs/ACCREDITATION-REVIEW.md` sends an assessor to the first of them to read the limits
#: at source, so a wrong number here is evidence that misleads rather than a typo.
REPORTING_FILES = (
    ROOT / "scripts" / "build-package.sh",
    ROOT / "docs" / "GATE-RECORDS.md",
    ROOT / "CHANGELOG.md",
)


#: The sentences those files must contain, rendered from the measurement rather than typed.
#: Pinning the measurement alone was the first four attempts at this, and it left the prose
#: free: a reviewer rewrote 22 to 47 and 26 to 99 in all three documents with the whole
#: suite green. The measurement could not drift; the report of it could.
def _rendered(tracked: int) -> dict[str, str]:
    """Render each figure the way the shipped files write it, from the measurement."""
    spaces, spaces_lines = EXPECTED["unquoted rule with spaces around the equals"]
    prose, prose_lines = EXPECTED["prose rule folded to ignore case"]
    leading, _ = EXPECTED["unquoted rule with the leading part of the name optional"]
    across = f"across all {tracked} tracked files"
    return {
        "unquoted rule with spaces around the equals": (
            f"{spaces} findings on {spaces_lines} lines {across}"
        ),
        "prose rule folded to ignore case": (f"{prose} matches on {prose_lines} lines {across}"),
        "unquoted rule with the leading part of the name optional": (
            f"{leading} findings across the tracked tree, {EXPECTED_IN_SRC} of them in `src/`"
        ),
    }


def test_the_tracked_file_count_is_what_the_records_say() -> None:
    """The count is a figure like any other, and it went stale twice.

    Most recently in the commit that added the two modules that changed it.
    """
    assert len(_tracked()) == EXPECTED_TRACKED


#: WHICH file reports WHICH figure. Not every file reports every experiment, and demanding
#: that would be false: the CHANGELOG carries the one that justifies the largest open gap
#: and points at the rest. Declared rather than inferred, so deleting a sentence is red.
REPORTS = {
    "unquoted rule with spaces around the equals": REPORTING_FILES,
    "prose rule folded to ignore case": REPORTING_FILES[:2],
    "unquoted rule with the leading part of the name optional": REPORTING_FILES[:2],
}

#: The shapes a figure is written in, used to find EVERY rendering in those files rather
#: than only the declared ones. Without this a stale number could be added to a fourth
#: place, or a second time in one file, and nothing would read it back.
_RENDERINGS = re.compile(
    r"(\d+) (findings|matches) on (\d+) lines across all (\d+) tracked files"
    r"|(\d+) findings across the tracked tree, (\d+) of them in `src/`"
)


def _flowed(path: Path) -> str:
    """Read a file with its line wrapping and comment markers flattened away."""
    return " ".join(path.read_text(encoding="utf-8").replace("#", " ").split())


@pytest.mark.parametrize("experiment", sorted(EXPECTED))
def test_the_shipped_files_report_the_figure_they_measured(experiment: str) -> None:
    """The other half. A figure nobody reads back is a figure that drifts.

    Each sentence is rebuilt from the measurement and asserted to appear verbatim in every
    file declared to report it, so changing the measurement without changing the prose is
    red and changing the prose without changing the measurement is red. Pinning only the
    measurement was the first four attempts at this class, and it left the prose free: a
    reviewer rewrote 22 to 47 and 26 to 99 in all three documents with the suite green.
    """
    sentence = _rendered(EXPECTED_TRACKED)[experiment]
    for path in REPORTS[experiment]:
        assert sentence in _flowed(path), (
            f"{path.name} does not report {experiment} as measured.\n  expected to find: {sentence}"
        )


def test_no_shipped_file_reports_a_figure_that_was_never_measured() -> None:
    """Every rendering in those files, not only the ones this module went looking for.

    A declared list catches a sentence that goes stale where it stands. It does not catch a
    second copy appearing somewhere else, which is exactly how this class survived four
    fixes: the figure was corrected where the reviewer pointed and left standing 154 lines
    away in the same file.
    """
    allowed = set(_rendered(EXPECTED_TRACKED).values())
    for path in REPORTING_FILES:
        flowed = _flowed(path)
        for match in _RENDERINGS.finditer(flowed):
            assert match.group(0) in allowed, (
                f"{path.name} reports a figure this module did not measure: {match.group(0)!r}"
            )
