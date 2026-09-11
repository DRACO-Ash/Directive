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
import subprocess
from pathlib import Path

import pytest

from sweep_rules import KEYWORD_GROUP, load_case_sensitive, load_rules

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


def _tracked() -> list[Path]:
    listed = subprocess.run(  # noqa: S603
        ["/usr/bin/git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=False
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
            unquoted.replace(
                "[A-Z][A-Z0-9_]*" + KEYWORD_GROUP, "(?:[A-Z][A-Z0-9_]*)?" + KEYWORD_GROUP, 1
            ),
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
