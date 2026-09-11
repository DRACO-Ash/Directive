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
EXPECTED_KEYS_IN_SRC = 1

#: The clauses INSIDE a pinned sentence, which were free while the sentence was held. A
#: reviewer set 19 to 31, 7 to 98 and the word "eight" to "twelve" with the suite green, and
#: the first of those is the exact figure this project recorded as wrong at its thirteenth
#: security gate. Every one of them is a digit in the documents now, so the sweep can read
#: it back; a figure written as a word is invisible to any scanner and is a defect on its
#: own.
EXPECTED_PYTHON_KEYWORD_ARGUMENTS = 19
EXPECTED_SONAR = 7
EXPECTED_SONAR_IN_TEMPLATES = 6
#: The remainder of the sonar split. Pinning 7 and 6 and leaving this free let a reviewer
#: set it to 4, which made the sentence contradict itself (6 and 4 against a total of 7)
#: with nothing red. A figure decomposed into parts needs every part held, not all but one.
EXPECTED_SONAR_IN_PROJECT = 1

#: What the rules as they SHIP cost on this tree. One, and it is the declared test double
#: the exemption ledger pins by path, digest and match count. It was written as the word
#: "zero" in three documents, which was imprecise as well as unreadable by any scanner, and
#: when it became a digit it was still wired to nothing: rewriting it to 0 was green.
EXPECTED_LIVE_FINDINGS = 1

#: What the rules cost on content they were NOT meant to match. The distinction matters: the
#: one live finding is a true positive on a declared double, so "no false positives" and
#: "one finding" are both true and say different things. Written as the word "zero" in two
#: shipped files, where no scanner could read it.
EXPECTED_FALSE_POSITIVES = 0

#: The tree size is NOT pinned and is no longer written in any document. It was decoration:
#: the argument a reader needs is "this many findings across the tracked tree", and the
#: cardinality of the tree adds nothing to it. As a figure it went stale three times,
#: including in the commit that added the module meant to stop that, so it is gone rather
#: than corrected a fourth time. Removing a figure is a better fix than pinning one nobody
#: needs.


def _tracked() -> list[Path]:
    """Every file that WOULD be tracked after `git add -A`, or a skip with no repository.

    `--others --exclude-standard` as well as `--cached`, and that is the whole point rather
    than thoroughness. The verification loop runs before the commit, and every figure in
    this module describes the committed tree. A new file is untracked while the loop reads
    it and tracked a second later, so a loop that passed on 159 files failed on 160 at the
    commit it had just blessed. That has now happened three times, most recently in the
    commit written to stop it. Counting what `git add -A` would stage makes the measurement
    the same on both sides of the commit, which removes the trap rather than resetting it.

    `shutil.which`, not a hardcoded path. This module SHIPS, so it runs at the platform's
    test stage, where a hardcoded `/usr/bin/git` raises `FileNotFoundError` on any image
    that puts git elsewhere: a red stage 5 and an upload that fails with every later stage
    skipped. Every other module in this suite resolves a tool this way.
    """
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


#: The files that report these figures in their canonical sentences. Declared, so deleting a
#: sentence from one of them is red. It is NOT the boundary of the sweep below: a reviewer
#: put false figures into `README.md` and `docs/ACCREDITATION-REVIEW.md`, both of which ship,
#: and a three-file list read neither. `docs/ACCREDITATION-REVIEW.md` is named in the comment
#: that sends an assessor to the sweep to read its limits at source, which is precisely why a
#: restatement there has to be read back.
REPORTING_FILES = (
    ROOT / "scripts" / "build-package.sh",
    ROOT / "docs" / "GATE-RECORDS.md",
    ROOT / "CHANGELOG.md",
)

#: WHICH file reports WHICH sentence. Not every file reports every experiment, and demanding
#: that would be false: the CHANGELOG carries the one that justifies the largest open gap and
#: points at the rest. Declared, so deleting a sentence is red, and the union is asserted
#: against the tree below, so adding a carrier is red too.
REPORTS = {
    "unquoted rule with spaces around the equals": REPORTING_FILES,
    "prose rule folded to ignore case": REPORTING_FILES[:2],
    "unquoted rule with the leading part of the name optional": REPORTING_FILES[:2],
}

#: This module writes the figures it asserts, so it would match its own renderings.
SELF = Path(__file__).resolve()


def _rendered() -> dict[str, str]:
    """Render each figure the way the shipped files write it, from the measurement."""
    spaces, spaces_lines = EXPECTED["unquoted rule with spaces around the equals"]
    prose, prose_lines = EXPECTED["prose rule folded to ignore case"]
    leading, _ = EXPECTED["unquoted rule with the leading part of the name optional"]
    across = "across every tracked file"
    return {
        "unquoted rule with spaces around the equals": (
            f"{spaces} findings on {spaces_lines} lines {across}"
        ),
        "prose rule folded to ignore case": (f"{prose} matches on {prose_lines} lines {across}"),
        "unquoted rule with the leading part of the name optional": (
            f"{leading} findings across the tracked tree, {EXPECTED_IN_SRC} of them in `src/`"
        ),
    }


def _breakdowns() -> dict[str, int]:
    """Return the clauses inside those sentences, each pinned to its own measurement."""
    return {
        "Python keyword arguments": EXPECTED_PYTHON_KEYWORD_ARGUMENTS,
        "`sonar.projectKey=` lines": EXPECTED_SONAR,
        "of them in the skill templates": EXPECTED_SONAR_IN_TEMPLATES,
        "in this project's own": EXPECTED_SONAR_IN_PROJECT,
        "finding across every tracked file": EXPECTED_LIVE_FINDINGS,
        "false positives": EXPECTED_FALSE_POSITIVES,
        "are `key_id=`": EXPECTED_KEY_ID_IN_SRC,
        "is `keys=`": EXPECTED_KEYS_IN_SRC,
    }


#: WHERE each breakdown clause must appear. The negative sweep catches a clause whose NUMBER
#: is wrong; it cannot catch one that is deleted or reworded away, and a reviewer rewrote
#: `8 are key_id= and 1 is keys=` into a form carrying 12 and 3 with the suite green. A
#: figure needs both: nothing says it wrongly, and the thing that should say it does.
_SWEEP = ROOT / "scripts" / "build-package.sh"
_RECORDS = ROOT / "docs" / "GATE-RECORDS.md"
_CHANGELOG = ROOT / "CHANGELOG.md"

#: WHICH file must carry WHICH clause, one entry each rather than a blanket "both files".
#: The blanket form was correct only while every clause happened to live in both; the first
#: clause that legitimately belongs in one would have forced a false demand on the other.
BREAKDOWN_CARRIERS = {
    "Python keyword arguments": (_SWEEP, _RECORDS),
    "`sonar.projectKey=` lines": (_SWEEP, _RECORDS),
    "of them in the skill templates": (_SWEEP, _RECORDS),
    "in this project's own": (_SWEEP, _RECORDS),
    "are `key_id=`": (_SWEEP, _RECORDS),
    "is `keys=`": (_SWEEP, _RECORDS),
    "finding across every tracked file": (_CHANGELOG,),
    "false positives": (_SWEEP,),
}


#: Every shape a figure of this kind is written in. The sweep reads each occurrence in every
#: tracked file and asserts the number; the carrier maps assert that each figure is still
#: SAID where it should be. Both halves are needed and the reasons are not theoretical: a
#: clause with a wrong number was caught and a clause reworded away was not, until the
#: carrier map existed.
#:
#: The residual, named rather than waved at: a figure written in a shape not listed below is
#: unread. That is a narrower gap than it was, since emphasis no longer hides a digit and
#: every declared clause must be present, but adding a new phrasing to a document without
#: adding it here still drifts silently. There is no way to close that with a regular
#: expression, so it is written down instead.
_RENDERINGS = re.compile(
    r"(?:\d+) (?:findings|matches) on (?:\d+) lines across every tracked file"
    r"|(?:\d+) (?:findings|matches) on (?:\d+) lines"
    r"|(?:\d+) findings across the tracked tree, (?:\d+) of them in `src/`"
    r"|(?:\d+) tracked files"
    r"|(?:\d+) Python keyword arguments"
    r"|(?:\d+) `sonar\.projectKey=` lines"
    r"|(?:\d+) of them in the skill templates"
    r"|(?:\d+) are `key_id=`"
    r"|(?:\d+) is `keys=`"
    r"|(?:\d+) findings? across every tracked file"
    r"|(?:\d+) false positives"
)


#: Markdown emphasis. `` `97` ``, `**44**` and `~~22~~` all render to a reader as ordinary
#: numbers, and a scanner that does not strip them reads something else. Stripping only
#: where the markup ABUTS a digit was the first attempt and it was half a fix: `**47
#: findings**` kept its trailing pair, because that one follows a letter, and the match
#: broke. So it is stripped everywhere.
#:
#: Backtick, asterisk and tilde, and NOT underscore: this repository writes `key_id=` and
#: `sonar.projectKey=` as figures in their own clauses, and no document here uses underscore
#: emphasis (measured: none). Stripping it would mangle the identifiers the clauses are
#: about, for no gain.
_EMPHASIS = re.compile(r"[`*~]+")


def _normalise(text: str) -> str:
    """Render text the way a reader sees it: no wrapping, no comment markers, no emphasis.

    Applied to BOTH sides of every comparison. Normalising only the file would make the
    expected clauses unmatchable, because several of them carry backticks themselves.
    """
    return " ".join(_EMPHASIS.sub("", text).replace("#", " ").split())


def _flowed(path: Path) -> str:
    """Read one file, normalised."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        # The same guard `_scan` carries, and defensive by symmetry rather than by
        # measurement: no tracked file fails a UTF-8 read today, so no mutation shows it
        # failing. It is here so the first tracked binary is a finding about figures rather
        # than a decode traceback.
        return ""
    return _normalise(text)


@pytest.mark.parametrize("experiment", sorted(EXPECTED))
def test_the_shipped_files_report_the_figure_they_measured(experiment: str) -> None:
    """Each canonical sentence, asserted verbatim where it is declared to appear.

    Rebuilt from the measurement, so changing the measurement without changing the prose is
    red and changing the prose without changing the measurement is red.
    """
    sentence = _rendered()[experiment]
    for path in REPORTS[experiment]:
        assert _normalise(sentence) in _flowed(path), (
            f"{path.name} does not report {experiment} as measured.\n  expected to find: {sentence}"
        )


def test_no_tracked_file_reports_a_figure_that_was_never_measured() -> None:
    """EVERY tracked file, not the three that were declared.

    A declared list catches a sentence going stale where it stands. It does not catch a copy
    appearing elsewhere, and that is how this class survived five fixes: a figure corrected
    where the reviewer pointed and left standing 154 lines away, then false figures placed in
    two shipped documents outside the declared three with the whole suite green.
    """
    allowed = {_normalise(value) for value in _rendered().values()}
    allowed |= {_normalise(f"{count} {clause}") for clause, count in _breakdowns().items()}

    for path in _tracked():
        if path.resolve() == SELF:
            continue
        for match in _RENDERINGS.finditer(_flowed(path)):
            relative = path.relative_to(ROOT)
            assert match.group(0) in allowed, (
                f"{relative} reports a figure this module did not measure: {match.group(0)!r}"
            )


def test_the_breakdown_clauses_are_what_the_records_say() -> None:
    """The clauses inside a pinned sentence, measured rather than trusted.

    `26 matches on 18 lines` was held while the `19 Python keyword arguments` and
    `7 sonar.projectKey= lines` that decompose it were free to be anything.
    """
    pattern, flags = _widenings()["prose rule folded to ignore case"]
    found = _scan(pattern, flags, _tracked())
    sonar = [entry for entry in found if "projectkey" in entry[2].lower()]
    templates = [entry for entry in sonar if "/templates/" in entry[0]]

    assert len(found) - len(sonar) == EXPECTED_PYTHON_KEYWORD_ARGUMENTS
    assert len(sonar) == EXPECTED_SONAR
    assert len(templates) == EXPECTED_SONAR_IN_TEMPLATES


def test_the_leading_part_breakdown_is_what_the_records_say() -> None:
    """The same, for the other decomposed figure."""
    pattern, flags = _widenings()["unquoted rule with the leading part of the name optional"]
    found = _scan(pattern, flags, _tracked())
    in_src = [entry for entry in found if entry[0].startswith("src/")]
    key_id = [entry for entry in in_src if entry[2].startswith("key_id=")]

    assert len(in_src) == EXPECTED_IN_SRC
    assert len(key_id) == EXPECTED_KEY_ID_IN_SRC
    assert len(in_src) - len(key_id) == EXPECTED_KEYS_IN_SRC


def test_the_shipped_rules_themselves_cost_what_the_records_say() -> None:
    """What the rules as they ship actually cost on this tree: 1, the declared exemption.

    It is the only test asserting that the live rule set does not fire on ordinary content,
    and every "no false positives" sentence in the shipped documents rests on it. The figure
    is `EXPECTED_LIVE_FINDINGS` rather than a literal here, so the documents and this
    assertion move together.
    """
    files = _tracked()
    findings = []
    for label, pattern in load_rules().items():
        flags = re.MULTILINE | (0 if label in load_case_sensitive() else re.IGNORECASE)
        findings += [(label, *entry) for entry in _scan(pattern, flags, files)]

    # The declared test double the exemption ledger pins by path, digest and match count.
    assert len(findings) == EXPECTED_LIVE_FINDINGS, findings
    assert findings[0][1] == "tests/test_entra_sign_in.py", findings

    # And separately: nothing the rules were not meant to match. The two figures are written
    # in different documents and mean different things, so both are held.
    false_positives = [entry for entry in findings if entry[1] != "tests/test_entra_sign_in.py"]
    assert len(false_positives) == EXPECTED_FALSE_POSITIVES, false_positives


def test_no_file_outside_the_declared_set_carries_a_canonical_sentence() -> None:
    """The declared map says where a figure lives; this says nowhere else does.

    Deleting a sentence is caught by the map. Adding one somewhere undeclared was not, and
    two shipped documents outside the declared three were given false figures with the whole
    suite green.
    """
    sentences = _rendered()
    declared = {path.resolve() for files in REPORTS.values() for path in files}
    for path in _tracked():
        if path.resolve() in declared or path.resolve() == SELF:
            continue
        flowed = _flowed(path)
        carried = [name for name, sentence in sentences.items() if _normalise(sentence) in flowed]

        assert not carried, (
            f"{path.relative_to(ROOT)} reports {carried} and is not in REPORTS; add it there "
            "so the figure is read back, or remove the sentence"
        )


@pytest.mark.parametrize("clause", sorted(_breakdowns()))
def test_every_breakdown_clause_is_still_said_where_it_belongs(clause: str) -> None:
    """The positive half for the clauses inside a pinned sentence.

    The sweep catches a clause carrying the wrong number. It cannot catch one deleted or
    reworded into a different phrasing, and rewriting `8 are key_id= and 1 is keys=` into a
    sentence carrying 12 and 3 passed everything. Both halves, for clauses as for sentences.
    """
    rendered = f"{_breakdowns()[clause]} {clause}"
    for path in BREAKDOWN_CARRIERS[clause]:
        assert _normalise(rendered) in _flowed(path), (
            f"{path.name} no longer says {rendered!r}; if the wording changed, change it here "
            "too, and if the measurement changed, re-measure and change both"
        )


def test_the_sonar_split_adds_up() -> None:
    """The three parts of one figure, asserted against each other as well as the tree.

    Pinning the total and one part left the remainder free, and a reviewer set it so the
    sentence contradicted itself with nothing red.
    """
    assert EXPECTED_SONAR_IN_TEMPLATES + EXPECTED_SONAR_IN_PROJECT == EXPECTED_SONAR

    pattern, flags = _widenings()["prose rule folded to ignore case"]
    found = _scan(pattern, flags, _tracked())
    sonar = [entry for entry in found if "projectkey" in entry[2].lower()]
    templates = [entry for entry in sonar if "/templates/" in entry[0]]

    assert len(sonar) - len(templates) == EXPECTED_SONAR_IN_PROJECT
