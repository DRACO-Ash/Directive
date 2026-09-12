r"""The measured costs of the widenings the credential sweep deliberately does NOT make.

Three figures justify three open gaps, and each ships in one or more of
`scripts/build-package.sh` beside the rules, `docs/GATE-RECORDS.md` under Open in scope, and
`CHANGELOG.md`. Which figure lives where is declared in `REPORTS` and in
`BREAKDOWN_CARRIERS` and is asserted; demanding all three of every file would be false, and
an earlier version of this sentence said it anyway.

A figure is the whole argument for leaving a gap open, so a stale one is an argument nobody
can check, and this project has shipped a wrong one repeatedly: the same number written
three ways because the experiment behind it was never recorded, one file contradicting
itself about one experiment 154 lines apart, and a count that went stale in the commit that
changed what it counted.

Prose cannot hold a number. This module re-runs each experiment against the live rules and
the live tree, asserts that each figure is still SAID where it belongs, and sweeps every
tracked file for anything written in the same shapes. What it does NOT hold is stated with
the shapes below, because every previous version of this docstring claimed a closure the
code did not deliver, and each claim became the next finding.
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


#: Markdown emphasis. `` `97` ``, `**44**`, `~~22~~` and `_88_` all render to a reader as
#: ordinary numbers, and a scanner that does not strip them reads something else. Stripping
#: only where the markup ABUTS a digit was the first attempt and it was half a fix: `**47
#: findings**` kept its trailing pair, because that one follows a letter. So it is stripped
#: everywhere, including underscore.
#:
#: Underscore was excluded once, on the reasoning that it appears inside `key_id=` and
#: `sonar.projectKey=`, which are part of the clauses being matched. That reasoning was
#: wrong: normalisation is applied to BOTH sides of every comparison, so mangling is
#: symmetric and harmless, and `_99_ matches on _88_ lines` was invisible for one character's
#: worth of caution.
_EMPHASIS = re.compile(r"[`*~_]+")


def _normalise(text: str) -> str:
    """Render text the way a reader sees it: no wrapping, no comment markers, no emphasis.

    Applied to BOTH sides of every comparison, and to the SHAPES below before they are
    compiled. Normalising only one side is not a smaller version of this control, it is a
    hole: widening the stripper to remove backticks while four shapes still contained
    literal backticks made those four unmatchable, and a false figure of that shape shipped
    green in the accreditation record. That is what `test_every_shape_matches_its_own_rendering`
    exists to catch, and it is the check to keep whenever this function changes.
    """
    return " ".join(_EMPHASIS.sub("", text).replace("#", " ").split())


#: Every shape a figure of this kind is written in, as a TEMPLATE with `{n}` where a number
#: goes. Written once, normalised through `_normalise`, then compiled: pattern and haystack
#: therefore agree by construction, which is the thing that broke when the stripper was
#: widened and four hand-written alternatives kept their backticks.
#:
#: The sweep reads each occurrence of each shape in every tracked file and asserts the
#: number; the carrier maps assert that each figure is still SAID where it belongs. Both
#: halves are needed and neither reason is theoretical: a clause with a wrong number was
#: caught and a clause reworded away was not, until the carrier map existed.
#:
#: THE RESIDUAL, stated in both directions because only one of them was stated before.
#: Adding a new phrasing to a document without adding it here drifts silently, and there is
#: no way to close that with a regular expression. REMOVING a phrasing from here drifts
#: silently too, and that one IS closable: the shapes in `UNBACKED_SHAPES` back no declared
#: figure and exist only to ban a wording this project has retired or could regress to, so
#: nothing else would miss them. Deleting three shapes left the suite green while a false
#: figure sailed into the accreditation record. Changing the set costs an edit in three
#: places, here, `FROZEN_SHAPES` and `PHRASINGS`, and four for an unbacked one, which is
#: also in `UNBACKED_SHAPES`.
_SHAPES = (
    "{n} findings on {n} lines across every tracked file",
    "{n} matches on {n} lines across every tracked file",
    "{n} findings on {n} lines",
    "{n} matches on {n} lines",
    "{n} findings across the tracked tree, {n} of them in `src/`",
    "{n} tracked files",
    "{n} Python keyword arguments",
    "{n} `sonar.projectKey=` lines",
    "{n} of them in the skill templates",
    "{n} in this project's own",
    "{n} are `key_id=`",
    "{n} is `keys=`",
    "{n} findings across every tracked file",
    "{n} finding across every tracked file",
    "{n} false positives",
)


#: The same set, written out again on purpose, and be exact about what this holds, because
#: a reader who thinks it is a redundant copy will update it reflexively and it will hold
#: nothing. MEMBERSHIP is held by `PHRASINGS`, which catches a deletion semantically: the
#: phrasing stops being readable. What `FROZEN_SHAPES` uniquely holds is ORDER, and order is
#: load-bearing: the alternation is leftmost-first, and the sweep compares the text that
#: matched against the allowed set, so a reorder changes which alternative wins. The sweep
#: does catch a harmful reorder, measured; this makes it red at the anchor rather than four
#: hundred lines away in a message about a document.
FROZEN_SHAPES = (
    "{n} findings on {n} lines across every tracked file",
    "{n} matches on {n} lines across every tracked file",
    "{n} findings on {n} lines",
    "{n} matches on {n} lines",
    "{n} findings across the tracked tree, {n} of them in `src/`",
    "{n} tracked files",
    "{n} Python keyword arguments",
    "{n} `sonar.projectKey=` lines",
    "{n} of them in the skill templates",
    "{n} in this project's own",
    "{n} are `key_id=`",
    "{n} is `keys=`",
    "{n} findings across every tracked file",
    "{n} finding across every tracked file",
    "{n} false positives",
)

#: One concrete phrasing per shape, with a number that is NOT the measured one, so each
#: shape is exercised against its own pattern rather than against whichever sibling happens
#: to match first. The two suffix-free forms and the tree-size form are here because they
#: are the only guards against a wording this project has actually written and retired.
PHRASINGS = {
    "{n} findings on {n} lines across every tracked file": (
        "47 findings on 47 lines across every tracked file"
    ),
    "{n} matches on {n} lines across every tracked file": (
        "99 matches on 88 lines across every tracked file"
    ),
    "{n} findings on {n} lines": "47 findings on 47 lines",
    "{n} matches on {n} lines": "99 matches on 88 lines",
    "{n} findings across the tracked tree, {n} of them in `src/`": (
        "88 findings across the tracked tree, 77 of them in `src/`"
    ),
    "{n} tracked files": "160 tracked files",
    "{n} Python keyword arguments": "31 Python keyword arguments",
    "{n} `sonar.projectKey=` lines": "98 `sonar.projectKey=` lines",
    "{n} of them in the skill templates": "40 of them in the skill templates",
    "{n} in this project's own": "4 in this project's own",
    "{n} are `key_id=`": "12 are `key_id=`",
    "{n} is `keys=`": "3 is `keys=`",
    "{n} findings across every tracked file": "9 findings across every tracked file",
    "{n} finding across every tracked file": "9 finding across every tracked file",
    "{n} false positives": "9 false positives",
}


#: The markup a reader sees through and a scanner must. Every assertion in this module
#: normalises BOTH sides of its comparison, which makes them all symmetric and therefore
#: blind to the normaliser itself: a reviewer turned `_EMPHASIS` off entirely and shipped
#: four false figures into the accreditation record and the release note with the whole
#: suite green. This is the one leg that is deliberately ASYMMETRIC. The shapes carry no
#: markup and these renderings do, so the scanner can only read them if the stripper is
#: doing its job, and narrowing it to drop any one of these markers turns the corpus red.
EMPHASIS_MARKERS = ("`", "**", "~~", "_")

#: The characters the stripper removes, read out of its own pattern. Asserted against the
#: markers above, so trimming either one alone is red: the marker corpus had no anchor of
#: its own and could be cut to a single entry with the suite green.
_STRIPPED_CHARACTERS = frozenset(re.sub(r"[\[\]+]", "", _EMPHASIS.pattern))

_DIGITS = re.compile(r"\d+")


def _emphasised(phrasing: str, marker: str) -> str:
    """Wrap every number in one phrasing in markup, the way a document actually writes it."""
    return _DIGITS.sub(lambda run: f"{marker}{run.group(0)}{marker}", phrasing)


def _shape_pattern(template: str) -> str:
    """Compile one template against normalised text, escaping everything but the numbers."""
    return r"\d+".join(re.escape(part) for part in _normalise(template).split("{n}"))


_RENDERINGS = re.compile("|".join(_shape_pattern(shape) for shape in _SHAPES))


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


def _allowed() -> set[str]:
    """Every rendering this module has measured, normalised, as the sweep compares them."""
    allowed = {_normalise(value) for value in _rendered().values()}
    allowed |= {_normalise(f"{count} {clause}") for clause, count in _breakdowns().items()}
    return allowed


def _is_self(path: Path) -> bool:
    """Report whether this is the module itself, which writes the figures it asserts.

    A helper rather than an inline comparison so it can be held: widening it to every path
    under `tests/` retired the sweep over every shipped test module with the suite green,
    and `tests/` ships in the package.
    """
    return path.resolve() == SELF


def test_no_tracked_file_reports_a_figure_that_was_never_measured() -> None:
    """EVERY tracked file, not the three that were declared.

    A declared list catches a sentence going stale where it stands. It does not catch a copy
    appearing elsewhere, and that is how this class survived five fixes: a figure corrected
    where the reviewer pointed and left standing 154 lines away, then false figures placed in
    two shipped documents outside the declared three with the whole suite green.
    """
    allowed = _allowed()

    for path in _tracked():
        if _is_self(path):
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
        if path.resolve() in declared or _is_self(path):
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


@pytest.mark.parametrize("shape", _SHAPES)
def test_every_shape_matches_its_own_rendering(shape: str) -> None:
    """The scanner must be able to read what it is written to read.

    Widening `_EMPHASIS` to strip backticks made four hand-written alternatives unmatchable,
    because they still carried backticks themselves, and the sweep went silently blind to a
    whole canonical sentence and three clauses. Nothing failed. A false figure of that shape
    then passed green in the accreditation record, which is the document the sweep's own comment
    sends an assessor to.

    This asserts the property that was violated: each shape, rendered with a number and put
    through the same normalisation as a file, is found by the compiled pattern. It is the
    check to keep whenever `_EMPHASIS` or `_SHAPES` changes.
    """
    rendered = _normalise(shape.replace("{n}", "42"))

    # Its OWN pattern, not the whole alternation: a shape subsumed by a shorter sibling
    # would otherwise pass while being individually broken, which was measured.
    assert re.compile(_shape_pattern(shape)).search(rendered), (
        f"the scanner cannot read its own shape {shape!r}, which renders as {rendered!r}. "
        "Something normalised on one side of the comparison and not the other."
    )


def test_every_declared_figure_is_a_shape_the_scanner_reads() -> None:
    """And the other direction: every figure this module asserts is one it can also find.

    A constant with a carrier but no shape is held in one direction only: the sentence must
    be present, but a SECOND wrong copy elsewhere goes unread. That was the state of the
    live-cost figure for a commit.
    """
    rendered = list(_rendered().values())
    rendered += [f"{count} {clause}" for clause, count in _breakdowns().items()]

    for sentence in rendered:
        normalised = _normalise(sentence)

        assert _RENDERINGS.search(normalised), (
            f"{sentence!r} is asserted but matches no shape, so a wrong copy of it "
            "elsewhere in the tree would not be read back"
        )


#: The shapes that back no declared figure at all, derived and asserted below rather than
#: counted in a comment: the count was prose in a module whose whole purpose is that prose
#: cannot hold a number, and rewriting it left everything green. Both are pure ban-nets.
#: `{n} tracked files` is the only guard against the tree-size figure returning after it was
#: deliberately removed from every document, and the plural `findings across every tracked
#: file` guards the singular live-cost sentence against being pluralised into a shape no
#: constant covers. The two suffix-free forms are NOT here: they are substrings of the
#: canonical sentences, so a declared figure does back them.
UNBACKED_SHAPES = (
    "{n} tracked files",
    "{n} findings across every tracked file",
)


def test_the_unbacked_shapes_are_the_ones_named() -> None:
    """Which shapes are pure ban-nets, derived rather than asserted in a comment.

    A shape backed by a declared figure is held by that figure's carrier and its constant.
    These are held by nothing else, which is why deleting a shape was green before
    `PHRASINGS` existed, and naming them makes adding a declared figure for one of them a
    deliberate change rather than a silent one.
    """
    declared = [_normalise(value) for value in _rendered().values()]
    declared += [_normalise(f"{count} {clause}") for clause, count in _breakdowns().items()]

    unbacked = tuple(
        shape
        for shape in _SHAPES
        if not any(re.compile(_shape_pattern(shape)).search(text) for text in declared)
    )

    assert unbacked == UNBACKED_SHAPES


def test_the_shape_set_is_the_frozen_one() -> None:
    """Deleting a shape made the sweep blind with the suite green.

    `_SHAPES` is parametrised over, so a deleted entry is not tested. The shapes in
    `UNBACKED_SHAPES` back no declared figure at all: removing `{n} tracked files` reopens
    the tree-size figure that was deliberately taken out of every document. A reviewer
    deleted three shapes and shipped a false figure into the accreditation record with the
    suite green.

    `PHRASINGS` catches a deletion semantically, so a two-place edit is red. What this
    anchor adds is ORDER: the alternation is leftmost-first and the sweep judges the text
    that matched, so a reorder changes the verdict. The sweep does catch a harmful reorder
    on its own; this makes it red here rather than four hundred lines away.
    """
    assert _SHAPES == FROZEN_SHAPES


@pytest.mark.parametrize("shape", _SHAPES)
def test_every_shape_has_a_phrasing_that_exercises_it(shape: str) -> None:
    """And the corpus is total, so a shape added without one is not quietly unexercised."""
    assert shape in PHRASINGS, f"{shape!r} has no phrasing in PHRASINGS"

    pattern = re.compile(_shape_pattern(shape))

    assert pattern.search(_normalise(PHRASINGS[shape])), (
        f"{PHRASINGS[shape]!r} does not exercise {shape!r}"
    )


def test_every_phrasing_is_banned_by_the_compiled_scanner() -> None:
    """The corpus, end to end: read AND refused.

    The assertion used to stop at `search`, which proves only that the scanner can READ the
    phrasing. A phrasing whose number happened to be a measured one would then be read and
    ALLOWED, and the test named for banning would pass. It was true by luck rather than by
    construction, measured: the intersection was empty.
    """
    allowed = _allowed()
    for shape, phrasing in PHRASINGS.items():
        normalised = _normalise(phrasing)

        match = _RENDERINGS.search(normalised)

        assert match is not None, (
            f"{phrasing!r} would not be read back, so a figure in the shape {shape!r} could "
            "be written into a shipped document unnoticed"
        )
        # The MATCHED text, which is what the sweep judges. Comparing the whole phrasing let
        # a phrasing whose matched substring was an allowed figure pass while the sweep
        # allowed it: `0 false positives in the tree` is not an allowed string, and
        # `0 false positives` is.
        assert match.group(0) not in allowed, (
            f"{phrasing!r} matches as {match.group(0)!r}, a number this module MEASURED, so "
            "it is an allowed figure rather than a banned one and this test proves nothing"
        )


@pytest.mark.parametrize("marker", EMPHASIS_MARKERS)
def test_the_scanner_reads_a_figure_through_every_markup_it_knows(marker: str) -> None:
    """The one asymmetric leg, and the reason it exists.

    Every other assertion normalises both sides, so turning `_EMPHASIS` off entirely leaves
    all of them green: a reviewer did exactly that and shipped four false figures into
    `docs/ACCREDITATION-REVIEW.md` and `CHANGELOG.md` with the suite green. The shapes
    carry no markup; these renderings do. So the scanner can read them only while the
    stripper works, and dropping any one marker from it turns this red.

    This is the component this project has failed on three times running: emphasis hiding a
    digit, then strikethrough, then a backtick regression. It is the check to keep.
    """
    for shape, phrasing in PHRASINGS.items():
        marked = _emphasised(phrasing, marker)

        # The fixture must actually emphasise. Reducing `_emphasised` to `return phrasing`
        # left this test asserting what every other test already asserts, and the stripper
        # was unheld again for one invisible line.
        assert marker in marked, f"{marker!r} was not applied to {phrasing!r}"
        assert _RENDERINGS.search(_normalise(marked)), (
            f"{marked!r} is invisible to the scanner, so a figure in the shape {shape!r} "
            f"wrapped in {marker!r} would ship unread. The emphasis stripper has been "
            "narrowed or disabled."
        )


def test_only_this_module_is_skipped_by_the_sweep() -> None:
    """The sweep's one exemption, asserted rather than inlined.

    Widening the skip to every path under `tests/` retired the sweep over every shipped test
    module with the suite green, and `tests/` ships in the package.
    """
    skipped = [path for path in _tracked() if _is_self(path)]

    assert [path.resolve() for path in skipped] == [SELF]


def test_the_marker_corpus_covers_the_stripper() -> None:
    """The markers exercised must be the characters the stripper removes.

    `EMPHASIS_MARKERS` had no anchor of its own, so cutting it to one entry was green and
    the other three markups went unexercised. Reading the character class out of the
    stripper's own pattern ties the two together: narrowing either alone is red.
    """
    exercised = {character for marker in EMPHASIS_MARKERS for character in marker}

    assert exercised == set(_STRIPPED_CHARACTERS)
