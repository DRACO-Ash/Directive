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
from pathlib import Path

import pytest

from sweep_rules import keyword_group, load_case_sensitive, load_rules, tracked_files

ROOT = Path(__file__).resolve().parents[1]

#: What each widening costs, measured at `1bdbdb8`. Each entry is (findings, lines).
EXPECTED = {
    "prose rule folded to ignore case": (26, 18),
    "unquoted rule with spaces around the equals": (22, 22),
    "unquoted rule with the leading part of the name optional": (14, 14),
    "quoted rule with bare key and keys in its keyword group": (7, 7),
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

#: The part of the fourth figure that is the PRICE. Seven is what the widened quoted rule
#: finds; one of those is the declared test double the shipped rules already report, so six
#: is what adding the keywords would cost that is not already paid. The two numbers say
#: different things and recording only the total would read as six new findings too many.
EXPECTED_BEYOND_THE_DOUBLE = 6

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
    quoted = rules["Generic API key assignment"]
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
        # The quoted rule with bare `key` and `keys` added to its keyword group. The
        # unquoted rule's group carries both; the quoted rule's does not, so the two rules
        # do not cover the same names and the difference had no price recorded against it.
        "quoted rule with bare key and keys in its keyword group": (
            quoted.replace("api[_-]?key|", "api[_-]?key|key|keys|", 1),
            re.MULTILINE | re.IGNORECASE,
        ),
    }


@pytest.mark.parametrize("experiment", sorted(EXPECTED))
def test_the_cost_of_each_widening_is_what_the_records_say(experiment: str) -> None:
    """Re-measure, and fail rather than let a shipped figure drift."""
    pattern, flags = _widenings()[experiment]
    found = _scan(pattern, flags, tracked_files())
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
    "quoted rule with bare key and keys in its keyword group": REPORTING_FILES[:2],
}

#: This module writes the figures it asserts, so it would match its own renderings.
SELF = Path(__file__).resolve()


def _rendered() -> dict[str, str]:
    """Render each figure the way the shipped files write it, from the measurement."""
    spaces, spaces_lines = EXPECTED["unquoted rule with spaces around the equals"]
    prose, prose_lines = EXPECTED["prose rule folded to ignore case"]
    leading, _ = EXPECTED["unquoted rule with the leading part of the name optional"]
    quoted, quoted_lines = EXPECTED["quoted rule with bare key and keys in its keyword group"]
    across = "across every tracked file"
    return {
        "unquoted rule with spaces around the equals": (
            f"{spaces} findings on {spaces_lines} lines {across}"
        ),
        "prose rule folded to ignore case": (f"{prose} matches on {prose_lines} lines {across}"),
        "unquoted rule with the leading part of the name optional": (
            f"{leading} findings across the tracked tree, {EXPECTED_IN_SRC} of them in `src/`"
        ),
        "quoted rule with bare key and keys in its keyword group": (
            f"{quoted} findings on {quoted_lines} lines {across}"
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
        "beyond the declared double": EXPECTED_BEYOND_THE_DOUBLE,
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
    "beyond the declared double": (_SWEEP, _RECORDS),
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
    green in the accreditation record. Measured: compiling the shapes from the raw template
    instead of the normalised one is red at `test_every_shape_has_a_phrasing_that_exercises_it`,
    on exactly those four shapes, and in other places besides. That is the check to keep
    whenever this function changes.
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
    "{n} beyond the declared double",
    "{n} findings across every tracked file",
    "{n} finding across every tracked file",
    "{n} false positives",
)


#: The same set, written out again on purpose, and be exact about what this holds, because
#: a reader who thinks it is a redundant copy will update it reflexively and it will hold
#: nothing.
#:
#: Measured, and narrowly: for a shape SUBSUMED BY A LONGER SIBLING, which is
#: `{n} findings on {n} lines` and `{n} matches on {n} lines`, this anchor is the only test
#: that sees a coordinated deletion from `_SHAPES` and `PHRASINGS` together. Those two are
#: substrings of a canonical sentence, so neither the declared-figure direction nor
#: `UNBACKED_SHAPES` covers them. For the other thirteen shapes another test is red as well,
#: and the sweep catches a harmful reorder on its own. That narrow case is the whole reason
#: this stays, and an earlier version of this comment claimed a general one.
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
    "{n} beyond the declared double",
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
    "{n} beyond the declared double": "13 beyond the declared double",
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


def _entitled() -> set[str]:
    """Return the renderings the PRICE PASSAGE may carry a digit for, and no others.

    The whole allowed set is every figure this module measured, across four experiments and
    eight breakdown clauses. Clearing all of it from this passage before looking for a loose
    digit let a clause borrow another experiment's number and say something false about this
    one: `There are 0 false positives among them in auth.py.` is the prose rule's figure
    used as a claim about the quoted rule's split, and it was green.
    """
    quoted = _rendered()["quoted rule with bare key and keys in its keyword group"]
    clause = f"{EXPECTED_BEYOND_THE_DOUBLE} beyond the declared double"
    return {_normalise(quoted), _normalise(clause)}


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

    for path in tracked_files():
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
    found = _scan(pattern, flags, tracked_files())
    sonar = [entry for entry in found if "projectkey" in entry[2].lower()]
    templates = [entry for entry in sonar if "/templates/" in entry[0]]

    assert len(found) - len(sonar) == EXPECTED_PYTHON_KEYWORD_ARGUMENTS
    assert len(sonar) == EXPECTED_SONAR
    assert len(templates) == EXPECTED_SONAR_IN_TEMPLATES


def test_the_leading_part_breakdown_is_what_the_records_say() -> None:
    """The same, for the other decomposed figure."""
    pattern, flags = _widenings()["unquoted rule with the leading part of the name optional"]
    found = _scan(pattern, flags, tracked_files())
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
    files = tracked_files()
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
    for path in tracked_files():
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


#: The declared test double the shipped rules already report, which is the seventh of the
#: quoted rule's widened findings and the one that is NOT part of the price. Pinned by path
#: so the split below is measured rather than assumed: if the double moves, the split is
#: re-derived rather than silently counting a real finding as the double.
DECLARED_DOUBLE = "tests/test_entra_sign_in.py"


def _beyond_the_double() -> list[tuple[str, int, str]]:
    """Return the widened quoted rule's findings that are not the declared test double."""
    pattern, flags = _widenings()["quoted rule with bare key and keys in its keyword group"]
    return [
        entry for entry in _scan(pattern, flags, tracked_files()) if entry[0] != DECLARED_DOUBLE
    ]


def test_the_quoted_rule_split_adds_up_and_names_the_right_modules() -> None:
    """The decomposition of the 7, held the way the sonar split is held.

    A figure decomposed into parts needs EVERY part held. The count was pinned and the
    sentence around it was not, so `All six ... in `store.py` and `config.py`` - a count
    contradicting itself inside one sentence, naming two modules that carry none of the
    findings - passed the whole suite. The module names are derived from the scan here.

    The passage states no count as a WORD, and that is asserted rather than claimed. Saying
    it in a docstring was not enough twice: `All six` went in, was removed, and `Those three
    module names` went in behind it, both free because no scanner reads a word. The digits
    in the passage that are written in one of the pinned SHAPES are held by the shape sweep
    and the breakdown clauses. A free-form digit clause is held by neither, so every digit
    here, A COMMIT HASH EXCEPTED, must belong to a rendering this passage is entitled to,
    clause and all. Each narrowing of that sentence was bought with a green mutation:
    `5 of these sit in auth.py.` was free while nothing held a free-form clause,
    `7 modules carry them.` while the check read values rather than renderings, a
    backticked decomposition while every code span was exempt, and a clause built from
    another experiment's figure while the whole allowed set was cleared.

    A word count is banned too, case-folded, with the compound ordinals that name a gate run
    removed first. That ban is the words on its LIST and is not a closure over counts
    written as words; the open end is recorded in `docs/GATE-RECORDS.md` under accepted
    residual rather than implied closed.
    """
    beyond = _beyond_the_double()

    assert len(beyond) == EXPECTED_BEYOND_THE_DOUBLE, (
        f"{len(beyond)} findings beyond the declared double, not {EXPECTED_BEYOND_THE_DOUBLE}"
    )
    widened = EXPECTED["quoted rule with bare key and keys in its keyword group"][0]
    assert widened == EXPECTED_BEYOND_THE_DOUBLE + 1, (
        "the price and the double no longer add up to the widened rule's total"
    )

    #: No count written as a word, in either carrier, in EITHER case. Case-folded because
    #: the first word of a sentence is the most natural place in English for a count to
    #: appear, and `Three of these sit in auth.py` walked through the case-sensitive
    #: version with the whole suite green. The ordinals are removed from the passage first
    #: rather than excepted by a lookahead: `(?!-)` excepted every hyphenated compound, so
    #: it licensed `the three-module list`, which is exactly the figure the ban is for.
    #: `one` is not banned: the passage uses it as a pronoun ("every one a session key
    #: NAME") and banning it would force a worse sentence to satisfy a test.
    for path in BREAKDOWN_CARRIERS["beyond the declared double"]:
        passage = _quoted_rule_passage(path)
        readable = _ORDINALS.sub(" ", passage)
        spelled = [word for word in _WORD_NUMBERS if re.search(rf"(?i)\b{word}\b", readable)]
        assert not spelled, (
            f"{path.name} states {spelled} as a word in the price passage, where no scanner "
            "can read it. Write the figure as a digit and pin it, or delete the clause."
        )

    #: Every DIGIT in the passage, a commit hash excepted, belongs to a rendering this
    #: passage is ENTITLED to, CLAUSE and all. Requiring only that the value was pinned
    #: somewhere is not enough: `7` is the widened rule's finding count, so `7 modules carry
    #: them.` - false, there are three - passed a value-level check and was green. Nor is
    #: every rendering the module measured enough: clearing the whole allowed set let a
    #: figure belonging to ANOTHER experiment stand here, and `The split is 19 Python
    #: keyword arguments in auth.py.` was green on a figure that is the prose rule's. The
    #: renderings are removed longest first so a short one cannot consume part of a longer
    #: one, and the hash goes first because it is the one run of digits that is no figure.
    for path in BREAKDOWN_CARRIERS["beyond the declared double"]:
        residue = _normalise(_COMMIT_HASH_SPAN.sub(" ", _quoted_rule_passage_raw(path)))
        for rendering in sorted(_entitled(), key=len, reverse=True):
            residue = residue.replace(rendering, " ")
        loose = sorted(set(re.findall(r"[0-9]+", residue)))
        assert not loose, (
            f"{path.name} states {loose} in the price passage outside any rendering this "
            "module measured. Pin the measurement and write the figure in its shape, or "
            "delete the clause."
        )

    #: The module basenames the carriers name. Basenames rather than paths, because both
    #: carriers write them that way and a path would put `src/complyops/` into a sentence
    #: that is about which modules hold the names, not where the tree puts them.
    modules = sorted({Path(entry[0]).name for entry in beyond})
    for path in BREAKDOWN_CARRIERS["beyond the declared double"]:
        flowed = _flowed(path)
        missing = [name for name in modules if _normalise(f"`{name}`") not in flowed]
        assert not missing, (
            f"{path.name} does not name {missing}, which is where the findings beyond the "
            "declared double actually are"
        )

    #: And nothing else: naming a module that carries none of them is the half of the defect
    #: a positive check alone would miss. Read from the sentence itself rather than the whole
    #: file, because these basenames appear all over both carriers for unrelated reasons.
    #: Compared through `_normalise` on both sides, because it strips the backticks a
    #: carrier writes around a module name and the underscore inside one.
    for path in BREAKDOWN_CARRIERS["beyond the declared double"]:
        passage = _quoted_rule_passage(path)
        named = set(re.findall(r"\b([A-Za-z0-9_]+\.py)\b", passage))
        assert named == {_normalise(name) for name in modules}, (
            f"{path.name} names {sorted(named)} where the scan gives {modules}, compared "
            "with the emphasis markers stripped from both sides"
        )


#: The fragment that locates the price passage. Not the whole clause with its number: the
#: number is held by `test_every_breakdown_clause_is_still_said_where_it_belongs`, and
#: locating on it too would make one edit red in two places and say nothing extra.
_PRICE_CLAUSE = "beyond the declared double"

#: A backticked COMMIT HASH, and nothing else. Removed before the digit ban reads the
#: passage, because a hash is a span full of digits that are not a figure and `9b3bba3`
#: would otherwise have to be pinned as though someone had measured nine of something.
#:
#: Narrow on purpose, and the width is the whole point. Exempting every code span exempted
#: every backticked DIGIT, so a false decomposition written with each part in backticks was
#: green on the whole suite in both carriers, summing to the right total with the wrong
#: parts. A backticked number renders to a reader as an ordinary number, which is the same
#: reason `_EMPHASIS` strips backticks before anything compares text, and this project has
#: now been bitten by backtick blindness three times.
_COMMIT_HASH_SPAN = re.compile(r"`[0-9a-f]{7,40}`")

#: The ordinals the passage legitimately writes, removed before the ban reads it. They name
#: the gate runs that asked for the figure; `twenty-eighth` is a run's number, not a
#: quantity of anything. Named explicitly rather than matched as "anything hyphenated",
#: which is what let a compound COUNT through. The tens word and its suffix are BOTH
#: required: with the suffix optional this pattern stripped a bare `Thirty` and handed the
#: ban a passage the count had already been removed from, which was green. A standalone
#: ordinal such as `twentieth` is matched by the second alternation instead.
#:
#: The COMPOUND form only. A standalone alternation once carried `fourth` through
#: `thirtieth` as well, and every one of those words is a fraction as much as an ordinal:
#: `A fifth of these sit in auth.py` was green, stripped before the ban could read it.
#: `third` was diagnosed and fixed one round earlier and the other twelve were left, which
#: is the same walk-around one word over. A gate run is named in these two passages only as
#: a compound (`twenty-eighth`, `thirty-first`), so the compound is all that is needed, and
#: a standalone ordinal in the passage should be written as a digit or rephrased. `first`
#: and `second` survive the ban without an exemption, because neither is a count and
#: neither is on the word list.
_ORDINALS = re.compile(
    r"\b(?:twen|thir|for|fif|six|seven|eigh|nine)ty[- ]"
    r"(?:first|second|third|fourth|fifth|sixth|seventh|eighth|ninth)\b",
    re.IGNORECASE,
)

#: The words a restatement in the price passage could take, banned there in either case.
#: NOT a closure over "a count written as a word", and the claim is narrowed rather than the
#: list called complete: English has more ways to say a number than a list can hold, and the
#: numerals-only version of this list was walked around with `A pair sit in csrf.py, a
#: couple in auth_routes.py and the rest in auth.py`, a false decomposition of the very
#: figure the ban is for, green on the whole suite. The vague counts below are the near end
#: of that class, which is where the walk-arounds actually came from; the far end is open
#: and is recorded as accepted residual in `docs/GATE-RECORDS.md` rather than implied
#: closed.
#:
#: Two exclusions, each because the passage uses the word for something else and banning it
#: would buy a worse sentence rather than a held figure. `one` is a pronoun there ("every
#: one a session key NAME"), and `both` counts the keyword group's two words ("the unquoted
#: rule's group carries both words"), not the price. `all`, `any`, `each` and `every` are
#: left out for a related reason: each is ordinary connective English the passage already
#: uses, and banning them would rewrite the passage to satisfy a test rather than hold a
#: figure. Those four are recorded in the residual table with the rest of the open end.
_WORD_NUMBERS = (
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
    "eleven",
    "twelve",
    "thirteen",
    "fourteen",
    "fifteen",
    "sixteen",
    "seventeen",
    "eighteen",
    "nineteen",
    "twenty",
    "thirty",
    "forty",
    "fifty",
    "sixty",
    "seventy",
    "eighty",
    "ninety",
    "hundred",
    "dozen",
    "dozens",
    "score",
    "couple",
    "pair",
    "pairs",
    "trio",
    "quartet",
    "handful",
    "several",
    "twice",
    "thrice",
    "third",
    "thirds",
    "quarter",
    "quarters",
    "half",
    "halves",
    "twos",
    "threes",
    "fours",
    "fives",
    "sixes",
    "sevens",
    "zero",
    "none",
    "single",
    "brace",
    "treble",
    "twofold",
    "threefold",
    "thousand",
    "million",
    "fourth",
    "fourths",
    "fifth",
    "fifths",
    "sixth",
    "sixths",
    "seventh",
    "sevenths",
    "eighth",
    "eighths",
    "ninth",
    "ninths",
    "tenth",
    "tenths",
    "eleventh",
    "twelfth",
    "thirteenth",
    "twentieth",
    "thirtieth",
)


def _quoted_rule_passage(path: Path) -> str:
    """Return `_quoted_rule_passage_raw` as a reader sees it: flowed, markers stripped."""
    return _normalise(_quoted_rule_passage_raw(path))


def _quoted_rule_passage_raw(path: Path) -> str:
    """Return the passage of `path` that states the quoted rule's price, flowed.

    Bounded at the PASSAGE, which is the contiguous comment block in the script and the
    bullet in the record, rather than at a character count. A fixed 400-character window
    was defeated: appending the false sentence "Two of the six sit in `store.py` and
    `config.py`" to the end of the sweep's comment block landed past the window, so the
    negative half never saw the false names while the positive half, which searches the
    whole file, still found the true ones, and the suite stayed green. A window measured in
    characters is a window an editor can walk out of. A window measured in the structure of
    the document is harder to walk out of, and be exact about which structure: the comment
    PARAGRAPH here, bounded by a bare `#`, not the comment run, which carries several
    unrelated paragraphs about other parts of this sweep; and the bullet up to the next
    bullet or heading, not up to the next blank line, because a continuation indented one
    blank line below the bullet reads as part of the same claim and was green when the
    bound stopped at the blank.

    Bounded rather than whole-file because both carriers name every one of these modules
    elsewhere for unrelated reasons, so a whole-file negative check would be red always.
    """
    lines = path.read_text(encoding="utf-8").splitlines()
    hits = [index for index, line in enumerate(lines) if _PRICE_CLAUSE in line]

    assert len(hits) == 1, (
        f"{path.name} states the price on {len(hits)} lines, not exactly one. If the "
        "sentence was rewrapped, rewrap it so the clause stays whole on one line; if it "
        "was copied, one of the copies is the stale one."
    )
    index = hits[0]
    start = end = index
    if path.suffix == ".sh":
        #: The comment PARAGRAPH, not the whole comment run. The run around this clause is
        #: several thousand characters over several paragraphs about unrelated parts of the
        #: sweep, and it already contains the word `Two`, so a run-wide ban would have been
        #: red on arrival and a run-wide module check reads claims that are not this one's.
        #: No figure is given for either, deliberately: the first version of this comment
        #: gave both, and one was invalidated by the same commit that wrote it while the
        #: other was never measured at all. A bare `#` line separates paragraphs in this
        #: script, which is the structure the bound uses.
        while start > 0 and _is_prose_comment(lines[start - 1]):
            start -= 1
        while end + 1 < len(lines) and _is_prose_comment(lines[end + 1]):
            end += 1
        #: Plus any comment trailing the line of code that ends the paragraph. That line is
        #: not a comment line, so the walk stops above it, and `examined += 1  # 9 of these
        #: sit in auth.py.` sat one character outside the bound and was green. Appending to
        #: an existing line is not the structural edit the residual accepts, so it is taken
        #: in rather than recorded.
        if end + 1 < len(lines) and "#" in lines[end + 1]:
            trailing = lines[end + 1][lines[end + 1].index("#") :]
            return "\n".join([*lines[start : end + 1], trailing])
    else:
        #: The bullet: back to its marker, forward to the next marker or the next heading.
        #: NOT to the next blank line: a continuation indented under the bullet, one blank
        #: line below it, reads as part of the same claim and was green when the bound
        #: stopped at the blank.
        while start > 0 and not lines[start].lstrip().startswith("●"):
            start -= 1
        while end + 1 < len(lines) and not (
            lines[end + 1].lstrip().startswith("●")
            or lines[end + 1].lstrip().startswith("#")
            or lines[end + 1].lstrip().startswith("|")
        ):
            end += 1
    return "\n".join(lines[start : end + 1])


def _is_prose_comment(line: str) -> bool:
    """Report whether this line continues a comment PARAGRAPH: a `#` with words after it.

    A bare `#` ends the paragraph, which is how this script separates one argument from the
    next, and a line of code ends it too.
    """
    stripped = line.strip()
    return stripped.startswith("#") and stripped != "#"


@pytest.mark.parametrize(
    ("suffix", "body", "expected", "unexpected"),
    [
        pytest.param(
            ".md",
            "● A bullet. 6 beyond the declared double, in `auth.py`.\n\n"
            "  A continuation one blank line below.\n"
            "## A heading\n"
            "  Text under the heading.\n",
            "A continuation one blank line below",
            "Text under the heading",
            id="the record bullet ends at a heading, not at a blank line",
        ),
        pytest.param(
            ".md",
            "● A bullet. 6 beyond the declared double, in `auth.py`.\n| a | table | row |\n",
            "A bullet",
            "table",
            id="the record bullet ends at a table row",
        ),
        pytest.param(
            ".md",
            "● A bullet. 6 beyond the declared double, in `auth.py`.\n● The next bullet.\n",
            "A bullet",
            "The next bullet",
            id="the record bullet ends at the next bullet",
        ),
        pytest.param(
            ".sh",
            "    # A paragraph. 6 beyond the declared double, in `auth.py`.\n"
            "    #\n"
            "    # The next paragraph.\n",
            "A paragraph",
            "The next paragraph",
            id="the script paragraph ends at a bare hash",
        ),
        pytest.param(
            ".sh",
            "    # A paragraph. 6 beyond the declared double, in `auth.py`.\n    code_line=1\n",
            "A paragraph",
            "codeline",
            id="the script paragraph ends at a line of code",
        ),
    ],
)
def test_the_passage_bound_ends_where_the_structure_does(
    tmp_path: Path, suffix: str, body: str, expected: str, unexpected: str
) -> None:
    """Each terminator of `_quoted_rule_passage`, against a document written to need it.

    The live carriers exercise one terminator each, so the heading and the table row were
    held by nothing: deleting either left the suite green, because the price bullet happens
    to be followed by another bullet today. A control is unfinished until a mutation shows
    it can fail, and a terminator no document reaches cannot fail.
    """
    document = tmp_path / f"carrier{suffix}"
    document.write_text(body, encoding="utf-8")
    passage = _quoted_rule_passage(document)

    assert _normalise(expected) in passage, f"the bound dropped {expected!r}"
    assert _normalise(unexpected) not in passage, f"the bound ran past into {unexpected!r}"


def test_the_sonar_split_adds_up() -> None:
    """The three parts of one figure, asserted against each other as well as the tree.

    Pinning the total and one part left the remainder free, and a reviewer set it so the
    sentence contradicted itself with nothing red.
    """
    assert EXPECTED_SONAR_IN_TEMPLATES + EXPECTED_SONAR_IN_PROJECT == EXPECTED_SONAR

    pattern, flags = _widenings()["prose rule folded to ignore case"]
    found = _scan(pattern, flags, tracked_files())
    sonar = [entry for entry in found if "projectkey" in entry[2].lower()]
    templates = [entry for entry in sonar if "/templates/" in entry[0]]

    assert len(sonar) - len(templates) == EXPECTED_SONAR_IN_PROJECT


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

    Deleting a shape from `_SHAPES` alone is red at the phrasing corpus. For the two shapes
    subsumed by a longer sibling, deleting from `_SHAPES` and `PHRASINGS` together is red
    here and nowhere else, measured across all fifteen; that narrow case is why this stays.
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

        # The shape's OWN pattern. The alternation is leftmost-first, so a decoy earlier in
        # the phrasing became the match and the shape under test was never judged: a
        # phrasing of `47 findings on 47 lines and 0 false positives` passed on the first
        # clause while carrying an allowed figure in the second.
        match = re.compile(_shape_pattern(shape)).search(normalised)

        assert match is not None, (
            f"{phrasing!r} would not be read back, so a figure in the shape {shape!r} could "
            "be written into a shipped document unnoticed"
        )
        # The MATCHED text, which is what the sweep judges, rather than the whole phrasing.
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

        # EVERY digit run wrapped, not merely the marker present somewhere. `return phrasing`
        # retired this leg once; `return f"{marker}{phrasing}"` satisfies a presence check
        # while leaving every digit bare, which retires it again. The property is that the
        # scanner reads a figure THROUGH the markup, so the fixture must put markup on the
        # figures.
        for run in _DIGITS.findall(phrasing):
            assert f"{marker}{run}{marker}" in marked, (
                f"{marker!r} was not wrapped around {run!r} in {phrasing!r}"
            )
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
    skipped = [path for path in tracked_files() if _is_self(path)]

    assert [path.resolve() for path in skipped] == [SELF]


def test_the_marker_corpus_covers_the_stripper() -> None:
    """The markers exercised must be the characters the stripper removes.

    `EMPHASIS_MARKERS` had no anchor of its own, so cutting it to one entry was green and
    the other three markups went unexercised. Reading the character class out of the
    stripper's own pattern ties the two together: narrowing either alone is red.
    """
    exercised = {character for marker in EMPHASIS_MARKERS for character in marker}

    assert exercised == set(_STRIPPED_CHARACTERS)
    # And both against a literal, because tying them to each other alone let them be
    # narrowed together: one marker and a one-character class was green, and three markups
    # went unread again.
    assert exercised == {"`", "*", "~", "_"}
