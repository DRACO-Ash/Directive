r"""A shipped table must render as the table it was written as.

Three ways it silently does not, each found in this repository and each held below.

A blank line terminates a table under CommonMark and GitHub Flavored Markdown, so a row
below one renders as a paragraph of literal pipe characters. A row with fewer cells than its
header loses the columns it does not reach, and one with more has the excess discarded. And
an unescaped pipe inside a code span splits the cell there, so everything after it in that
row is dropped or pushed into a column that does not exist.

That last one is why this file exists rather than a proof-reading habit. It drops evidence
SILENTLY: `docs/GATE-RECORDS.md` is what an assessor reads to see what each binding gate
returned, and four of its verdict cells were losing their tails to a pipe inside a backtick.
Nothing in the source looks wrong. Only the render is.

Be exact about what is held and what is not, because the first version of this file claimed
to close the class and did not: it read only lines beginning with a pipe and only the first
two lines of a run, so it saw neither a row broken across lines nor a cell-count mismatch,
and it was green with two broken tables in the tree. What is held now is structural: every
run of pipe-delimited lines opens with a header and a delimiter, every row carries exactly
the header's cell count, and every row closes with a pipe. What is NOT held is semantics. A
row can still say something false in a well-formed cell, and no test here will notice.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

#: A pipe a renderer treats as a cell boundary: one not preceded by a backslash.
_UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")

ROOT = Path(__file__).resolve().parents[1]

#: Every Markdown document at the root or under `docs/`. A superset of what the package
#: ships, deliberately: `CLAUDE.md` is excluded from the package by `build-package.sh` and is
#: held here anyway, because a table that renders wrongly in the repository is worth catching
#: wherever it lives. `.claude/` is excluded because it is this assistant's own tooling.
SHIPPED = sorted([*ROOT.glob("*.md"), *ROOT.glob("docs/**/*.md")])


#: A delimiter row, `| --- | --- |`, optionally with alignment colons.
def _is_delimiter(line: str) -> bool:
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    return bool(cells) and all(cell and set(cell) <= set(":-") and "-" in cell for cell in cells)


def _blocks(lines: list[str]) -> list[tuple[int, list[str]]]:
    """Return each run of contiguous pipe-delimited lines, with its 1-based start."""
    blocks: list[tuple[int, list[str]]] = []
    run: list[str] = []
    start = 0
    for number, line in enumerate(lines, start=1):
        if line.lstrip().startswith("|"):
            if not run:
                start = number
            run.append(line)
        elif run:
            blocks.append((start, run))
            run = []
    if run:
        blocks.append((start, run))
    return blocks


def test_the_shipped_set_is_not_empty() -> None:
    """A glob that matches nothing makes every test below vacuously green."""
    assert len(SHIPPED) >= 5, f"only found {[p.name for p in SHIPPED]}"


def _cells(line: str) -> int:
    """Count the cells a renderer will find, honouring a backslash-escaped pipe."""
    return len(_UNESCAPED_PIPE.split(line.strip().strip("|"))) if line.strip().strip("|") else 0


@pytest.mark.parametrize("document", SHIPPED, ids=lambda p: str(p.relative_to(ROOT)))
def test_no_table_row_is_stranded_outside_a_table(document: Path) -> None:
    """A run of rows must open with a header and a delimiter, or it is not a table."""
    stranded = [
        (start, run[0][:70])
        for start, run in _blocks(document.read_text(encoding="utf-8").splitlines())
        if len(run) < 2 or not _is_delimiter(run[1])
    ]
    assert not stranded, (
        f"{document.relative_to(ROOT)} has pipe-delimited lines that are not a table, so "
        f"they render as literal text: {stranded}. A blank line terminates a table; move "
        "the prose below the rows, or give the run its own header and delimiter."
    )


@pytest.mark.parametrize("document", SHIPPED, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_row_carries_its_headers_cell_count(document: Path) -> None:
    """A row wider or narrower than its header loses cells, silently.

    The usual cause is an unescaped pipe inside a code span. A union type or a bitwise
    operator written between backticks still reads as a cell boundary, so the row gains a
    cell and the renderer discards the excess against the header. Everything in the verdict
    after that point vanishes from the rendered record while the source still looks
    complete.
    """
    wrong: list[tuple[int, int, int, str]] = []
    for start, run in _blocks(document.read_text(encoding="utf-8").splitlines()):
        if len(run) < 2 or not _is_delimiter(run[1]):
            continue  # held by the test above; do not report it twice
        expected = _cells(run[0])
        wrong += [
            (start + offset, _cells(line), expected, line[:60])
            for offset, line in enumerate(run)
            if _cells(line) != expected
        ]
    assert not wrong, (
        f"{document.relative_to(ROOT)} has rows whose cell count differs from their "
        f"header's, as (line, found, expected, start): {wrong}. Escape a pipe inside a code "
        "span as a backslash pipe, or the cells past it are dropped when rendered."
    )


@pytest.mark.parametrize("document", SHIPPED, ids=lambda p: str(p.relative_to(ROOT)))
def test_every_row_is_closed(document: Path) -> None:
    """A row that does not end with a pipe has been broken across lines."""
    unclosed = [
        (start + offset, line[-60:])
        for start, run in _blocks(document.read_text(encoding="utf-8").splitlines())
        if len(run) >= 2 and _is_delimiter(run[1])
        for offset, line in enumerate(run)
        if not line.rstrip().endswith("|")
    ]
    assert not unclosed, (
        f"{document.relative_to(ROOT)} has table rows that do not close with a pipe, so the "
        f"row continues into whatever follows: {unclosed}."
    )
