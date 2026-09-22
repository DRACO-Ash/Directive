r"""Every table row in a shipped document must belong to a table.

A blank line terminates a table under CommonMark and GitHub Flavored Markdown, so a row
below one renders as a paragraph of literal pipe characters. That is not cosmetic in this
repository: `docs/GATE-RECORDS.md` is the artefact an assessor reads to see what each
binding gate returned, and twice its newest verdicts were the rows left outside the table.

The class is closed here rather than audited by eye. It was audited by eye three rounds
running: the first fix removed one blank line and the insertion beside it created another a
row earlier, the second relocated it again, and the third missed a table sixty lines below
in the same file. A defect that survives three careful readings is not a carelessness
problem, it is a missing test.
"""

from __future__ import annotations

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Everything shipped that a reader outside this team may open. `.claude/` is tooling for
#: this assistant and is not in the package, so it is not held to the same bar.
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
