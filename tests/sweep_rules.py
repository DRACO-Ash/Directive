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
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SWEEP = ROOT / "scripts" / "build-package.sh"

#: The alternation every credential rule shares. Held here so an experiment built on top of
#: a rule can find the name part without matching a fragment of some other rule.
KEYWORD_GROUP = "(?:SECRET|TOKEN|KEY|KEYS|PASSWORD|PASSWD|PWD)[A-Z0-9_]*"

_CASE_SENSITIVE_MARKER = "]\n#: The rules that must NOT fold case"
_NAME_PATTERN = re.compile(r"-name '([^']+)'")


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
    patterns = set(_NAME_PATTERN.findall(expression))
    assert patterns, "no -name patterns were parsed out of the filename sweep"
    # The one name that must ship. It appears in the expression as the `! -name` exemption
    # rather than as a refusal, so it is removed here rather than probed as a refusal.
    return patterns - {".env.example"}
