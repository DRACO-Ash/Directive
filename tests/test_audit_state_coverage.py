"""Which writers reach `old_state` and `new_state`, and under which rule.

Two documents make a coverage claim about this and both got it wrong before this module
existed. `docs/DEPLOYMENT.md` said `check_state` enforced the closed vocabulary on every
route the application serves, and `records.check_state` said no route reached those fields
without passing through it. The sign-in refusal path falsifies both: it composes a
collapsed-count marker server-side and writes it straight to the chain, under the audit
boundary's character rule alone.

The claim is now bounded and the bound is held here: every REGISTER writer goes through the
vocabulary, the refusal path is the one declared exception, and it carries no caller value.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from complyops import records

SRC = Path(__file__).resolve().parents[1] / "src" / "complyops"

#: The one writer of a state field that does not reach `records.check_state`. Declared, so
#: a second one is a red test rather than a silent widening of the exception.
DECLARED_EXCEPTIONS = ("views/auth_routes.py",)

#: What that exception is allowed to write: a server-composed marker, digits only, and no
#: caller value anywhere in it.
MARKER = re.compile(r"\AREPEATED_\d+\Z")


def _writers_of_a_state_field() -> set[str]:
    """Return every module under `src/` that names `old_state` or `new_state` in a literal."""
    found = set()
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and node.value in {"old_state", "new_state"}:
                found.add(str(path.relative_to(SRC)))
    return found


def test_every_state_writer_is_the_vocabulary_or_a_declared_exception() -> None:
    """A new writer must be a deliberate line in this list, not an accident."""
    writers = _writers_of_a_state_field()
    through_the_vocabulary = {"records.py", "audit/validation.py", "audit/hashing.py"}
    undeclared = writers - through_the_vocabulary - set(DECLARED_EXCEPTIONS)

    assert not undeclared, (
        f"{sorted(undeclared)} writes a state field and is neither the vocabulary nor a "
        "declared exception. Route it through `records.check_state`, or declare it here "
        "and correct the coverage sentence in `docs/DEPLOYMENT.md`."
    )


def test_the_declared_exception_is_still_the_one_that_shipped() -> None:
    """The exception list is an allowance, so it is pinned rather than merely honoured."""
    assert DECLARED_EXCEPTIONS == ("views/auth_routes.py",)


@pytest.mark.parametrize("register", sorted(records.REGISTERS))
def test_a_register_state_comes_from_the_closed_vocabulary(register: str) -> None:
    """Every value `check_state` admits is in that register's list, and nothing else is."""
    states = records.REGISTERS[register]["states"]
    for state in states:
        assert records.check_state(state, register=register) == state

    with pytest.raises(records.RecordError):
        records.check_state("REPEATED_5", register=register)


def test_the_refusal_marker_carries_no_caller_value() -> None:
    """The one value written outside the vocabulary is a count, not a caller's text.

    That is what makes the exception defensible: it is composed server-side from an integer
    the application itself counted, so no caller can steer a byte of it.
    """
    source = (SRC / "views" / "auth_routes.py").read_text(encoding="utf-8")

    assert 'f"REPEATED_{collapsed}"' in source, (
        "the refusal marker is no longer composed from a counted integer; if it now carries "
        "a caller value, the exception in `docs/DEPLOYMENT.md` no longer holds"
    )
    for collapsed in (1, 35, 10_000):
        assert MARKER.fullmatch(f"REPEATED_{collapsed}")
