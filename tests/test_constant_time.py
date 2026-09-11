"""Every comparison of a secret is constant-time, and a test says so.

This class has bitten the project once already. The test holding `hashes_equal` records in
its own docstring that a mutation showed `==` passed all 467 tests; the fix was applied to
that one call site and the class was never swept. A security gate then replaced
`hmac.compare_digest` with `==` at four OTHER sites and all 845 tests stayed green:

    csrf.valid            the cross-site request forgery token
    auth.state_matches    the Entra ID sign-in state and nonce
    anchor._marker_is_valid   the first-use marker's tag
    anchor._validate      the anchor MAC, which CLAUDE.md calls the truncation detector

Each of those modules documents its comparison as constant-time in prose. None of them was
held by anything. The exploit is marginal on its own, a remote timing oracle against a MAC
through an authenticated endpoint, and that is not why this file exists: the project's own
bar is that a control is unfinished until a mutation shows it can fail, and the threat model
in `CLAUDE.md` makes an unheld control a finding whichever side of the boundary it sits on.

Asserted by naming the functions rather than by sweeping the package for `==`. A sweep over
identifiers that look sensitive flagged four comparisons of a public constant and an integer
count and none of the four real sites, because those already call `compare_digest`. A list
that has to be maintained is the honest shape here: adding a secret comparison means adding
a line, and forgetting to is caught in review rather than by a regex that was never going to
see it.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Every function that compares a secret, and must therefore not use `==`. The comment on
#: each is what the value is, because "why is this constant-time" is the question a reader
#: asks and the answer is never in the function name.
MUST_BE_CONSTANT_TIME = [
    ("src/complyops/csrf.py", "valid"),  # the cross-site request forgery token
    ("src/complyops/auth.py", "state_matches"),  # the sign-in state and the nonce
    ("src/complyops/audit/hashing.py", "hashes_equal"),  # an entry's keyed digest
    ("src/complyops/audit/anchor.py", "_marker_is_valid"),  # the first-use marker's tag
    ("src/complyops/audit/anchor.py", "_validate"),  # the anchor MAC, the truncation detector
]


def _function(path: str, name: str) -> ast.FunctionDef:
    """Return one function's syntax tree, failing loudly if it has been renamed."""
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    pytest.fail(f"{path} has no function {name}; this list is stale and the control unheld")


@pytest.mark.parametrize(("path", "name"), MUST_BE_CONSTANT_TIME)
def test_a_secret_is_never_compared_with_equals(path: str, name: str) -> None:
    """The function compares its secret with `hmac.compare_digest` and with nothing else."""
    function = _function(path, name)
    calls = {
        node.func.attr
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }

    assert "compare_digest" in calls, f"{path}::{name} does not call hmac.compare_digest"


@pytest.mark.parametrize(("path", "name"), MUST_BE_CONSTANT_TIME)
def test_the_secret_itself_is_not_compared_with_equals(path: str, name: str) -> None:
    """And the value reaching `compare_digest` is not ALSO compared with `==` beside it.

    A call to `compare_digest` somewhere in the function is necessary and not sufficient: the
    mutation the gate ran replaced the operator while leaving the import and, in two cases,
    another call in place.
    """
    function = _function(path, name)
    compared = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Compare)
        and any(isinstance(operator, ast.Eq | ast.NotEq) for operator in node.ops)
    ]
    secret_like = {"expected", "provided", "mac", "tag", "digest", "signature", "token"}
    for node in compared:
        identifiers = {inner.id for inner in ast.walk(node) if isinstance(inner, ast.Name)}
        assert not (identifiers & secret_like), (
            f"{path}::{name} line {node.lineno} compares {sorted(identifiers & secret_like)}"
            " with an equality operator"
        )
