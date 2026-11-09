"""Every comparison of a secret is constant-time, and a test says so.

This class has bitten the project once already. The test holding `hashes_equal` records in
its own docstring that a mutation showed `==` passed all 467 tests; the fix was applied to
that one call site and the class was never swept. A security gate then replaced
`hmac.compare_digest` with `==` at four OTHER sites and all 845 tests stayed green:

    csrf.valid            the cross-site request forgery token
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
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

#: Every function that compares a secret, and must therefore not use `==`. The comment on
#: each is what the value is, because "why is this constant-time" is the question a reader
#: asks and the answer is never in the function name.
MUST_BE_CONSTANT_TIME = [
    ("src/directive/csrf.py", "valid"),  # the cross-site request forgery token
    #: `auth.constant_time_equal` stood here and is gone with the code. It compared the
    #: Entra sign-in state, had no caller in `src/` after that provider went, and this line
    #: described it as "a secret on an unauthenticated route" when no route passed a secret
    #: through it. A pin naming a function nothing calls is a pin that cannot fail.
    ("src/directive/audit/hashing.py", "hashes_equal"),  # an entry's keyed digest
    ("src/directive/audit/anchor.py", "_marker_is_valid"),  # the first-use marker's tag
    ("src/directive/audit/anchor.py", "_validate"),  # the anchor MAC, the truncation detector
    #: The local account list, added with it. Each of these three is the whole of what
    #: stands between a caller and a session, so each is the kind of comparison this file
    #: exists for: a password hash, a one-time code, and a recovery code.
    ("src/directive/accounts.py", "verify_password"),  # the scrypt hash of a password
    ("src/directive/accounts.py", "spend_recovery_code"),  # a single-use recovery code hash
    #: `matching_step`, not `verify`. `verify` is now a boolean view over it and compares
    #: nothing itself, so pinning `verify` would have pinned a function with no comparison
    #: in it: green by construction, which is the shape of unheld control this file exists
    #: to catch. The loop caught the rename, which is the pin working.
    ("src/directive/totp.py", "matching_step"),  # a time-based one-time password
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


#: The comparisons whose LOOP must also run to completion, with the reason each one scans
#: more than a single value. A constant-time primitive inside a loop that stops at the
#: first match leaks WHICH iteration matched, which is a different quantity from which
#: byte matched and is not covered by the assertion above.
MUST_NOT_SHORT_CIRCUIT = [
    #: Three steps of drift, so stopping early says whether the code came from the current
    #: step or the edge of the window.
    ("src/directive/totp.py", "matching_step"),
    #: Ten held hashes, so stopping early says which recovery code was presented.
    ("src/directive/accounts.py", "spend_recovery_code"),
]


@pytest.mark.parametrize(("path", "name"), MUST_NOT_SHORT_CIRCUIT)
def test_a_scanning_comparison_runs_to_completion(path: str, name: str) -> None:
    """No `return` or `break` inside the loop that does the comparing.

    Structural rather than timed, deliberately: a timing assertion over three HMAC
    evaluations is noise on a loaded runner, and it would be the kind of test that is
    disabled the first week it flakes. What can be held exactly is the shape, and the shape
    is the whole of the control: both functions set a flag and fall out of the loop.

    Added because a gate found the property unheld. Both docstrings state it in full,
    `totp.py` calling it out as the reason the loop does not short-circuit, and replacing
    the comparison with `==` AND returning on the first match left the one-time password,
    account and sign-in suites green. The `==` half is caught by the pin above; the
    early-exit half was caught by nothing.
    """
    function = _function(path, name)
    loops = [node for node in ast.walk(function) if isinstance(node, ast.For | ast.While)]
    assert loops, f"{path}::{name} no longer loops; this pin is stale and the control unheld"

    for loop in loops:
        #: `Continue` and `Raise` as well as `Return` and `Break`, because a gate evaded
        #: the first version with a `continue` guard: `if found: continue` runs no further
        #: comparison after the first match while containing neither of the two exits the
        #: pin looked for. `Raise` is the same shape through the exception machinery.
        exits = [
            type(node).__name__
            for node in ast.walk(loop)
            if isinstance(node, ast.Return | ast.Break | ast.Continue | ast.Raise)
        ]
        assert not exits, (
            f"{path}::{name} leaves or skips its comparison loop early via {exits}. "
            "Stopping at the first match leaks which iteration matched, whatever the "
            "comparison inside it costs. Set a flag and fall out of the loop."
        )
        #: And a `while` can short-circuit in its own TEST, which no statement inside the
        #: body spells: rewriting the drift loop as
        #: `while drift <= DRIFT_STEPS and matched is None:` leaves the body exit-free and
        #: still stops at the first match. The gate demonstrated it. So a `while` here may
        #: not test any name the body assigns.
        if isinstance(loop, ast.While):
            assigned = {
                target.id
                for node in ast.walk(loop)
                if isinstance(node, ast.Assign)
                for target in node.targets
                if isinstance(target, ast.Name)
            } | {
                node.target.id
                for node in ast.walk(loop)
                if isinstance(node, ast.AugAssign | ast.AnnAssign)
                and isinstance(node.target, ast.Name)
            }
            tested = {node.id for node in ast.walk(loop.test) if isinstance(node, ast.Name)}
            overlap = sorted(assigned & tested)
            assert not overlap, (
                f"{path}::{name} has a `while` testing {overlap}, which its own body "
                "assigns. The loop then stops as soon as the comparison succeeds, which is "
                "the same leak as a `break` written in the body."
            )


def test_the_recovery_loop_compares_every_held_code_even_after_a_match() -> None:
    """Behavioural, not structural, because the structural pin has been evaded twice.

    The AST check above refuses the shapes a short-circuit is usually written in. This
    counts the comparisons instead, which is the property itself rather than a spelling of
    it: with the FIRST of ten held codes matching, `hmac.compare_digest` must still be
    called ten times. A `continue` guard, a `while` whose test watches the flag, a helper
    that returns early and anything else anyone invents are all caught by a count.
    """
    import hmac  # noqa: PLC0415 - only this test needs it

    sys.path.insert(0, str(ROOT / "src"))
    from directive import accounts  # noqa: PLC0415 - after the path insert

    codes, hashes = accounts.new_recovery_codes()
    account = {"recovery": hashes}
    calls: list[int] = []
    real = hmac.compare_digest

    def counted(a: object, b: object) -> bool:
        calls.append(1)
        return real(a, b)  # type: ignore[arg-type]

    original = accounts.hmac.compare_digest
    accounts.hmac.compare_digest = counted  # type: ignore[assignment]
    try:
        assert accounts.spend_recovery_code(account, codes[0]) is True
    finally:
        accounts.hmac.compare_digest = original  # type: ignore[assignment]

    assert len(calls) == len(hashes), (
        f"the loop compared {len(calls)} of {len(hashes)} held codes, so it stopped at the "
        "first match and leaks which recovery code was presented"
    )
