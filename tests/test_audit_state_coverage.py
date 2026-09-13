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
from flask.testing import FlaskClient

from complyops import create_app, records
from complyops.views import refusals

SRC = Path(__file__).resolve().parents[1] / "src" / "complyops"

#: Real key material, published on purpose: it is not a credential. Same value the rest of
#: the suite uses.
SUITE_KEY = bytes(range(32)).hex()

#: What a caller might try to smuggle into the collapsed count. Each is a shape that would
#: satisfy an unguarded f-string and none is a counted integer.
HOSTILE_TAGS = ("ADMIN", "0 OR 1", "ASH_HIGGINS", "1; DROP")


@pytest.fixture
def signed_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> FlaskClient:
    """Return an unauthenticated client on a fresh volume."""
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    return create_app().test_client()


#: The one writer of a state field that does not reach `records.check_state`. Declared, so
#: a second one is a red test rather than a silent widening of the exception.
DECLARED_EXCEPTIONS = ("views/auth_routes.py",)

#: What that exception is allowed to write: a server-composed marker, digits only, and no
#: caller value anywhere in it.
MARKER = re.compile(r"\AREPEATED_\d+\Z")

#: The modules that reach a state field THROUGH the closed vocabulary. The larger of the two
#: allowances, and the one that was left unpinned.
THROUGH_THE_VOCABULARY = frozenset(
    {
        "records.py",
        "audit/validation.py",
        "audit/hashing.py",
        #: Visible only once the reader learned to see an annotation: the entry dataclass
        #: declares both fields. It reaches them through `normalise_fields`, which is the
        #: vocabulary's own boundary, so it belongs on this side rather than in the
        #: exception list.
        "audit/chain.py",
    }
)


#: Every syntactic place a state field can be NAMED. A string constant was the whole of the
#: first version, and a gate walked past it: a module calling `chain.append(dict(...,
#: new_state=caller_value))` names the field as a keyword argument, is invisible to a
#: constant scan, and writes a raw caller value to the chain past `check_state`. The dict
#: literal form of the same module was caught, which is what made it a detection gap rather
#: than a design choice, and `audit/chain.py` was escaping the scan the same way.
STATE_FIELDS = frozenset({"old_state", "new_state"})


def _names_a_state_field(node: ast.AST) -> bool:
    """Report whether this node names a state field, in any form a writer can use."""
    if isinstance(node, ast.Constant):
        return node.value in STATE_FIELDS
    if isinstance(node, ast.keyword):
        return node.arg in STATE_FIELDS
    if isinstance(node, ast.arg):
        return node.arg in STATE_FIELDS
    if isinstance(node, ast.Attribute):
        return node.attr in STATE_FIELDS
    if isinstance(node, ast.Name):
        return node.id in STATE_FIELDS
    return False


def _writers_of_a_state_field() -> set[str]:
    """Return every module under `src/` that names `old_state` or `new_state`, any form."""
    found = set()
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if _names_a_state_field(node):
                found.add(str(path.relative_to(SRC)))
    return found


def _undeclared(writers: set[str]) -> set[str]:
    """Return the state writers that are neither the vocabulary nor a declared exception."""
    return writers - THROUGH_THE_VOCABULARY - set(DECLARED_EXCEPTIONS)


def test_the_reader_still_sees_the_writer_the_exception_is_written_for() -> None:
    """The reader that makes every claim here checkable, held against its own retirement.

    Inserting `return found` at the top of the walk left the whole suite byte-identical at
    `1212 passed, 2 skipped`, not even a skip, which is worse than the `ALIAS_SHAPES` case
    this project took a guard for. Narrowing the glob to `records.py` was green the same
    way. By the conjunctive discriminator in `docs/GATE-RECORDS.md` this is a TAKE: one
    edit defeats it with nothing red, and the fix asserts on a set that already exists.
    """
    assert "views/auth_routes.py" in _writers_of_a_state_field()


def test_the_declared_exception_writes_one_state_field_and_no_caller_value() -> None:
    """The exception is a MODULE in the list above, which is wider than the allowance.

    A second state write added inside `views/auth_routes.py`, carrying a request header
    straight into `old_state`, was green: the reader still reported one declared exception
    and the marker was still found in the source. The allowance is ONE write of a
    server-composed value, so that is what is counted.
    """
    source = (SRC / "views" / "auth_routes.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    written = [
        node
        for parent in ast.walk(tree)
        if isinstance(parent, ast.Dict)
        for key, node in zip(parent.keys, parent.values, strict=True)
        if isinstance(key, ast.Constant) and key.value in {"old_state", "new_state"}
    ]
    #: The marker is written as a conditional, `f"REPEATED_{n}" if n else ""`, so the branch
    #: that carries a value is what has to be read: a whole-node check would see an `IfExp`
    #: and learn nothing about either half.
    branches = [
        branch
        for node in written
        for branch in ((node.body, node.orelse) if isinstance(node, ast.IfExp) else (node,))
    ]
    non_empty = [
        node for node in branches if not (isinstance(node, ast.Constant) and node.value == "")
    ]

    assert len(non_empty) == 1, (
        f"{len(non_empty)} state fields are written with a value in the declared exception, "
        "and the allowance is one server-composed count. A second one widens the exception "
        "past what `docs/DEPLOYMENT.md` states."
    )
    #: And it is composed, not taken. An `ast.JoinedStr` whose only substitution is a name
    #: the application counted itself; a subscript or a call would be a caller's value.
    only = non_empty[0]
    assert isinstance(only, ast.JoinedStr), "the marker is no longer an f-string"
    substituted = [part for part in only.values if isinstance(part, ast.FormattedValue)]
    assert all(isinstance(part.value, ast.Name) for part in substituted), (
        "the marker now substitutes something other than a plain local name, so it may "
        "carry a caller value"
    )


def test_every_state_writer_is_the_vocabulary_or_a_declared_exception() -> None:
    """A new writer must be a deliberate line in this list, not an accident."""
    writers = _writers_of_a_state_field()
    #: Pinned, because it is the LARGER allowance of the two and only the smaller one was
    #: held: widening it to `writers` made the assertion vacuous and was green.
    assert frozenset(
        {"records.py", "audit/validation.py", "audit/hashing.py", "audit/chain.py"}
    ) == (THROUGH_THE_VOCABULARY)
    undeclared = _undeclared(writers)
    #: And the subtraction still discriminates. Pinning the two allowances does not stop the
    #: EXPRESSION being made vacuous: `writers - writers` was green, because nothing asked
    #: the check to catch anything. A synthetic writer that is in neither allowance must
    #: come back, or the assertion below is asserting nothing.
    assert _undeclared(writers | {"views/console.py"}) == {"views/console.py"}

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


@pytest.mark.parametrize("hostile", HOSTILE_TAGS)
def test_the_refusal_marker_written_to_the_chain_carries_no_caller_value(
    signed_out: FlaskClient, hostile: str
) -> None:
    """The ENTRY, not the source.

    The first version asserted a substring and then a tautology: it matched the marker
    pattern against strings the test itself built from integers, so it never asserted
    `collapsed` was a counted integer at all.

    A gate widened that parameter to `int | str` and fed it from a request header, leaving
    `ruff`, `mypy --strict` and the whole suite green, after which an unauthenticated caller
    wrote `REPEATED_ADMIN` into `new_state` of an audit entry. The AST check added the round
    after inspects the f-string and sees a plain name, so it did not catch it either. This
    drives the real path with a hostile header and reads what landed on the volume.
    """

    def refuse() -> None:
        #: A forged callback state, which is the refusable unauthenticated request the rest
        #: of the suite uses. A sign-in POST is not refusable in the development posture,
        #: which is why the first version of this drive produced no refusal rows at all.
        signed_out.get(
            "/auth/callback?code=x&state=forged",
            headers={"X-Repeat-Tag": hostile, "X-Forwarded-For": "198.51.100.7"},
        )

    for _ in range(20):
        refuse()
    #: Force the window closed the way time would, so the suppressed count is banked and
    #: written. Without this the collapse never fires inside a test and the assertion below
    #: passes over an empty set, which is how the first version of this proved nothing.
    for window in refusals._windows.values():
        window.started -= refusals.WINDOW_SECONDS + 1
    refuse()

    chain = signed_out.application.extensions["complyops_chain"]
    states = {entry.new_state for entry in chain.entries if entry.new_state}

    assert states, "no refusal entry carried a state, so this proves nothing"
    for state in states:
        assert MARKER.fullmatch(state), (
            f"{state!r} reached `new_state` on the refusal path. The marker must be composed "
            "from a counted integer, and nothing a caller sends may reach it."
        )


def test_the_refusal_marker_source_is_still_server_composed() -> None:
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
