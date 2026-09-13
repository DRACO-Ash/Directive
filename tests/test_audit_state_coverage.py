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
from types import MappingProxyType

import flask
import pytest
from flask.testing import FlaskClient

from complyops import create_app, records
from complyops.audit.journal import read_entries
from complyops.views import refusals

SRC = Path(__file__).resolve().parents[1] / "src" / "complyops"

#: Real key material, published on purpose: it is not a credential. Same value the rest of
#: the suite uses.
SUITE_KEY = bytes(range(32)).hex()

#: What a caller might try to smuggle into the collapsed count. Each is a shape that would
#: satisfy an unguarded f-string and none is a counted integer.
#:
#: They do not all fail the same way, and that is measured rather than assumed. `ADMIN` and
#: `ASH_HIGGINS` satisfy the audit boundary's state rule, so a smuggled one LANDS and the
#: `MARKER` check is what catches it. `0 OR 1` and `1; DROP` carry a space and a semicolon,
#: which the boundary refuses, so `_record_authentication` swallows the `AuditFieldError`
#: and no row is written at all: those two are caught by the "no row was written" guard
#: instead. A gate read that as two cases that cannot falsify; both drives below were
#: mutated with all four and all four went red, by one route or the other. Keeping the
#: refused pair is deliberate, because a widening of the boundary rule and a widening of
#: the marker are different edits and this corpus should notice either.
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


#: One case per syntactic form the reader knows, each with a negative twin that names a
#: field the reader must NOT match. Without the twin a case is satisfied by a reader that
#: returns True for everything, which is the shape the vacuous first version had.
#:
#: The forms are not hypothetical in the same way. `Constant` and `Name` are both live in
#: `src/` today and the two assertions below name the modules. `keyword`, `arg` and
#: `Attribute` are not live, and that is exactly why they are held here: they were added
#: because a gate wrote `chain.append(dict(..., new_state=caller_value))` and walked past a
#: constant-only scan, so the branch that catches that writer has to be red before the
#: writer exists, not after.
READER_FORMS = (
    ("a string constant", 'entry = {"new_state": value}', 'entry = {"new_stat": value}'),
    ("a keyword argument", "chain.append(new_state=value)", "chain.append(new_stat=value)"),
    (
        "a parameter name",
        "def write(*, old_state: str) -> None: ...",
        "def write(*, old: str) -> None: ...",
    ),
    ("an attribute", "return entry.new_state", "return entry.state"),
    ("an annotated declaration", "old_state: str", "old: str"),
)


@pytest.mark.parametrize(
    ("form", "names_one", "names_none"), READER_FORMS, ids=[c[0] for c in READER_FORMS]
)
def test_the_reader_sees_a_state_field_in_every_form_a_writer_can_use(
    form: str, names_one: str, names_none: str
) -> None:
    """Four of the five branches were held by nothing and deleting them was byte-identical.

    The reader grew from a constant-only scan to five forms in one commit, and the whole
    suite stayed green with the four new branches removed: `Attribute` is shadowed by the
    constant that finds the same module, and `keyword`, `arg` and `Name` had no live writer
    to find. A branch added to catch a writer that does not exist yet is the one branch a
    test has to hold, because nothing else will notice when it goes.
    """

    def sees(source: str) -> bool:
        return any(_names_a_state_field(node) for node in ast.walk(ast.parse(source)))

    assert sees(names_one), f"the reader no longer sees a state field named as {form}"
    assert not sees(names_none), f"the reader matches a non-state name in the {form} position"


def test_the_reader_form_corpus_is_not_empty() -> None:
    """Emptying the corpus is a SKIP, which `verify.sh` reads as a pass."""
    assert len(READER_FORMS) == 5


def test_the_reader_sees_the_annotation_only_writer() -> None:
    """`audit/chain.py` declares both fields and names them nowhere else.

    It reaches them through `normalise_fields`, so it belongs on the vocabulary side, and
    that is why losing sight of it is silent: `_undeclared` SUBTRACTS the allowances, so a
    reader that stops seeing an allowed module makes the set smaller rather than red. The
    pin on `THROUGH_THE_VOCABULARY` does not help either, because it pins the allowance and
    not what the reader found.
    """
    assert "audit/chain.py" in _writers_of_a_state_field()


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


@pytest.mark.parametrize("hostile", HOSTILE_TAGS)
def test_the_flood_marker_written_to_the_chain_carries_no_caller_value(
    signed_out: FlaskClient, hostile: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The OTHER writer of the same field on the same route, held by nothing until now.

    `_refuse` writes `new_state` twice: once per address from `decision.collapsed`, and once
    for the whole window from `decision.flood`. The drive above reaches only the first, so
    feeding the flood row's count from a request header was green across the whole suite,
    and an unauthenticated caller could put `REPEATED_ADMIN` into an audit entry by the
    second door after the first was closed. That is the engineering gate's own rule from
    the round before: when a fix establishes a rule, sweep the rule's siblings in the same
    commit. This is the sibling.

    The flood row needs the global row budget spent and the window rolled. The budget is
    lowered rather than driven to its real 500, because 500 fsynced entries per parameter
    is the cost of the realism and the path exercised is identical; `_budget` is then aged
    the way time would age it. Addresses come from `REMOTE_ADDR`, because `_client_ip`
    reads the socket and never `X-Forwarded-For`, so a header cannot spread the flood.
    """
    monkeypatch.setattr(refusals, "GLOBAL_ROWS_PER_WINDOW", 3)

    def refuse(address: str) -> None:
        signed_out.get(
            "/auth/callback?code=x&state=forged",
            headers={"X-Repeat-Tag": hostile},
            environ_base={"REMOTE_ADDR": address},
        )

    for number in range(10):
        refuse(f"198.51.100.{number}")
    #: Past the budget, so the overflow is non-empty and the roll below has something to
    #: report. Without this the flood row is never composed and the assertion is vacuous.
    assert refusals._budget.refusals_over, "nothing overflowed, so no flood row is composed"
    refusals._budget.started -= refusals.WINDOW_SECONDS + 1
    refuse("198.51.100.200")

    chain = signed_out.application.extensions["complyops_chain"]
    flood = [entry for entry in chain.entries if entry.action == "LOGIN_FAILED_FLOOD"]

    assert flood, "no flood row was written, so this proves nothing"
    for entry in flood:
        assert MARKER.fullmatch(entry.new_state), (
            f"{entry.new_state!r} reached `new_state` on the flood path. The marker must be "
            "composed from a counted integer, and nothing a caller sends may reach it."
        )
        #: And the address count beside it, which is the same shape of value from the same
        #: decision and reaches an audit field through an f-string the same way.
        assert re.fullmatch(r"addresses-(atleast-)?\d+", entry.resource_id), (
            f"{entry.resource_id!r} reached `resource_id` on the flood path"
        )


#: Every header a proxy, a CDN or a load balancer conventionally sets to carry the original
#: client address. None of them is evidence, because any caller can send any of them.
FORWARDING_HEADERS = (
    "X-Forwarded-For",
    "X-Real-IP",
    "Forwarded",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Client-IP",
    "X-Original-Forwarded-For",
)


@pytest.mark.parametrize("header", FORWARDING_HEADERS)
def test_the_recorded_source_address_comes_from_the_socket_never_a_header(
    signed_out: FlaskClient, header: str
) -> None:
    """AUD-001's source address is evidence, so it may not be caller-asserted.

    The property held and nothing held it: changing `_client_ip` to
    `request.headers.get("X-Forwarded-For") or request.remote_addr` left all 1253 tests
    green. Measured consequence of that one line: 40 requests from ONE address rotating the
    header wrote 40 durable refusal rows with 40 distinct recorded addresses, defeating
    `RECORDED_PER_WINDOW = 3`, and `X-Forwarded-For: ash.higgins.laptop` landed verbatim in
    the `source_ip` of an immutable entry.

    That is the whole value of keeping authentication in the application rather than
    delegating it to the platform gateway, which CLAUDE.md records as Ash's decision: the
    audit entry's attribution comes from what the container actually saw, not from a header
    a caller reaching the pod directly could assert.
    """
    forged = "203.0.113.9"
    signed_out.get(
        "/auth/callback?code=x&state=forged",
        headers={header: forged},
        environ_base={"REMOTE_ADDR": "198.51.100.4"},
    )

    chain = signed_out.application.extensions["complyops_chain"]
    recorded = {entry.source_ip for entry in chain.entries}

    assert recorded, "no entry was written, so this proves nothing"
    assert forged not in recorded, (
        f"{header} reached the source address of an audit entry. AUD-001's source address "
        "is evidence, and a header a caller sets is not."
    )
    assert recorded == {"198.51.100.4"}, (
        f"the recorded address is {recorded}, not the socket address the container saw"
    )


@pytest.mark.parametrize("header", FORWARDING_HEADERS)
def test_a_register_entry_records_the_socket_address_not_a_header(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, header: str
) -> None:
    """The SECOND reader, on an authenticated route, which no drive reached.

    `views/api.py` has its own `_client_ip` and the refusal drive above never touches it,
    so that reader rested on the source pin alone: rewriting it to
    `request.environ.get("HTTP_X_FORWARDED_FOR")` left all 1267 tests green while letting a
    caller set the recorded `source_ip` on every register-mutation entry. A pin and a drive
    catch different mutations, and this reader had only one of the pair.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    client = create_app().test_client()
    client.post(
        "/sign-in",
        data={
            "actor": "ash.higgins@bluestaq.uk",
            "csrf_token": client.get("/").headers["X-CSRF-Token"],
        },
    )
    token = {"X-CSRF-Token": client.get("/").headers["X-CSRF-Token"], header: "203.0.113.9"}

    created = client.post("/api/registers/tasks", json={"title": "Access review"}, headers=token)
    assert created.status_code == 201, created.get_data(as_text=True)

    chain = client.application.extensions["complyops_chain"]
    written = [entry for entry in chain.entries if entry.action == "TSK_CREATED"]

    assert written, "no register entry was written, so this proves nothing"
    for entry in written:
        assert entry.source_ip != "203.0.113.9", (
            f"{header} reached the source address of a register entry through the api "
            "reader. AUD-001's source address is evidence, and a header is not."
        )


#: The audit-entry field whose value may never be built from anything a caller sends, and
#: the FOUR shapes a module can write it in: a keyword argument, a dict literal value, a
#: subscript store onto an entry after the literal, and an annotated assignment. The first
#: version read two, and a pin keyed only on the keyword missed `auth_routes.py`'s dict.
ADDRESS_KEYWORD = "source_ip"

#: Every NAME and every ATTRIBUTE that may appear in a source address value, anywhere in the
#: package. A whitelist of what may be there, not a ban on what may not, and the difference
#: decided four demonstrated attacks.
#:
#: The rule before this banned the word `request` inside the value. A gate walked past it
#: four ways, twice end to end with attacker-chosen addresses in durable signed entries and
#: the whole loop at `LOOP: PASS`: a one-line local hoist, where the value is a bare name and
#: mentions nothing; `flask.request` qualified, where `request` is an Attribute and not a
#: Name; an aliased import, `from flask import request as req`; and a subscript store onto
#: the entry after the dict literal the pin was reading. A ban has to enumerate the spellings
#: of the thing it forbids. A whitelist enumerates the four names this application actually
#: uses, and those do not grow when Flask gains a new alias.
#:
#: This is a RESTORATION. The first version of this pin demanded a bare `_client_ip()` and
#: was loosened to accommodate the refusal path's legitimate values. The gate's judgement on
#: that trade is recorded and correct: the strict form would have refused the first two
#: attacks on sight. The loosening is undone and those values are admitted by NAME instead.
#: Each admitted name carries the shipped expression that needs it, because a bare set
#: gives a maintainer nothing to decide against and this one has to be edited whenever a
#: legitimate value does not fit. `test_every_admitted_name_is_reached_by_some_value`
#: below asserts every entry here is actually reached, so a stale entry reds rather than
#: lingering as silent permission. That sentence shipped for a commit while the assertion
#: it described did not exist: `reached` was collected and never compared, and a sixth
#: never-reached name left the whole suite green.
ADDRESS_VALUE_NAMES = MappingProxyType(
    {
        "_client_ip": "views/api.py and the else-branch of views/auth_routes.py",
        "recordable": "the audit boundary's validator, in auth_routes' conditional",
        "source_ip": "the PARAMETER of records.mutate and _record_authentication",
        "collapsed": "the refusal summary at auth_routes.py, whose address came from _client_ip",
        #: The fifth, and it arrived the moment the resolver learned loop targets: `collapsed`
        #: is bound by `for collapsed in decision.collapsed`, so resolving that binding makes
        #: the pin read `decision.collapsed` and `decision` has to be admitted with it.
        "decision": "the refusal tracker's verdict, which `collapsed` is bound from",
    }
)
ADDRESS_VALUE_ATTRIBUTES = frozenset({"address", "collapsed"})

#: Where a source address is assembled outside `views/`, and why each is sound. Declared,
#: because the derivation now ranges over the WHOLE package: a gate reached a durable entry
#: through `records.py`, which a `views/`-only derivation could not see.
ASSEMBLED_OUTSIDE_THE_VIEWS = {
    "audit/validation.py": "the field's length cap, an integer, not an address",
    "records.py": "passes through the parameter its pinned callers fill",
}


def _bound_names(target: ast.AST) -> list[str]:
    """Return every plain name a binding target introduces, unwrapping tuples and stars."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, ast.Tuple | ast.List):
        return [name for element in target.elts for name in _bound_names(element)]
    if isinstance(target, ast.Starred):
        return _bound_names(target.value)
    return []


def _assigned_at_module_and_function_scope(  # noqa: PLR0912 - one branch per binding form, enumerated
    tree: ast.AST,
) -> dict[str, list[ast.AST]]:
    """Return every expression a plain name is bound to, in the eight forms enumerated here.

    Not "every form": the first version of this docstring said so while reading two, then
    said so again while reading seven, and a gate found the eighth both times. The count is
    stated and the forms are numbered so the claim is checkable rather than aspirational.

    Eight forms, and the first version read two. A gate defeated it with the third:

        for collapsed in (request.headers.get("X-Peer-Address") or _client_ip(),):
            _record_authentication(..., source_ip=collapsed)

    `collapsed` is a whitelisted name, the value at the keyword is a bare `Name`, and a
    resolver that reads only `Assign` and `AnnAssign` finds NO binding for it, so nothing
    is resolved and the whitelist passes it on sight. Measured: an unauthenticated caller's
    `X-Peer-Address` in a durable signed entry on the volume, whole loop green.

    That is the same class of miss this module was fixing one level down. The collector
    learned four STORE forms and the resolver still knew two BINDING forms, so the
    enumeration is now explicit in both and each is named.

    A function PARAMETER is deliberately not a binding here. It is the seam a pinned caller
    fills, and `source_ip` is a parameter in both `records.mutate` and
    `_record_authentication`; treating it as an unresolvable binding is what distinguishes
    that seam from a local somebody composed.
    """
    bound: dict[str, list[ast.AST]] = {}

    def bind(target: ast.AST, value: ast.AST) -> None:
        for name in _bound_names(target):
            bound.setdefault(name, []).append(value)

    for node in ast.walk(tree):
        #: 1 and 2, the two the first version knew.
        if isinstance(node, ast.Assign):
            for target in node.targets:
                bind(target, node.value)
        if isinstance(node, ast.AnnAssign) and node.value:
            bind(node.target, node.value)
        #: 3, the loop target, which is what the gate used.
        if isinstance(node, ast.For | ast.AsyncFor):
            bind(node.target, node.iter)
        #: 4, the context manager's bound name.
        if isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:
                if item.optional_vars is not None:
                    bind(item.optional_vars, item.context_expr)
        #: 5, the comprehension target, whose iterable is the value it takes from.
        if isinstance(node, ast.comprehension):
            bind(node.target, node.iter)
        #: 6, the walrus.
        if isinstance(node, ast.NamedExpr):
            bind(node.target, node.value)
        #: 7, the caught exception. Its value is the exception EXPRESSION, which cannot
        #: carry a header, but the binding is recorded so the name is not treated as
        #: unresolvable and waved through.
        if isinstance(node, ast.ExceptHandler) and node.name and node.type is not None:
            bound.setdefault(node.name, []).append(node.type)
        #: 8, the match capture pattern, which reproduced the seventh form's defect exactly.
        #: `match (header or request.remote_addr,): case (collapsed,):` binds a whitelisted
        #: name with no `Assign` anywhere, so the value at the keyword is a bare name with
        #: no binding to resolve and the whitelist passed it on sight. Measured: an
        #: attacker-chosen header in the `source_ip` of a durable signed entry on the
        #: volume, with format, lint, strict types and all 1293 tests green. Every capture
        #: takes from the SUBJECT, so that is what each name is bound to.
        if isinstance(node, ast.Match):
            for pattern in ast.walk(node):
                if isinstance(pattern, ast.MatchAs | ast.MatchStar) and pattern.name:
                    bound.setdefault(pattern.name, []).append(node.subject)
                if isinstance(pattern, ast.MatchMapping) and pattern.rest:
                    bound.setdefault(pattern.rest, []).append(node.subject)
    return bound


#: The fields an audit entry carries, from `audit/hashing.FIELD_ORDER`. Written out so the
#: shape check does not import the value it reasons about.
AUDIT_ENTRY_FIELDS = frozenset(
    {
        "timestamp",
        "actor",
        "action",
        "resource",
        "resource_id",
        "outcome",
        "source_ip",
        "user_agent",
        "fields_changed",
        "old_state",
        "new_state",
    }
)


def _is_an_audit_entry(node: ast.Dict) -> bool:
    """Report whether this dict literal is shaped like an audit entry.

    Two or more constant keys naming audit fields. One is too loose, since a register
    record legitimately carries a `resource_id`; two together is the entry shape.
    """
    named = {
        key.value
        for key in node.keys
        if isinstance(key, ast.Constant) and key.value in AUDIT_ENTRY_FIELDS
    }
    return len(named) >= 2


def _source_address_values(tree: ast.AST) -> list[ast.AST]:
    """Return every expression that can reach `source_ip`, in every form a view writes it.

    FOUR forms, and the first version of this saw two. A gate defeated it twice with the
    whole suite green, both on the unauthenticated `/auth/callback` path:

    ● A one-line local HOIST. `peer = request.environ.get(...) or collapsed.address` then
      `source_ip=peer` passes a pin that inspects only the expression at the keyword,
      because that expression is a bare name and mentions `request` nowhere. So a bare name
      is resolved back to everything ever assigned to it.
    ● A SUBSCRIPT assignment. `entry["source_ip"] = request.headers.get(...)` is neither a
      keyword nor a dict literal, so it was invisible to the collector AND to the derivation
      that decides which modules are pinned at all, which is the worse half: the module
      would not have been parametrised.

    The two forms already covered are the keyword argument and the dict literal value.
    """
    values: list[ast.AST] = []
    bound = _assigned_at_module_and_function_scope(tree)

    def take(value: ast.AST) -> None:
        values.append(value)
        #: A bare name is only as safe as what was put in it. One level of resolution is
        #: enough for the hoist that was demonstrated; a chain of rebinding would need more,
        #: and the ban on `request` anywhere in the resolved value is what makes one level
        #: bite, because the header read has to appear in SOME assignment to reach here.
        if isinstance(value, ast.Name):
            values.extend(bound.get(value.id, []))

    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == ADDRESS_KEYWORD:
            take(node.value)
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=True):
                if isinstance(key, ast.Constant) and key.value == ADDRESS_KEYWORD:
                    take(value)
                #: A non-Constant key, or a `**` unpacking, is UNRESOLVABLE rather than
                #: absent. A gate rebuilt the entry as `{**snapshot, _ADDRESS_FIELD: peer}`
                #: in `audit/chain.py`, so no constant key named the field, the module never
                #: joined the writing set, and the tripwire never noticed. CLAUDE.md says a
                #: control that cannot be verified is treated as failed, so an unresolvable
                #: write is collected and fails the whitelist on whatever it names.
                #: Scoped by SHAPE. The unscoped version swept every non-constant-keyed
                #: dict in the package and red on `audit/anchor.py`, `records.py` and
                #: `views/api.py`, none of which is an entry. A dict naming two or more
                #: audit fields as constants is one, and nothing else in the package is.
                if (key is None or not isinstance(key, ast.Constant)) and _is_an_audit_entry(node):
                    take(value)
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.slice, ast.Constant)
                    and target.slice.value == ADDRESS_KEYWORD
                ):
                    take(node.value)
    return values


def _view_modules() -> list[str]:
    """Return every view module, recursively, keyed by its path relative to `views/`.

    `rglob`, because `glob` is not recursive: a view PACKAGE, `views/incidents/routes.py`,
    sat outside every derivation here. Keyed on the relative path rather than the file name,
    because two modules can both be called `api.py` once a package exists.
    """
    return [str(path.relative_to(SRC / "views")) for path in sorted((SRC / "views").rglob("*.py"))]


def _views_writing_a_source_address() -> list[str]:
    """Return every module in the PACKAGE that assigns a source address, in any form."""
    return [
        str(path.relative_to(SRC))
        for path in sorted(SRC.rglob("*.py"))
        if _source_address_values(ast.parse(path.read_text(encoding="utf-8")))
    ]


@pytest.mark.parametrize("module", _views_writing_a_source_address())
def test_no_view_builds_the_source_address_from_anything_a_caller_sends(module: str) -> None:
    """Derived over EVERY view, because the hand-kept version left the live gap.

    The first version of this pin ranged over a one-element tuple naming `views/api.py`, and
    excused excluding `views/auth_routes.py` with a docstring claiming that path was held by
    `test_the_refusal_marker_source_is_still_server_composed`. That test holds `new_state`
    and says nothing about `source_ip`. Two mutations on the excluded module each folded
    `X-Forwarded-For` into the source address of a durable entry, on the UNAUTHENTICATED
    `/auth/callback` path, with the whole suite green: one at the `source_ip=` keyword of
    the collapsed row, one at the dict value in `_record_authentication`.

    This is the obligation the same commit wrote into `docs/GATE-RECORDS.md` and did not
    apply here: derive the set rather than writing the members down, because a hand-kept
    list leaves the next member unheld by default. `auth_routes.py` was already that member.

    The rule is a WHITELIST of the names and attributes a source address value may contain,
    and the docstring said otherwise for a commit after the instrument changed, which is
    worse than saying nothing: a maintainer opening this test learnt the rule it had just
    stopped using. It is not a ban on `request`. A ban has to enumerate the spellings of
    what it forbids, and it was walked past by `flask.request` qualified, by an aliased
    import, and by a local hoist that mentions nothing at all.

    `ADDRESS_VALUE_NAMES` above carries the provenance of each admitted name. Adding a sixth
    means naming the shipped expression that needs it, and a name no value reaches reds in
    `test_every_admitted_name_is_reached_by_some_value`, which unions across modules rather
    than asserting per case: a name used only by `auth_routes.py` must not red the `api.py`
    case.
    """
    #: Parametrised over the modules that WRITE one, rather than over every view with a
    #: skip for the rest. Four honest skips are still four entries that `verify.sh` reads
    #: as passes, in a suite where exactly that has retired a control before. The guard
    #: below is what stops an empty list collecting nothing at all.
    tree = ast.parse((SRC / module).read_text(encoding="utf-8"))
    bound = _assigned_at_module_and_function_scope(tree)
    values = _source_address_values(tree)
    assert values, f"{module} assembles no source address, so this case proves nothing"
    reached: set[str] = set()

    def check(value: ast.AST, via: str) -> None:
        names = {node.id for node in ast.walk(value) if isinstance(node, ast.Name)}
        attributes = {node.attr for node in ast.walk(value) if isinstance(node, ast.Attribute)}
        reached.update(names)
        assert names <= set(ADDRESS_VALUE_NAMES), (
            f"{module}: a source address value{via} names "
            f"{sorted(names - set(ADDRESS_VALUE_NAMES))}. Only "
            f"{sorted(ADDRESS_VALUE_NAMES)} may appear in one, each with its reason in "
            "`ADDRESS_VALUE_NAMES`. A whitelist, because a ban on `request` was walked past "
            "by a local, by `flask.request` qualified, and by an aliased import."
        )
        assert attributes <= ADDRESS_VALUE_ATTRIBUTES, (
            f"{module}: a source address value{via} reads "
            f"{sorted(attributes - ADDRESS_VALUE_ATTRIBUTES)}, and the only attribute one "
            f"may read is {sorted(ADDRESS_VALUE_ATTRIBUTES)}."
        )

    for value in values:
        check(value, "")
        #: One level of resolution, which is what catches the hoist. The whitelist alone
        #: admits `source_ip = request.headers.get(...)` followed by `source_ip=source_ip`,
        #: because that name is legitimately on the list: it is the PARAMETER both
        #: `records.mutate` and `_record_authentication` receive. Resolution is what
        #: distinguishes a seam a pinned caller fills from a local somebody composed.
        for node in ast.walk(value):
            if isinstance(node, ast.Name) and node.id in bound:
                for assigned in bound[node.id]:
                    check(assigned, f" assigned to `{node.id}`")


def test_the_source_address_pin_covers_every_view_that_writes_one() -> None:
    """The parametrisation is derived, so an empty one collects NOTHING and reds nowhere.

    `verify.sh` reads no skip count and no collected count, so a rename or a move that
    emptied every view of `source_ip` would retire the pin above in silence. This is the
    assertion that cannot be made vacuous by the same edit, because it names the modules.
    """
    defining = [
        module
        for module in _view_modules()
        if any(
            isinstance(node, ast.FunctionDef) and node.name == "_client_ip"
            for node in ast.walk(ast.parse((SRC / "views" / module).read_text("utf-8")))
        )
    ]
    assert sorted(defining) == ["api.py", "auth_routes.py"], (
        f"the views defining `_client_ip` are now {defining}. Each is pinned by "
        "`test_neither_client_address_reader_reaches_past_the_socket`; this assertion "
        "exists so a module joining or leaving that set is deliberate."
    )

    writing = _views_writing_a_source_address()
    expected = sorted({"views/api.py", "views/auth_routes.py", *ASSEMBLED_OUTSIDE_THE_VIEWS})
    assert sorted(writing) == expected, (
        f"the modules assembling a source address are now {sorted(writing)}, not {expected}. "
        "Each is pinned by the test above; this assertion exists so a module joining or "
        "leaving that set is a deliberate line rather than a silent widening."
    )


#: Every ATTRIBUTE the reader's body may name, and every NAME it may load. Both are
#: whitelists over the whole body rather than over `request.<attr>` specifically, because
#: scoping to that one expression left two live escapes, each green across the whole suite:
#:
#: ● An alias. `peer = request` then `peer.environ.get("HTTP_X_PEER_ADDRESS")` never forms
#:   an `Attribute` whose value is the Name `request`, so the old comprehension saw only
#:   `remote_addr` and passed, while `X-Peer-Address` landed verbatim in the `source_ip` of
#:   a durable entry and defeated `RECORDED_PER_WINDOW` on the unauthenticated path.
#: ● A helper. Any call out of the function moves the header read somewhere the pin is not
#:   looking, which is why `ADDRESS_NAMES` is a whitelist and not merely non-empty.
#:
#: Collecting every attribute in the body catches `environ`, `headers`, and any other
#: spelling; collecting every loaded name catches the alias, because the alias is a name
#: the shipped readers do not load.
ADDRESS_ATTRIBUTES = frozenset({"remote_addr"})
ADDRESS_NAMES = frozenset({"request", "recordable"})


def test_neither_client_address_reader_reaches_past_the_socket() -> None:
    """The source pin beside the drive, in both modules that read an address.

    Be exact about what this asserts, because two successive versions of this sentence
    over-claimed and both shipped in the upload package. It does NOT say "no header is
    consulted anywhere". It says: inside these two functions, the only attribute named is
    `remote_addr` and the only names loaded are `request` and `recordable`. Both halves are
    whitelists over the whole body, which is what refuses an alias and a helper; the
    version before this one scoped the attribute check to `request.<attr>` and a two-line
    alias walked past it with the whole suite green.

    What it still does not cover is the CALL SITE, where the value can be composed after
    this function returns. That is the sibling below.
    """
    #: Derived, for the reason one screen above: a new blueprint defining its own
    #: header-reading `_client_ip` passed this pin while the hand-written tuple named two
    #: modules. The tripwire below names the expected two.
    defining = [
        module
        for module in _view_modules()
        if any(
            isinstance(node, ast.FunctionDef) and node.name == "_client_ip"
            for node in ast.walk(ast.parse((SRC / "views" / module).read_text("utf-8")))
        )
    ]
    assert defining, "no view defines `_client_ip`, so this proves nothing"
    for relative in defining:
        module = f"views/{relative}"
        source = (SRC / module).read_text(encoding="utf-8")
        defined = [
            node
            for node in ast.walk(ast.parse(source))
            if isinstance(node, ast.FunctionDef) and node.name == "_client_ip"
        ]
        #: Exactly one. The lookup was `next(...)`, so a SECOND definition later in the
        #: module shadowed the first at import time and was inspected by nothing.
        assert len(defined) == 1, (
            f"{module} defines `_client_ip` {len(defined)} times. The last definition wins "
            "at import and a pin that reads the first holds nothing."
        )
        reader = defined[0]

        #: The decorators and the signature as well as the body. Walking the body alone left
        #: a decorator free to wrap the reader and return a header: measured, a forged
        #: address landed in a durable entry with the whole loop at `LOOP: PASS`.
        inspected = ast.Module(
            body=[*reader.decorator_list, *reader.body, reader.args], type_ignores=[]
        )

        touched = {node.attr for node in ast.walk(inspected) if isinstance(node, ast.Attribute)}
        assert touched <= ADDRESS_ATTRIBUTES, (
            f"{module}: `_client_ip` reads {sorted(touched - ADDRESS_ATTRIBUTES)}, and the "
            f"only attribute it may read is {sorted(ADDRESS_ATTRIBUTES)}. A header is not "
            "evidence by any spelling: `environ` carries the same values under their WSGI "
            "names, and an alias reaches them without naming `request` at all."
        )

        loaded = {
            node.id
            for node in ast.walk(inspected)
            if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        assert loaded <= ADDRESS_NAMES, (
            f"{module}: `_client_ip` loads {sorted(loaded - ADDRESS_NAMES)}. A helper or an "
            "alias is where a header read hides from a pin that inspects only this function."
        )

        #: And `recordable` must still BE the validator. The whitelist above pins the name,
        #: not the binding: a module-level `def recordable(...)` shadowing the import folded
        #: a header in and delegated, with the pin and both drives green.
        tree = ast.parse(source)
        #: `node.module` is `audit.validation` with `level` 2 for a `from ..audit.validation`
        #: import: the leading dots live in `level`, not in the name. Comparing against the
        #: dotted literal matched nothing and the assertion fired on correct source.
        imported = [
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("audit.validation")
            for alias in node.names
        ]
        assert "recordable" in imported, (
            f"{module}: `recordable` is not imported from `..audit.validation`, so the name "
            "in the whitelist above may not be the validator at all."
        )
        rebound = [
            node.name
            for node in tree.body
            if isinstance(node, ast.FunctionDef | ast.ClassDef) and node.name == "recordable"
        ] + [
            target.id
            for node in tree.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name) and target.id == "recordable"
        ]
        assert not rebound, (
            f"{module}: `recordable` is rebound at module scope, so the reader's call does "
            "not reach the audit boundary's validator."
        )


def test_every_admitted_name_is_reached_by_some_value() -> None:
    """A whitelist entry nothing uses is silent permission, and it was unheld.

    The comment on `ADDRESS_VALUE_NAMES` promised this assertion for a commit before it
    existed: the per-case test collected the names it reached and never compared them, so a
    sixth entry that no shipped value reaches was green across the whole suite.

    Unioned across every module rather than asserted per case, because `collapsed` and
    `decision` are reached only by `auth_routes.py` and `_client_ip` only by the two views,
    so a per-case assertion would red on modules that are perfectly correct.
    """
    reached: set[str] = set()
    for module in _views_writing_a_source_address():
        tree = ast.parse((SRC / module).read_text(encoding="utf-8"))
        bound = _assigned_at_module_and_function_scope(tree)
        for value in _source_address_values(tree):
            for node in ast.walk(value):
                if isinstance(node, ast.Name):
                    reached.add(node.id)
                    for assigned in bound.get(node.id, []):
                        reached.update(
                            inner.id for inner in ast.walk(assigned) if isinstance(inner, ast.Name)
                        )

    stale = set(ADDRESS_VALUE_NAMES) - reached
    assert not stale, (
        f"{sorted(stale)} are admitted by `ADDRESS_VALUE_NAMES` and no shipped value "
        "reaches them. An entry nothing uses is permission nobody asked for; delete it, or "
        "name the expression that needs it."
    )


#: Every CHANNEL a caller controls, not a list of header names. The first version of this
#: enumerated three header names and a gate walked past it three ways, each with the whole
#: loop green and each writing an attacker-chosen address into a durable signed entry: a
#: query parameter read inside `views/refusals.py`, a cookie read in a request hook, and
#: `X-Forwarded-For` read behind a condition on a PRIVATE peer address, which every drive
#: in this module missed because they all used a public or loopback socket.
#:
#: A name list generalises over mechanism and not over channel. The matrix does the reverse.
#: Names no pin and no other drive mentions, sent alongside `FORWARDING_HEADERS` so both
#: header channels carry every name the suite knows about.
UNENUMERATED_HEADER_NAMES = (
    "X-Peer-Address",
    "X-Custom-Origin",
    "X-Originating-Address",
    "X-Client-Address",
)

FORGERY_CHANNELS = (
    "an unenumerated header",
    "a header the client already sends",
    "a query parameter",
    "a cookie",
    "a form field",
    "a JSON field",
)

#: Both sides of the ingress question. `views/refusals.py` records the real client address
#: as `TBC, re-verify` pending the first deploy, so a forge conditioned on the private peer
#: the App Store ingress presents is the most likely future edit of all of them, and it was
#: invisible to every drive here until this parametrisation existed.
SOCKET_ADDRESSES = ("198.51.100.4", "10.42.0.7")

FORGED = "203.0.113.9"


def _drive_every_channel(client: FlaskClient, channel: str, socket_address: str) -> bool:
    """Send refusals and a register write, carrying the forged value in `channel`.

    Returns whether the register write landed. The JSON channel puts `source_ip` in the
    request body, and the register boundary refuses an unknown field name, which IS the
    control rather than a failure of this drive: a caller cannot smuggle the field through
    the body at all. That refusal is asserted here and the caller adjusts what it expects
    on the volume, rather than the drive quietly pretending the write succeeded.
    """
    headers = {"X-CSRF-Token": client.get("/").headers["X-CSRF-Token"]}
    #: EVERY name the suite knows, in both header channels, not one apiece. The first
    #: version sent `X-Peer-Address` and `X-Forwarded-For` alone, so a forge keyed on any
    #: third name was inert on every driven request and the whole matrix passed it: a gate
    #: read `X-Real-IP` inside `views/refusals.py` and put `ash.higgins.laptop` into the
    #: `source_ip` of a durable entry at `LOOP: PASS`. The channel enumeration was sound
    #: and the NAME enumeration inside it was the same defect one level down.
    if channel in ("an unenumerated header", "a header the client already sends"):
        for name in (*FORWARDING_HEADERS, *UNENUMERATED_HEADER_NAMES):
            headers[name] = FORGED
    if channel == "a cookie":
        client.set_cookie("src", FORGED)
    #: Only when the query channel is the one under test. It was appended to EVERY request
    #: in every case, so all twelve cases drove the query channel and a query forge reported
    #: twelve failures naming twelve different carriers, eleven of them wrong. A drive that
    #: mis-attributes its own failure sends the next reader to the wrong place.
    query = (
        f"&src={FORGED}&source_ip={FORGED}&remote_addr={FORGED}"
        if channel == "a query parameter"
        else ""
    )
    base = {"REMOTE_ADDR": socket_address}

    #: Enough refusals to bank a suppressed count, then the window aged so the collapsed
    #: row is written. Without this the drive produced `LOGIN_FAILED` only, whose address
    #: comes straight from `_client_ip`, and never `LOGIN_FAILED_REPEATED`, whose address
    #: comes from `refusals.note`. A gate forged the latter through a query parameter read
    #: inside `views/refusals.py` and every case here stayed green, because the row that
    #: carries that value was never emitted at all.
    for _ in range(refusals.RECORDED_PER_WINDOW + 2):
        client.get(f"/auth/callback?code=x&state=forged{query}", headers=headers, environ_base=base)
    for window in refusals._windows.values():
        window.started -= refusals.WINDOW_SECONDS + 1
    client.get(f"/auth/callback?code=x&state=forged{query}", headers=headers, environ_base=base)

    form = {"actor": "ash.higgins@bluestaq.uk", "csrf_token": headers["X-CSRF-Token"]}
    if channel == "a form field":
        form["source_ip"] = FORGED
    client.post(f"/sign-in?{query}", data=form, headers=headers, environ_base=base)

    body: dict[str, object] = {"title": "Access review"}
    if channel == "a JSON field":
        body["source_ip"] = FORGED
    #: The spread FIRST, then the fresh token, or the stale one from before the sign-in
    #: overwrites it and every case answers 403 instead of exercising the channel.
    token = {**headers, "X-CSRF-Token": client.get("/").headers["X-CSRF-Token"]}
    created = client.post(
        f"/api/registers/tasks?{query}", json=body, headers=token, environ_base=base
    )
    if channel == "a JSON field":
        assert created.status_code == 400, created.get_data(as_text=True)
        assert "not a field" in created.get_json()["error"], (
            "the body carried a `source_ip` and the register boundary did not refuse it "
            "by name, so the field may have been silently dropped rather than rejected"
        )
        return False
    assert created.status_code == 201, created.get_data(as_text=True)
    return True


@pytest.mark.parametrize("socket_address", SOCKET_ADDRESSES)
@pytest.mark.parametrize("channel", FORGERY_CHANNELS)
def test_no_channel_at_all_reaches_a_recorded_address_on_either_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, channel: str, socket_address: str
) -> None:
    """The BEHAVIOURAL backstop, over channels rather than over header names.

    Eight bypasses of the source pins have now been demonstrated across three gate runs,
    every one with the suite green and every one writing an attacker-chosen address into a
    durable signed entry. Five were mechanisms inside a reader or a call site. Three were
    channels: a query parameter, a cookie, and a header read only when the peer is private.

    A list of names generalises over mechanism and not over channel, so this drives the
    channels a caller actually controls and reads the entry back FROM THE VOLUME rather
    than from process memory, which is what the previous docstring claimed while reading
    memory.

    The socket address is parametrised over a public and a private value because
    `views/refusals.py` marks the real client address `TBC, re-verify` pending first
    deploy: a forge gated on `10.` is the most plausible edit this application will ever
    see, and every drive here was blind to it.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    client = create_app().test_client()

    written = _drive_every_channel(client, channel, socket_address)

    #: From the VOLUME. The in-process list is what the writer put there; the file is the
    #: evidence, and this test's predecessor said "on the volume" while reading memory.
    persisted = read_entries(str(tmp_path))
    actions = {entry.action for entry in persisted}
    #: `LOGIN_FAILED_REPEATED` too: it is the only row carrying `refusals.note`'s address,
    #: and it is the row a gate forged through. If the drive stops emitting it, this test
    #: has lost the path it exists to cover and says so rather than passing.
    expected = {"LOGIN_FAILED", "LOGIN_FAILED_REPEATED"}
    if written:
        expected.add("TSK_CREATED")
    assert expected <= actions, (
        f"the drive wrote {sorted(actions)}, expecting {sorted(expected)}, so a path this "
        "test claims to cover did not reach the volume and that half of it is vacuous."
    )

    recorded = {entry.source_ip for entry in persisted if entry.source_ip}
    assert recorded == {socket_address}, (
        f"{channel} reached the recorded address: {sorted(recorded)}, not just the socket "
        f"address {socket_address!r} the container saw. AUD-001's source address is "
        "evidence, and a caller supplies none of it."
    )


#: The modules that legitimately hold a request context. EVERY other module in the package
#: is pinned, derived rather than listed, which is the fifth time this project has had to
#: make that move and the first time in this file: a hand-kept `NO_REQUEST_CONTEXT` named
#: `views/refusals.py` alone, and a gate then forged every durable row through
#: `audit/chain.py`, which was in exactly the same position. It measured that 17 of 21
#: modules were reached by neither source pin.
#:
#: Declaring the allowed side rather than the forbidden one puts a NEW module on the pinned
#: side by default, which is the safe direction: adding a module that needs a request is a
#: deliberate line here, and adding one that does not is held automatically.
HOLDS_A_REQUEST_CONTEXT = frozenset(
    {
        "__init__.py",
        "auth.py",
        "csrf.py",
        "security_headers.py",
        "views/api.py",
        "views/auth_routes.py",
        "views/console.py",
        "views/health.py",
    }
)

#: What a module with no request context may import. A WHITELIST, because the first version
#: asserted `flask` was absent from the import names and `request` from the loaded names,
#: and a gate reached the live request with neither: `sys.modules.get("flask")` puts no
#: flask in the imports, and `.globals.request` is an Attribute rather than a Name. A
#: blacklist has to enumerate the spellings of what it forbids, which is the same lesson
#: `ADDRESS_VALUE_NAMES` learnt two commits ago.
PERMITTED_IMPORTS = frozenset(
    {
        "__future__",
        "abc",
        "base64",
        "binascii",
        "collections",
        "contextlib",
        "dataclasses",
        "datetime",
        "errno",
        "fcntl",
        "hashlib",
        "hmac",
        "json",
        "logging",
        "os",
        "pathlib",
        "re",
        "secrets",
        "shutil",
        "stat",
        "string",
        "tempfile",
        "threading",
        "time",
        "typing",
        "unicodedata",
        "urllib",
        "uuid",
        "complyops",
    }
)

#: Names that reach a module the import statements do not name. `sys` is not on the
#: whitelist above, so `sys.modules` is already refused; these close the rest of the class
#: in one line rather than waiting for each to be demonstrated.
DYNAMIC_IMPORT_NAMES = frozenset({"__import__", "eval", "exec", "globals", "vars", "compile"})


def _modules_without_a_request_context() -> list[str]:
    """Return every module in the package that must never reach for a request."""
    return [
        str(path.relative_to(SRC))
        for path in sorted(SRC.rglob("*.py"))
        if str(path.relative_to(SRC)) not in HOLDS_A_REQUEST_CONTEXT
    ]


@pytest.mark.parametrize("module", _modules_without_a_request_context())
def test_a_module_with_no_request_context_cannot_reach_one(module: str) -> None:
    """A whitelist of imports, which needs no spelling of the thing it forbids.

    Be exact about what this asserts, because the sentence it replaces said the module
    "cannot read one" and a gate read one with it green. It asserts that every import is on
    a list of modules that cannot produce a request, and that no dynamic-import name is
    loaded. Those two together leave no route to a request object that does not add an
    import, which is the property; the previous version asserted two SPELLINGS instead.
    """
    tree = ast.parse((SRC / module).read_text(encoding="utf-8"))
    imported = sorted(
        {
            node.module.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module and node.level == 0
        }
        | {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
    )
    outside = [name for name in imported if name not in PERMITTED_IMPORTS]
    assert not outside, (
        f"{module} imports {outside}, which is not on `PERMITTED_IMPORTS`. A module outside "
        f"`HOLDS_A_REQUEST_CONTEXT` must not be able to reach a request at all: its address "
        "and its fields arrive as arguments from callers that are pinned. Add the import "
        "here with its reason, or move the module to the allowed set deliberately."
    )

    loaded = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }
    dynamic = sorted(loaded & DYNAMIC_IMPORT_NAMES)
    assert not dynamic, (
        f"{module} loads {dynamic}, which reaches a module the import statements do not "
        'name. A gate used `sys.modules.get("flask")` to read the live request with no '
        "flask import and no `request` name anywhere."
    )


def test_the_request_context_allowance_is_the_one_that_shipped() -> None:
    """The allowed set is the smaller half, so it is pinned rather than merely honoured.

    Derived pins need a tripwire beside them, per the rule in `docs/GATE-RECORDS.md`: the
    derivation subtracts, so widening `HOLDS_A_REQUEST_CONTEXT` silently shrinks what is
    checked and reds nowhere.
    """
    holding = {
        str(path.relative_to(SRC))
        for path in sorted(SRC.rglob("*.py"))
        if any(
            (
                isinstance(node, ast.ImportFrom)
                and (node.module or "").split(".")[0] in {"flask", "werkzeug"}
            )
            or (
                isinstance(node, ast.Import)
                and any(alias.name.split(".")[0] in {"flask", "werkzeug"} for alias in node.names)
            )
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        )
    }
    assert holding == HOLDS_A_REQUEST_CONTEXT, (
        f"the modules importing flask or werkzeug are now {sorted(holding)}, and the "
        f"declared allowance is {sorted(HOLDS_A_REQUEST_CONTEXT)}. A module joining or "
        "leaving that set has to be a deliberate line, because everything outside it is "
        "pinned by subtraction."
    )


def test_the_address_a_view_reads_is_the_one_the_socket_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mechanism-complete assertion, which no enumeration of hooks can match.

    Every forging mechanism found so far ends the same way: `request.remote_addr` returns
    something other than the `REMOTE_ADDR` the server put in the environ. A middleware
    rewrites the environ before the Request is built, a `request_class` sets the attribute
    in `__init__`, a `before_request` or a `url_value_preprocessor` or a `request_started`
    receiver assigns it afterwards. Listing those hooks has been wrong twice; comparing the
    two values is true whatever the hook is called.
    """
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_HMAC_KEY", SUITE_KEY)
    monkeypatch.setenv("AUDIT_KEY_ID", "k1")
    monkeypatch.setenv("COMPLYOPS_ENV", "development")
    application = create_app()
    seen: list[tuple[str | None, str | None]] = []

    @application.route("/probe-the-address")
    def probe() -> str:
        seen.append((flask.request.remote_addr, flask.request.environ.get("REMOTE_ADDR")))
        return "ok"

    application.test_client().get(
        "/probe-the-address",
        headers={"X-Peer-Address": FORGED, "X-Forwarded-For": FORGED},
        environ_base={"REMOTE_ADDR": "198.51.100.4"},
    )

    assert seen, "the probe route did not run, so this proves nothing"
    for reported, environ in seen:
        assert reported == environ == "198.51.100.4", (
            f"a view reads `remote_addr` as {reported!r} while the environ carries "
            f"{environ!r}. Something between the socket and the view rewrote the address, "
            "and which hook it used does not matter."
        )


#: Derived from a BARE application rather than written down, for the same reason the source
#: corpora are. A written list of four went stale immediately, because
#: `before_first_request_funcs` was removed in Flask 2.3 and naming it raised
#: `AttributeError` instead of asserting anything. Deriving means a registry Flask ADDS is
#: compared automatically and one it REMOVES simply leaves the set.
def _hook_registries(bare: flask.Flask) -> list[str]:
    """Return every per-application registry a bare Flask carries that runs BEFORE a view."""
    return sorted(
        name
        for name in vars(bare)
        #: A DECLARED exclusion, which the first version left unstated. Selecting on
        #: `isinstance(..., dict)` alone was tried and is far too wide: `blueprints`,
        #: `config` and `extensions` are all dicts a real application legitimately fills,
        #: so the comparison would red on every correct build. The suffix set is therefore
        #: the filter, and it is the ORIGINAL four. `_processors` was added to it and then
        #: removed, and this comment described the version that did not ship for a commit,
        #: which is the promise-without-implementation class this file has now been caught
        #: on twice. `template_context_processors` is declared OUT, for a reason stronger
        #: than render-time ordering: no audit-writing view renders at all. `render_template`
        #: appears in `views/auth_routes.py` and `views/console.py` and neither writes an
        #: entry, measured, so a context-processor forge reaches nothing.
        #:
        #: The residual is bounded rather than vague. Enumerating `vars(flask.Flask(...))`,
        #: the only dict-valued members outside this suffix set are
        #: `template_context_processors`, `blueprints`, `config` and `extensions`, and none
        #: of them runs before a view on this Flask version. So the residual is EMPTY today,
        #: and the backstop for a future one is the channel matrix rather than
        #: `test_the_address_a_view_reads_is_the_one_the_socket_reported`, which drives two
        #: header names at one socket and so backstops an unconditional forge only.
        if name.endswith(("_funcs", "_preprocessors", "_functions", "_handlers"))
        and isinstance(getattr(bare, name), dict)
        #: Only what runs BEFORE the view. `after_request_funcs` legitimately carries the
        #: AMD-001 security headers and the CSRF token attachment, and nothing that runs
        #: after a view can change the address that view already read.
        and not name.startswith(("after_", "teardown_", "error_"))
        #: `view_functions` matches the suffix and is the route TABLE, not a hook: adding a
        #: route does not run anything before another route's view. Declared rather than
        #: filtered by shape because it is the one exception, and routes are already held
        #: by the authorisation and CSRF walks in `test_application.py`.
        and name != "view_functions"
    )


def test_nothing_between_the_socket_and_the_view_is_wired_to_rewrite_the_address(
    signed_out: FlaskClient,
) -> None:
    """The application carries no pre-view hook a bare Flask does not, on either object.

    `gunicorn wsgi:app` serves `wsgi.app`; the fixture builds its own from `create_app()`.
    A wrap installed in `wsgi.py` after the factory returns is the live path and is
    invisible to the factory's product, so both are checked.

    This asserts the SHAPE, and enumeration has been wrong twice here: the first version
    named `wsgi_app` and a gate forged the address with `request_class` and
    `before_request_funcs`; the second named those and a gate forged it with
    `url_value_preprocessors` and a `request_started` receiver. Its companion,
    `test_the_address_a_view_reads_is_the_one_the_socket_reported`, asserts the OUTCOME and
    is mechanism-complete. Both are kept because they fail in different directions: the
    shape check names the hook, the outcome check needs no name at all.
    """
    import wsgi  # noqa: PLC0415 - imported here so the module's own boot runs under the fixture

    bare = flask.Flask(__name__)
    registries = _hook_registries(bare)
    assert registries, "a bare Flask exposes no pre-view registry, so this proves nothing"

    served = (("the factory's product", signed_out.application), ("wsgi.app", wsgi.app))
    for label, application in served:
        #: `getattr`, because a wrapped `wsgi_app` has no `__self__` and the bare attribute
        #: access raises before the assertion's message can print.
        assert getattr(application.wsgi_app, "__self__", None) is application, (
            f"{label}: `wsgi_app` is {application.wsgi_app!r}, not Flask's own unwrapped "
            "application. A middleware there rewrites `REMOTE_ADDR` before the Request is "
            "even built."
        )
        assert type(application) is flask.Flask, (
            f"{label}: the application is {type(application)!r}. A subclass can override "
            "`preprocess_request` or `request_context` and never touch a named hook."
        )
        #: The class itself, not only its identity. Assigning
        #: `Request.remote_addr = property(...)` at package scope leaves `type(application)`
        #: and `request_class` both unchanged, installs no hook, defines no `_client_ip` and
        #: assembles no `source_ip`, so it walked past every instrument in this module and
        #: put an unauthenticated caller's arbitrary string into three durable signed
        #: entries with format, lint, strict types, bandit and all 1304 tests clean. One
        #: assertion, no header name and no channel: the attribute must not be shadowed.
        #: The whole MRO, not one class, and the reason is measurable rather than
        #: cautious: at HEAD `remote_addr` is on NO class in the chain, because the sansio
        #: `__init__` sets it as an instance attribute. Reading `vars(request_class)` alone
        #: therefore guarded one empty slot of three, and a gate patched
        #: `werkzeug.sansio.request.Request` with a data descriptor and forged all seven
        #: durable rows with the loop green. `__getattribute__` is in the set because
        #: installing one on the base is the same escape by another name.
        #:
        #: A metaclass and a class-level `__getattr__` are NOT vectors and are deliberately
        #: not asserted: instance attribute lookup never consults the metaclass, and
        #: `__getattr__` only fires when normal lookup fails, which it does not because the
        #: attribute is set in `__init__`. Recorded so nobody adds two assertions that
        #: cannot fail.
        shadowed = [
            f"{klass.__module__}.{klass.__qualname__}.{name}"
            for klass in application.request_class.__mro__
            for name in ("remote_addr", "__getattribute__", "__getattr__")
            if name in vars(klass) and klass is not object
        ]
        assert not shadowed, (
            f"{label}: {shadowed} shadows the address on the request class chain. A "
            "descriptor anywhere in the MRO rewrites it for every request while the class "
            "identity, the hook registries and both `_client_ip` bodies stay untouched."
        )
        assert application.request_class is bare.request_class, (
            f"{label}: `request_class` is {application.request_class!r}. A subclass sets "
            "`remote_addr` in its own `__init__`, before any view reads it."
        )
        for registry in registries:
            assert getattr(application, registry) == getattr(bare, registry), (
                f"{label}: `{registry}` is {getattr(application, registry)!r} against a "
                f"bare Flask's {getattr(bare, registry)!r}. Anything registered there runs "
                "before the view and can assign `request.remote_addr` outright."
            )
        #: The routing converters, which run BEFORE every hook: a `UnicodeConverter`
        #: subclass installed before `register_blueprint` executes during routing and can
        #: assign `remote_addr` ahead of anything in the registries above. `url_map` is in
        #: `vars()` and is not a dict, so the comparison below never reached it.
        assert application.url_map.converters == bare.url_map.converters, (
            f"{label}: the routing converters differ from a bare Flask's. A converter runs "
            "during routing, before every hook, and can rewrite the address there."
        )
        #: `list`, because `receivers_for` returns a GENERATOR and a generator is always
        #: truthy: the assertion could never have passed, which is its own kind of unheld.
        connected = list(flask.request_started.receivers_for(application))
        assert not connected, (
            f"{label}: {connected} is connected to `request_started`. It runs with the "
            "request context live and can assign `remote_addr` with every hook registry "
            "empty."
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
