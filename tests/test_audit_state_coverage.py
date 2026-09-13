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


#: The ONLY attribute of `request` either address reader may touch, and the only function
#: either may call. A whitelist, because the blacklist this replaced named `headers` and a
#: header reaches the reader under other names: `request.environ.get("HTTP_X_PEER_ADDRESS")`
#: is the same header by its WSGI spelling, and it passed the blacklist, passed the
#: seven-header drive, and passed the whole suite, after which 40 requests from one socket
#: address wrote 40 durable rows with 40 forged `source_ip` values. A helper-function
#: indirection evaded it the same way.
#: The audit-entry field whose value may never be built from anything a caller sends, and
#: the two shapes a view can write it in: a keyword argument, and a dict value. Both forms
#: are live, and a pin keyed only on the keyword misses `auth_routes.py`'s dict entirely.
ADDRESS_KEYWORD = "source_ip"

#: What a `source_ip` value may be made of. A whitelist of CALLS plus a ban on `request`,
#: rather than a list of admissible expressions, because the shipped forms differ per module
#: (`_client_ip()`, a literal, `collapsed.address`, and a conditional over two of those) and
#: enumerating them would have to change every time one does. What must never differ is that
#: no caller-supplied value reaches the field.
ADDRESS_VALUE_CALLS = frozenset({"recordable", "_client_ip"})
REQUEST_OBJECT = "request"


def _source_address_values(tree: ast.AST) -> list[ast.AST]:
    """Return every expression assigned to `source_ip`, in either form a view writes it."""
    values: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == ADDRESS_KEYWORD:
            values.append(node.value)
        if isinstance(node, ast.Dict):
            values += [
                value
                for key, value in zip(node.keys, node.values, strict=True)
                if isinstance(key, ast.Constant) and key.value == ADDRESS_KEYWORD
            ]
    return values


def _views_writing_a_source_address() -> list[str]:
    """Return every view module that assigns a source address, in either form."""
    return [
        path.name
        for path in sorted((SRC / "views").glob("*.py"))
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

    The rule is structural rather than a list of admissible expressions: a `source_ip` value
    may call only `recordable` or `_client_ip`, and may not mention `request` at all. That
    accepts every shipped form, `_client_ip()`, the literal `"multiple"`,
    `collapsed.address`, and the conditional over the first and a validated argument, and it
    refuses a header by any spelling without needing to know which spellings exist.
    """
    #: Parametrised over the modules that WRITE one, rather than over every view with a
    #: skip for the rest. Four honest skips are still four entries that `verify.sh` reads
    #: as passes, in a suite where exactly that has retired a control before. The guard
    #: below is what stops an empty list collecting nothing at all.
    values = _source_address_values(ast.parse((SRC / "views" / module).read_text("utf-8")))

    for value in values:
        named = {node.id for node in ast.walk(value) if isinstance(node, ast.Name)}
        assert REQUEST_OBJECT not in named, (
            f"views/{module}: a `{ADDRESS_KEYWORD}` value mentions `{REQUEST_OBJECT}`. The "
            "recorded source address comes from the socket, and a header is not evidence "
            "by any spelling."
        )
        called = {
            node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id
            for node in ast.walk(value)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute | ast.Name)
        }
        assert called <= ADDRESS_VALUE_CALLS, (
            f"views/{module}: a `{ADDRESS_KEYWORD}` value calls "
            f"{sorted(called - ADDRESS_VALUE_CALLS)}. Only `recordable` and `_client_ip` "
            "may contribute to it; anything else can reach a request header."
        )


def test_the_source_address_pin_covers_every_view_that_writes_one() -> None:
    """The parametrisation is derived, so an empty one collects NOTHING and reds nowhere.

    `verify.sh` reads no skip count and no collected count, so a rename or a move that
    emptied every view of `source_ip` would retire the pin above in silence. This is the
    assertion that cannot be made vacuous by the same edit, because it names the modules.
    """
    writing = _views_writing_a_source_address()
    assert sorted(writing) == ["api.py", "auth_routes.py"], (
        f"the views writing a source address are now {writing}. Each is pinned by the test "
        "above; this assertion exists so a module leaving the set is deliberate."
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
    for module in ("views/auth_routes.py", "views/api.py"):
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
