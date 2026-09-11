r"""The two credential rule sets are one rule set, asserted rather than asserted in prose.

`scripts/build-package.sh` sweeps the staged package; `.claude/hooks/secret-scan.mjs` blocks
this assistant's own writes. They guard the same repository by different routes, so a
difference between them is a hole in whichever is narrower. That is stated in a comment in
both files, and the comment has been false twice: first the flags diverged, so the hook
missed a lower-case spelling while the sweep missed a credential below line one, and then
eight hook rules folded case while their counterparts did not. Both were found by a
reviewer reading the two files side by side, which is not a control.

The two sets are compared as (label, pattern, flags) triples. One normalisation is needed
and only one: a Python raw string written inside double quotes carries `\\"` where a
JavaScript regular expression literal carries a bare `"`, so a backslash before a double
quote is removed on both sides before comparing. Everything else must match character for
character, including the flags.
"""

from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SWEEP = ROOT / "scripts" / "build-package.sh"
HOOK = ROOT / ".claude" / "hooks" / "secret-scan.mjs"

#: The platform runs this suite against the UNPACKED PACKAGE, and `.claude/` is the
#: assistant's baseline rather than shipped code, so the hook is not there. Skipping is
#: honest; failing would turn a green local loop into a red upload for a reason that has
#: nothing to do with the code. Found by `scripts/simulate-pipeline.sh` on the first run
#: after this module was written, which is what that simulation is for.
pytestmark = pytest.mark.skipif(
    not (SWEEP.is_file() and HOOK.is_file()),
    reason="the sweep and the hook are not both present; this is the unpacked package",
)

#: The one rule the hook carries and the sweep does not. It is a build-contract check rather
#: than a credential check: `ENV PORT` in a Dockerfile silently overrides the platform's
#: port 8080. The sweep's counterpart is a test, not a pattern. Named here so the exception
#: is a single reviewable line rather than a loosened comparison.
HOOK_ONLY = {"Dockerfile ENV PORT"}

#: The rules the sweep compiles without IGNORECASE. Mirrored from the sweep's own set, and
#: the test below reads that set from the source rather than trusting this copy.
EXPECTED_CASE_SENSITIVE = {"Credential written into prose"}

_HOOK_ENTRY = re.compile(r"^\s*\['([^']+)',\s*/(.*)/([a-z]*)\],\s*$")


def _unescape_quotes(pattern: str) -> str:
    """Drop the backslash Python needs before a double quote and JavaScript does not."""
    return pattern.replace('\\"', '"')


def _sweep_rules() -> tuple[list[tuple[str, str, str]], set[str]]:
    """Read the sweep's RULES literal and its case-sensitive set out of the shell script."""
    source = SWEEP.read_text(encoding="utf-8")
    marker = "]\n#: The rules that must NOT fold case"
    literal = source[source.index("RULES = [") + len("RULES = ") : source.index(marker) + 1]
    rules: list[tuple[str, str]] = ast.literal_eval(literal)

    case_sensitive_block = source[source.index("CASE_SENSITIVE = {") :]
    case_sensitive = ast.literal_eval(
        case_sensitive_block[len("CASE_SENSITIVE = ") : case_sensitive_block.index("}") + 1]
    )
    triples = [
        (label, _unescape_quotes(pattern), "m" if label in case_sensitive else "im")
        for label, pattern in rules
    ]
    return triples, set(case_sensitive)


def _hook_rules() -> list[tuple[str, str, str]]:
    """Read the hook's RULES array as text, because importing it would need a JS runtime."""
    source = HOOK.read_text(encoding="utf-8")
    array = source[
        source.index("const RULES = [") : source.index("];", source.index("const RULES = ["))
    ]
    found = []
    for line in array.splitlines():
        match = _HOOK_ENTRY.match(line)
        if match is not None:
            label, pattern, flags = match.groups()
            found.append((label, _unescape_quotes(pattern), "".join(sorted(flags))))
    return found


def test_the_two_rule_sets_are_one_rule_set() -> None:
    """Every sweep rule is in the hook, with the same pattern and the same flags."""
    sweep, _ = _sweep_rules()
    hook = [entry for entry in _hook_rules() if entry[0] not in HOOK_ONLY]

    assert hook, "no rules parsed out of the hook; the parser has drifted from the file"
    assert set(sweep) == set(hook), (
        "the sweep and the hook disagree.\n"
        f"  only in the sweep: {sorted(set(sweep) - set(hook))}\n"
        f"  only in the hook:  {sorted(set(hook) - set(sweep))}"
    )


def test_the_rule_sets_are_in_the_same_order() -> None:
    """Order too, because a reviewer reads them side by side and a reorder hides a swap."""
    sweep, _ = _sweep_rules()
    hook = [entry for entry in _hook_rules() if entry[0] not in HOOK_ONLY]

    assert [label for label, _, _ in sweep] == [label for label, _, _ in hook]


def test_every_line_of_the_hook_array_was_parsed() -> None:
    """A line the parser cannot read is invisible, and the comparison then proves nothing.

    Set inequality catches a rule that is DROPPED from the hook, so the hole is
    one-directional: an unparsed hook-only rule passes the exception test above while
    nothing ever reads it. The sweep wraps its own long rules across lines, so that style
    is one edit away from being used here too.
    """
    source = HOOK.read_text(encoding="utf-8")
    start = source.index("const RULES = [")
    array = source[start + len("const RULES = [") : source.index("];", start)]
    substantive = [
        line for line in array.splitlines() if line.strip() and not line.strip().startswith("//")
    ]

    assert len(substantive) == len(_hook_rules()), (
        "the hook array holds lines the parser did not read:\n  "
        + "\n  ".join(line for line in substantive if not _HOOK_ENTRY.match(line))
    )


def test_the_hook_only_exception_is_exactly_one_rule() -> None:
    """The exception is a licence to differ, so it is pinned rather than described."""
    hook_labels = {label for label, _, _ in _hook_rules()}
    sweep_labels = {label for label, _, _ in _sweep_rules()[0]}

    assert hook_labels - sweep_labels == HOOK_ONLY
    assert sweep_labels - hook_labels == set()


def test_the_case_sensitive_set_is_what_the_sweep_says_it_is() -> None:
    """A rule quietly moved into the no-fold set would lose the lower-case spelling."""
    _, case_sensitive = _sweep_rules()

    assert case_sensitive == EXPECTED_CASE_SENSITIVE


def test_every_rule_compiles_and_the_flags_are_the_ones_read() -> None:
    """The triples are text until something compiles them, and text can be nonsense."""
    sweep, case_sensitive = _sweep_rules()

    for label, pattern, flags in sweep:
        compiled = re.compile(
            pattern, re.MULTILINE | (0 if label in case_sensitive else re.IGNORECASE)
        )
        assert compiled.flags & re.MULTILINE, label
        assert bool(compiled.flags & re.IGNORECASE) == ("i" in flags), label


#: One probe per rule, each a string the rule must match, each ASSEMBLED FROM PARTS so the
#: literal never appears in this module. The packaging sweep scans this file, and a probe
#: written whole makes the build refuse its own test suite; that has happened five times in
#: this repository. The mapping is asserted to be total against the hook's own rule list, so
#: a rule added without a probe fails here rather than going unexercised.
_VALUE = "Abc8Qk" + "Pz3nR9wLmT2xV6" + "yH1jF4dS7gB0"
_NAME = "CLIENT_" + "SECRET"
PROBES = {
    "AWS access key id": "AKIA" + "ABCDEFGHIJKLMNOP",
    "Generic API key assignment": "api_" + "key" + ' = "' + _VALUE + '"',
    "Bearer token": "Bearer " + "abcdefghijklmnopqrstuvwxyz01",
    "Private key block": "-----BEGIN " + "PRIVATE " + "KEY-----",
    "LLM provider key": "sk-" + "abcdefghijklmnopqrstuvwxyz01",
    "Google API key": "AIza" + "a" * 35,
    "Slack token": "xoxb-" + "1234567890abcdef",
    "GitLab personal token": "glpat-" + "abcdefghijklmnopqrstuv",
    "Client-side access gate": "ADMIN_" + "PIN" + ' = "' + '4821"',
    "Unquoted environment-file credential": "ENV " + _NAME + "=" + _VALUE,
    "Credential written into prose": "Set " + _NAME + "=" + _VALUE + " in the console.",
    "Credential in a document table row": "| `" + _NAME + "` | set | " + _VALUE + " |",
    "Dockerfile ENV PORT": "ENV " + "PORT" + "=8080",
}


#: Every field a write can carry its new content in, and the tool that carries it. A hook
#: that reads only the first of these is blind to every `Edit` and `MultiEdit`, which is the
#: majority of writes to the very files these rules exist for, and every probe below went
#: through `content` alone until a reviewer cut the other three and left the suite green.
PAYLOAD_SHAPES = {
    "Write, content": ("Write", lambda probe: {"content": probe}),
    "Edit, new_string": ("Edit", lambda probe: {"new_string": probe}),
    "Write, file_text": ("Write", lambda probe: {"file_text": probe}),
    "MultiEdit, edits": ("MultiEdit", lambda probe: {"edits": [{"new_string": probe}]}),
}

#: The matcher both registration files must carry. A hook that is correct and unregistered
#: for `Edit` is a hook that never runs on an edit, which is the same outcome as a hook that
#: cannot read `new_string`, and neither file ships so nothing else would notice.
REQUIRED_MATCHER = "Write|Edit|MultiEdit"
REGISTRATIONS = (
    ROOT / ".claude" / "settings.json",
    ROOT / ".claude" / "hooks" / "hooks.json",
)


def _hook_verdict(content: str, shape: str = "Write, content") -> subprocess.CompletedProcess[str]:
    """Run the hook exactly as Claude Code runs it: a JSON payload on standard input."""
    tool, build = PAYLOAD_SHAPES[shape]
    payload = json.dumps({"tool_name": tool, "tool_input": build(content)})
    node = shutil.which("node")
    # NOT a skip. The module already established that this is the developer tree rather than
    # the unpacked package, and in the developer tree `node` is the hook's own prerequisite:
    # without it the hook has never run on a single write. Skipping printed LOOP: PASS with
    # the control unheld, which is the failure mode this module exists to stop.
    assert node is not None, "node is missing, so the pre-write hook has never run here"
    return subprocess.run(  # noqa: S603
        [node, str(HOOK)], input=payload, capture_output=True, text=True, check=False
    )


def test_every_rule_the_hook_carries_has_a_probe() -> None:
    """The probe set is total, so a new rule cannot be added without being exercised."""
    labels = {label for label, _, _ in _hook_rules()}

    assert labels == set(PROBES), (
        f"rules with no probe: {sorted(labels - set(PROBES))}; "
        f"probes with no rule: {sorted(set(PROBES) - labels)}"
    )


@pytest.mark.parametrize("shape", sorted(PAYLOAD_SHAPES))
def test_the_hook_reads_every_field_a_write_can_carry(shape: str) -> None:
    """WHICH text reaches the rules, which is a separate control from what the rules are.

    A reviewer reduced the hook's input collection to `tool_input.content` alone and left
    all twenty-one tests green while every `Edit` and `MultiEdit` write stopped being
    scanned. The rule array was untouched, so the parity tests could not see it: they
    compare rules, and this compares reach.
    """
    blocked = _hook_verdict(PROBES["Unquoted environment-file credential"], shape)

    assert blocked.returncode == 2, f"{shape} was not scanned: exit {blocked.returncode}"
    assert "Unquoted environment-file credential" in blocked.stderr, blocked.stderr


@pytest.mark.parametrize("registration", REGISTRATIONS)
def test_the_hook_is_registered_for_every_write_tool(registration: Path) -> None:
    """A hook unregistered for `Edit` is a hook that never runs on an edit.

    Neither registration file ships in the package, and nothing else in the suite reads
    them, so deleting `Edit|MultiEdit` from either matcher was green.
    """
    if not registration.is_file():
        pytest.skip(f"{registration.name} is not present in this tree")
    declared = json.loads(registration.read_text(encoding="utf-8"))

    matchers = [
        entry.get("matcher")
        for entry in declared.get("hooks", declared).get("PreToolUse", [])
        if any("secret-scan" in hook.get("command", "") for hook in entry.get("hooks", []))
    ]

    assert matchers, f"{registration.name} does not register the secret scan at all"
    assert all(matcher == REQUIRED_MATCHER for matcher in matchers), matchers


@pytest.mark.parametrize("label", sorted(PROBES))
def test_the_hook_actually_blocks_each_rule(label: str) -> None:
    """Behaviour, not text, because the parity test above compares only the rule array.

    A reviewer defeated that by leaving the array untouched and iterating only its first
    element: twelve of thirteen rules stopped blocking with every parity test green.
    CLAUDE.md names this hook in its first hard rule, and the threat model says a control
    that exists must be held by a test, so the hook is executed here rather than read.
    """
    result = _hook_verdict(PROBES[label])

    assert result.returncode == 2, f"{label} did not block: exit {result.returncode}"
    assert label in result.stderr, f"{label} blocked without naming itself: {result.stderr}"


def test_the_hook_allows_content_that_carries_no_credential() -> None:
    """The positive control. A hook that blocks everything is a hook someone switches off."""
    allowed = [
        "def add(left: int, right: int) -> int:\n    return left + right\n",
        _NAME + "=[REDACTED:secret]",
        "boot: inputs TENANT_ID=set(32+), AUDIT_HMAC_" + "KEY" + "=MISSING(0), ...",
        "| `" + _NAME + "` | Operator-set | [REDACTED:secret] |",
    ]
    for content in allowed:
        result = _hook_verdict(content)

        assert result.returncode == 0, f"the hook blocked benign content: {result.stderr}"
