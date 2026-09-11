r"""The house-voice hook, executed rather than read.

`.claude/hooks/house-voice.mjs` blocks an em-dash and a prose `+` in authored content, both
of which `CLAUDE.md` forbids. Nothing in this suite referenced it at all until now, and that
is why a defect shipped in it: `new_source` was added to its field list to cover
`NotebookEdit`, but the enclosing branch did not admit that tool, so the new field was
unreachable for exactly the tool it was added for and the hook exited 0 on every notebook
write. The comment beside it asserted the fix.

A style guardrail is not a threat-model control, so this module is not scored the way
`tests/test_secret_rule_parity.py` is. It exists because an unheld hook is an unheld hook,
and because the sibling module's four successive defeats all had the same root cause: the
hook was read and not run.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / ".claude" / "hooks" / "house-voice.mjs"
REGISTRATION = ROOT / ".claude" / "hooks" / "hooks.json"

#: The baseline directory, never the hook itself. Keyed on the control, the skip would be
#: co-extensive with it and one `rm` would retire the hook with the suite green, which is
#: what happened to the credential hook at the sixteenth security gate.
pytestmark = pytest.mark.skipif(
    not (ROOT / ".claude").is_dir(),
    reason="no assistant baseline here; this is the unpacked package",
)

#: An em-dash, assembled rather than written, because the house voice forbids one in this
#: file as much as anywhere else and the hook would block the edit that added it.
EM_DASH = chr(0x2014)
PROBE = "a sentence with an " + EM_DASH + " in the middle of it"

#: Every tool the hook is registered for, with the field that carries new content for it.
#: Parametrised so a tool added to the matcher without being admitted by the hook's own
#: branch is red, which is the defect this module was written for.
CONTENT_FIELDS = {
    "Write": "content",
    "Edit": "new_string",
    "MultiEdit": "edits",
    "NotebookEdit": "new_source",
}

#: `Bash` is registered too, and it is a different branch of the hook with a different rule:
#: it inspects a commit MESSAGE, which is where the `+` meaning "and" is caught. Carving it
#: out of the matcher comparison left that whole branch held by nothing, and it is the only
#: enforcement anywhere of one of the hard rules in `CLAUDE.md`.
COMMIT_COMMAND = 'git commit -m "[AUDIT] tighten auth '
PLUS_PROBE = COMMIT_COMMAND + 'and config"'.replace("and", "+")
EM_DASH_PROBE = COMMIT_COMMAND + "and config" + EM_DASH + ' properly"'
#: The same `+` outside a commit message, which is arithmetic or a flag and must pass.
INNOCENT_COMMAND = 'python -c "print(2 + 2)"'


def _verdict(tool: str, content: str) -> subprocess.CompletedProcess[str]:
    """Run the hook the way Claude Code runs it: a JSON payload on standard input."""
    written = (
        {"edits": [{"new_string": content}]}
        if CONTENT_FIELDS[tool] == "edits"
        else {CONTENT_FIELDS[tool]: content}
    )
    node = shutil.which("node")
    assert node is not None, "node is missing, so this hook has never run here"
    payload = json.dumps({"tool_name": tool, "tool_input": written})
    return subprocess.run(  # noqa: S603
        [node, str(HOOK)], input=payload, capture_output=True, text=True, check=False
    )


def _run_bash(command: str) -> subprocess.CompletedProcess[str]:
    """Run the hook against a `Bash` payload, which reaches its other branch."""
    node = shutil.which("node")
    assert node is not None, "node is missing, so this hook has never run here"
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
    return subprocess.run(  # noqa: S603
        [node, str(HOOK)], input=payload, capture_output=True, text=True, check=False
    )


def test_the_hook_is_present() -> None:
    """NOT a skip. A missing hook inside a present baseline is a missing control."""
    assert HOOK.is_file(), f"{HOOK} is missing"


@pytest.mark.parametrize("tool", sorted(CONTENT_FIELDS))
def test_the_hook_blocks_an_em_dash_from_every_registered_tool(tool: str) -> None:
    """Every tool in the matcher, because the hook has its own branch and they diverged."""
    blocked = _verdict(tool, PROBE)

    assert blocked.returncode == 2, f"{tool} was not inspected: exit {blocked.returncode}"
    assert "an em-dash (U+2014) in the authored content" in blocked.stderr, blocked.stderr


def test_the_hook_allows_ordinary_prose() -> None:
    """The positive control. A hook that blocks everything is a hook someone switches off."""
    allowed = _verdict("Write", "Ordinary prose with a single dash - and nothing else.\n")

    assert allowed.returncode == 0, allowed.stderr


#: The hook's own hit strings, in full. A substring like `"+"` or `em-dash` does not
#: discriminate: the guidance the hook prints on a refusal contains both, so either probe
#: would pass whichever rule actually fired. The exit code is what carries these tests, but
#: an assertion that reads as though it identifies the rule should identify the rule.
@pytest.mark.parametrize(
    ("probe", "expected"),
    [
        (PLUS_PROBE, 'a "+" used to mean "and" in the commit message'),
        (EM_DASH_PROBE, "an em-dash (U+2014) in the commit message"),
    ],
)
def test_the_hook_inspects_a_commit_message(probe: str, expected: str) -> None:
    """The Bash branch, which was carved out of the matcher check and held by nothing.

    Deleting the whole branch left this module green, and it is the only place the house
    rule against a `+` meaning "and" is enforced at all.
    """
    blocked = _run_bash(probe)

    assert blocked.returncode == 2, f"the commit message was not inspected: {blocked.stderr}"
    assert expected in blocked.stderr, blocked.stderr


def test_the_hook_leaves_an_ordinary_command_alone() -> None:
    """The negative control, and it is load-bearing rather than decorative.

    A `+` is arithmetic or a flag nearly everywhere. A hook that refused every one of them
    would be switched off within a day, which is why the branch inspects commit messages
    only.
    """
    allowed = _run_bash(INNOCENT_COMMAND)

    assert allowed.returncode == 0, allowed.stderr


def test_every_tool_in_the_registration_has_a_probe() -> None:
    """The matcher is the source of truth for which tools this hook must handle.

    Adding a tool to the matcher without adding it here would leave the new tool unexercised,
    which is exactly the shape of the defect above.
    """
    declared = json.loads(REGISTRATION.read_text(encoding="utf-8"))
    matchers = [
        entry.get("matcher", "")
        for entry in declared.get("hooks", declared).get("PreToolUse", [])
        if any("house-voice" in hook.get("command", "") for hook in entry.get("hooks", []))
    ]

    assert matchers, "the registration does not mention this hook at all"
    registered = {tool for matcher in matchers for tool in matcher.split("|")}

    probed = set(CONTENT_FIELDS) | {"Bash"}

    assert registered == probed, (
        f"registered for {sorted(registered)}, probed for {sorted(probed)}. Every registered "
        "tool needs a probe: carving one out left that whole branch of the hook unheld."
    )
