#!/bin/sh
# Build the App Store upload package: the artefact, and nothing that is not the artefact.
#
# This exists because the deploy gate found there was no artefact at all, so the thing
# that would be uploaded had never been built or tested. A plausible hand-assembled
# allowlist then went RED on the platform's own test stage in seconds, because the suite
# reads files from the package ROOT and two of them had not been shipped. A package is
# not a tarball of the repository and it is not the image build context either: the image
# excludes `tests/`, the platform requires them.
#
# Flat, with the Dockerfile at the root. A nested Dockerfile breaks both template
# detection and the build context, which is a recorded failure on this platform.
#
# Pure POSIX sh, like the verification loop, for the same reason.
set -eu

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"
# `dist` itself is the last predictable component, and `mkdir -p` follows a link planted
# there. Weaker than the class closed below, since anyone who can create it in the
# repository root can edit this script instead, but it costs one line to refuse.
[ ! -L dist ] || { echo "FAIL: dist is a symlink; refusing to build through it"; exit 1; }
mkdir -p dist

# The content sweep below needs an interpreter. The project's own is preferred; a system
# python3 is accepted so the package can still be built on a machine without the virtual
# environment, and the absence of both is a hard failure rather than a silent skip, because
# this is a credential control.
PY_FOR_SWEEP=""
for candidate in "${PYTHON:-.venv/bin/python}" python3; do
  if command -v "$candidate" >/dev/null 2>&1; then PY_FOR_SWEEP="$candidate"; break; fi
done
[ -n "$PY_FOR_SWEEP" ] || { echo "FAIL: no interpreter for the credential sweep"; exit 1; }

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' pyproject.toml | head -1)"
# A version with a slash in it makes $OUT and `basename "$OUT"` disagree, so the zip is
# written to one path while a different one is recorded, hashed and pointed at.
case "$VERSION" in
  "" | *[!0-9.]* ) echo "FAIL: implausible version '$VERSION' in pyproject.toml"; exit 1 ;;
esac
STAMP="$(date -u +%Y%m%d)"
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
# A package from a tree with uncommitted changes is stamped as such, so the simulation can
# refuse it. Without this, commit granularity admits a package built before an edit and the
# simulation reports PASS for a tree whose package was never built.
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  COMMIT="${COMMIT}-dirty"
fi
OUT="dist/comply-ops-${VERSION}-${STAMP}-${COMMIT}.zip"
# EVERY intermediate is created inside one private directory, and only the finished archive
# is moved out of it.
#
# The pointer race was fixed three times and each fix narrowed the class instead of closing
# it, because `dist/` held four writes to names an attacker could predict: the stage, the
# manifest, the archive and the pointer. A symlink planted at any one of them is followed by
# a `>` redirect or entered by `tar`. The manifest was taken on the FIRST attempt, truncating
# a file outside the repository and leaving the build to exit 0; the stage went the same way.
#
# `mktemp -d` is mode 0700, so a non-owner cannot traverse it, and every predictable name
# inside it is unreachable. What leaves it does so by `mv`, which uses `rename(2)` and
# REPLACES a symlink at the destination rather than following it. So the class ends here
# rather than being narrowed again.
# The trap is installed BEFORE the directory exists, not after. Set afterwards, a signal
# arriving in the gap between `mktemp -d` returning and the trap being armed killed the
# shell with the default action and left a full copy of HEAD behind: caught by the trap's
# own test, which signals as soon as the directory appears, where the security gate's
# timing had landed later and seen it work.
#
# The signals matter as much as the ordering: dash runs an EXIT trap for none of INT, TERM,
# HUP or PIPE, so `sh scripts/build-package.sh | head -2` used to leave the same copy
# behind, unbounded in number, at mode 0700.
#
# `${WORK:-}` because the trap can now fire before the assignment; `rm -rf ""` is a silent
# no-op under `-f`. A sub-millisecond window remains between the directory appearing on
# disk and the shell assigning WORK. It leaks a mode-0700 copy of HEAD and nothing else,
# and it is not reachable by choice, so it is recorded rather than closed with a glob that
# would delete a concurrent build's directory.
WORK=""
trap 'rm -rf "${WORK:-}"' EXIT HUP INT TERM PIPE
WORK="$(mktemp -d dist/.build.XXXXXX)"
STAGE="$WORK/stage"
MANIFEST="$WORK/manifest"
BUILT="$WORK/package.zip"

# Every path that ships. Anything not named here is not in the package, so a new file
# that a test reads must be added HERE as well as written, and the assertion below is
# what catches the omission before the platform does.
FILES="Dockerfile
.dockerignore
.env.example
.python-version
pyproject.toml
sonar-project.properties
requirements-runtime.in
requirements-runtime.txt
requirements.in
requirements.txt
requirements-dev.in
requirements-dev.txt
wsgi.py
README.md
SECURITY.md
CHANGELOG.md"
DIRS="src
tests
docs
scripts"

# What is deliberately NOT shipped, and why, so the next person does not add it back:
#   .git, .github, .claude   history, CI and the assistant baseline are not the product
#   .venv, __pycache__       local build output
#   data/                    runtime state; the volume supplies it
#   dist/                    this script's own output
#   coverage.xml, sbom.*     regenerated by the platform's own run; a stale copy misleads
#   CLAUDE.md, READINESS.md  internal working documents
#   .gitlab-ci.yml           the platform generates its own pipeline; a shipped copy is
#                            inert at best and misleading at worst

# Invalidate the pointer BEFORE building, not after. It was only ever written on success
# and never cleared, so a build that failed left the previous commit's package still
# pointed at, and the simulation would test that stale artefact and report PASS for a tree
# whose package never built. Reproduced in a throwaway clone.
rm -f dist/latest dist/latest.sha256 "$OUT"
mkdir -p "$STAGE"

for path in $FILES; do
  [ -f "$path" ] || { echo "FAIL: $path is named in the allowlist and does not exist"; exit 1; }
done
for path in $DIRS; do
  [ -d "$path" ] || { echo "FAIL: $path is named in the allowlist and does not exist"; exit 1; }
done

# The stage is materialised from the OBJECT DATABASE, not from a walk of the working tree,
# and that is a security boundary rather than a tidiness preference. Two attacks made the
# case, both demonstrated rather than theorised.
#
# A directory copy ships whatever is on disk. A git-ignored `src/.env` is invisible to
# `git status`, so the tree reads clean, the package is stamped with a clean commit, and the
# secret is inside it. Reading the file list from `git ls-files` closed that, and left a
# second hole open: `cp` dereferences a symlink at any INTERMEDIATE path component, so
# replacing `docs/` with a link to a directory outside the tree put host-side content into
# the artefact while every leaf-level check passed. The sweep could not see it, because `cp`
# had already resolved it.
#
# `git archive HEAD` ends the class rather than narrowing it again. The bytes come from the
# committed tree, so an ignored file, an untracked file, a symlinked directory component, a
# hardlink swapped in on disk and an `assume-unchanged` bit are all equally invisible: none
# of them is in HEAD.
#
# The consequence is worth stating plainly. The package always contains HEAD, never the
# working tree. On a dirty tree it therefore packages the committed content and the `-dirty`
# stamp says so, which is the honest signal: the artefact does not represent what you are
# looking at.
# shellcheck disable=SC2086  # deliberate: both are newline-separated allowlists of
# literal paths this file controls, each checked to exist immediately above.
git archive HEAD -- $FILES $DIRS | tar -x -C "$STAGE"
[ -n "$(find "$STAGE" -type f -print -quit)" ] || { echo "FAIL: git archive produced nothing"; exit 1; }

# `git archive` is NOT a byte-faithful copy of HEAD, and believing it was is what the
# comment above got wrong. It applies the archived tree's own `.gitattributes` and the build
# host's conversion settings, all of which an attacker reaches from a single committed file:
#
#   export-ignore   removes a path from the archive. One committed line deleted the
#                   AMD-001 10.6 security header test from the package, the build exited 0,
#                   and the pipeline simulation returned SIMULATION: PASS on an artefact
#                   with the control's test missing.
#   export-subst    substitutes attacker-chosen commit-message text into a shipped file.
#   ident           expands $Id$ in a shipped file.
#   filter          a smudge driver rewrites shipped bytes wholesale.
#   core.autocrlf   host config alone rewrites every text file, CRLF-ing the shell scripts.
#
# There is no switch that disables tree attributes, so the archive is verified against the
# object database instead. `git ls-tree` reports the mode and the blob hash of every path
# HEAD actually contains; a git blob hash is sha1("blob <len>\0" + bytes), which the checker
# recomputes from what landed in the stage. A missing path, an extra path, a changed byte, a
# committed symlink and a committed gitlink all fail here, together, for one reason: the
# stage must equal HEAD or nothing ships.
# shellcheck disable=SC2086  # deliberate, as above: newline-separated literal allowlists.
git ls-tree -r HEAD -- $FILES $DIRS > "$MANIFEST"
[ -s "$MANIFEST" ] || { echo "FAIL: HEAD contains none of the allowlisted paths"; exit 1; }
"$PY_FOR_SWEEP" - "$STAGE" "$MANIFEST" <<'VERIFY'
import hashlib
import pathlib
import sys

stage = pathlib.Path(sys.argv[1])
failures = []
expected = set()

for line in pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines():
    meta, path = line.split("\t", 1)
    mode, kind, blob = meta.split()
    if path.startswith('"'):
        failures.append(f"{path}: the path needs quoting, so it carries a control character")
        continue
    if mode == "120000" or kind != "blob":
        failures.append(f"{path}: committed as mode {mode} ({kind}), which may not ship")
        continue
    expected.add(path)
    landed = stage / path
    if not landed.is_file():
        failures.append(f"{path}: in HEAD and not in the package (a .gitattributes export-ignore does this)")
        continue
    landed_mode = "100755" if landed.stat().st_mode & 0o111 else "100644"
    if landed_mode != mode:
        failures.append(f"{path}: mode {landed_mode} in the package against {mode} in HEAD")
    raw = landed.read_bytes()
    digest = hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()  # noqa: S324
    if digest != blob:
        failures.append(f"{path}: {digest} in the package against {blob} in HEAD")

for landed in stage.rglob("*"):
    if landed.is_file() and str(landed.relative_to(stage)) not in expected:
        failures.append(f"{landed.relative_to(stage)}: in the package and not in HEAD")

for failure in failures:
    print(f"FAIL: {failure}")
if failures:
    sys.exit(1)
print(f"package verified against HEAD: {len(expected)} paths, every byte and mode matching")
VERIFY

# A symlink can still be COMMITTED, and `git archive` faithfully restores it as a link.
# Nothing in this package has any reason to be one, and `zip -r` without `-y` would store
# what it points at, so any link is refused rather than followed or preserved.
LINK="$(find "$STAGE" -type l -print -quit)"
[ -z "$LINK" ] || { echo "FAIL: $LINK is a symlink; the archiver would store what it points at"; exit 1; }

# By name. `.env.example` holds placeholders, is tracked, and the suite reads it from the
# package root, so it is the one name in this shape that must ship.
#
# This list and the one in `.gitignore` are NOT the same list, and the difference is
# deliberate. This one refuses a name INSIDE the package, which is what a `git add -f` or an
# edited ignore file reaches; the ignore list refuses a name reaching the repository at all.
# The ignore list is therefore the wider of the two, carrying `.netrc`, `.pypirc`,
# `secrets.yaml`, `secrets.yml`, `credentials.json` and `client_secret*.json` as well: those
# are configuration files that carry credentials rather than credential files, so an ignore
# rule is proportionate and refusing them from a package nobody would put them in is not.
# Every name below is held by a probe in `tests/test_package_build.py`, parametrised over
# this list, because five of these names were added in one commit and deleting all five
# left the whole suite green.
SECRET="$(find "$STAGE" ! -name '.env.example' \
               \( -name '.env' -o -name '.env.*' -o -name '*.pem' -o -name '*.key' \
                  -o -name 'id_rsa*' -o -name 'id_ed25519*' -o -name 'id_ecdsa*' \
                  -o -name 'id_dsa*' -o -name '*.jks' -o -name '*.p12' \
                  -o -name '*.pfx' -o -name '*.ppk' -o -name '*.keytab' \
                  -o -name '*.kdbx' -o -name '*.p8' \) -print -quit)"
[ -z "$SECRET" ] || { echo "FAIL: $SECRET looks like a credential and is in the package"; exit 1; }

# By CONTENT, because a name sweep is only a name sweep. A tracked file with an innocuous
# name and a credential inside it shipped in a clean-stamped package; the pre-write hook
# that would have caught it only runs on this assistant's own edits, so a human `git add`,
# a heredoc or a paste never passes through it. These are the hook's own patterns, so one
# rule set governs both routes into the repository. Be exact about "one rule set", because
# it is not identical: the one rule the hook carries and this sweep does not
# (`Dockerfile ENV PORT`, pinned by name in `tests/test_secret_rule_parity.py`) is a build-contract
# check rather than a credential check and lives in the suite instead, and the hook matches
# one joined blob while this sweep matches line by line AND joined, so a split assignment is
# caught by both ONLY where its halves are separated by whitespace: neither route crosses an
# intervening comment, which is recorded with the sweep's other limits below. A line carrying the project's existing `# noqa: S105` or `# nosec` marker
# is a declared test double and is skipped only inside the package's own top-level
# `tests/*.py`, anchored to the package root rather than matched anywhere in the path,
# because outside that the marker is a seven-character bypass for anyone who can commit.
"$PY_FOR_SWEEP" - "$STAGE" <<'SWEEP'
import collections
import hashlib
import pathlib
import re
import sys

RULES = [
    ("AWS access key id", r"\bAKIA[0-9A-Z]{16}\b"),
    ("Generic API key assignment",
     r"(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]"),
    ("Bearer token", r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    ("LLM provider key", r"\b(?:sk-[A-Za-z0-9_\-]{20,}|sk-ant-[A-Za-z0-9_\-]{20,})\b"),
    ("Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ("Slack token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"),
    ("GitLab personal token", r"\bglpat-[0-9A-Za-z_\-]{20,}\b"),
    ("Client-side access gate", r"\b(?:ADMIN_)?PIN\s*=\s*['\"][0-9A-Za-z]{4,}['\"]"),
    # The generic rule above requires QUOTES, and every secret this application actually
    # consumes is written without them. An unquoted assignment of the client secret, pasted
    # into `.env.example`, built clean and shipped at the package root, demonstrated end to
    # end. That file is the worst possible place for the gap: its whole purpose is to carry
    # exactly these names, dotenv format is unquoted by convention, the build REQUIRES it to
    # ship, and it is deliberately exempt from the filename sweep, so this is the only
    # control over it. The shape is written here by description rather than as a literal,
    # because the prose rule below correctly matched this very comment twice.
    #
    # Matched on the dotenv SHAPE rather than by widening this rule's equals to allow spaces
    # around it, which flags 22 findings on 22 lines across all 159 tracked files. Python
    # writes `SUITE_KEY = bytes(...)` with spaces around the equals; dotenv never does.
    #
    # Every figure in this file is re-measured by `tests/test_sweep_cost_figures.py`, which
    # runs the experiment against the live rules and the live tree AND asserts the sentence
    # you are reading. No commit hash is cited because none is needed: a figure that drifts
    # from the tree is a red test, not a stale sentence. That is the fifth attempt at this
    # class, after a number written three ways, a file contradicting itself 154 lines apart,
    # and a count written stale in the commit that changed what it counted.
    #
    # The trailing `[A-Z0-9_]*` is there because the keyword need not END the name:
    # `CLIENT_SECRET_V2=` walked past without it. The name must still CONTAIN one of these
    # words and not begin with one, and that restriction is deliberate and measured: making
    # the leading `[A-Z][A-Z0-9_]*` optional gives 14 findings across the tracked tree, 9 of
    # them in `src/` (eight `key_id=` and one `keys=`). So `SECRET_FOR_ENTRA=` is left open
    # and recorded rather than bought at that price. `[REDACTED:...]` is the placeholder the
    # hard rule mandates and is allowed through. The optional opening delimiter is not
    # decoration:
    # a backtick between the bullet and the name defeated the whole prefix set, and this
    # project's own house style puts every identifier in backticks behind a bullet, so the
    # likeliest real shape was the one walking past.
    ("Unquoted environment-file credential",
     r"^[ \t]*(?:(?:ENV|ARG|export|-e|--env|[-*\u25cf])[ \t]+)*['\"`]?[A-Z][A-Z0-9_]*"
     r"(?:SECRET|TOKEN|KEY|KEYS|PASSWORD|PASSWD|PWD)[A-Z0-9_]*=(?!\[REDACTED:)\S{8,}"),
    # The same assignment anywhere in a LINE OF PROSE, which is how a runbook writes it:
    # "Set NAME=value in the console", or a `docker run -e NAME=value` that does not begin
    # its line. Case-SENSITIVE, and that is the whole reason this is a separate rule rather
    # than a relaxed anchor on the one above. Folding case here gives 26 matches on 18 lines
    # across all 159 tracked files: 19 Python keyword arguments (`outgoing_key=`,
    # `sort_keys=`) and 7 `sonar.projectKey=` lines, six of them in the skill templates and
    # one in this project's own `sonar-project.properties`, all admitted by the
    # preceding-character widening. Requiring the upper case name that every environment
    # variable actually has leaves zero. The one carve-out
    # is the diagnostics read-out shape `NAME=MISSING(n)`, which is a value-ABSENT marker
    # this application prints on purpose and which appears in a document and a test.
    #
    # "Anywhere in a line" means it: the character before the name need only be a non-word
    # one. A narrower list of separators was written first and ten shapes walked past it,
    # the plausible ones being a query string (`?NAME=`, `&NAME=`) and a bullet written with
    # no space after it. The widening costs zero false positives here, so the narrower list
    # bought nothing.
    ("Credential written into prose",
     r"(?:^|[^A-Za-z0-9_])['\"`]?[A-Z][A-Z0-9_]*"
     r"(?:SECRET|TOKEN|KEY|KEYS|PASSWORD|PASSWD|PWD)[A-Z0-9_]*="
     r"(?!\[REDACTED:)(?!MISSING\()[^\s'\"`]{8,}"),
    # The same names in the shape a DOCUMENT writes them: a parameter table row. The table
    # in `docs/DEPLOYMENT.md` is the likeliest place in the tree for a real value to be
    # pasted beside the name it belongs to, and it has THREE columns, headed Variable,
    # Source and Value. A rule reading only the cell after the name therefore scanned the
    # Source cell and never the one literally headed Value, which is where a credential
    # lands; the row shipped clean, demonstrated. Any cell of the row is scanned now. The
    # value cell must be one token with no spaces, which is what separates a credential from
    # the prose the live rows actually hold. The placeholder exemption is ROW-level rather
    # than cell-level, and that is the second attempt: a lookahead on the value cell let the
    # engine try a different cell instead, so `| NAME | Operator-set | [REDACTED:secret] |`
    # matched on `Operator-set`, a legitimate lone token. A row carrying `[REDACTED:...]` or
    # `TBC` anywhere in it is a documented parameter row and is skipped whole. That is a
    # bypass for anyone who adds `TBC` to a row on purpose, and it is the right trade: the
    # adversary this rule is for is an honest committer pasting a value into a table.
    ("Credential in a document table row",
     r"^[ \t]*\|(?![^\n]*(?:\[REDACTED:|TBC))(?:[^|\n]*\|)*?[ \t]*`?[A-Z][A-Z0-9_]*"
     r"(?:SECRET|TOKEN|KEY|KEYS|PASSWORD|PASSWD|PWD)[A-Z0-9_]*`?[ \t]*\|(?:[^|\n]*\|)*?"
     r"[ \t]*`?[^ \t|]{8,}`?[ \t]*(?:\||$)"),
]
#: The rules that must NOT fold case. Every other rule folds, because `client_secret=` is a
#: real spelling and a sweep that misses it is a sweep with a hole. This one is the
#: exception BY MEASUREMENT rather than by taste: it matches anywhere in a line, so folding
#: case turns every Python keyword argument ending in `_key` into a finding.
CASE_SENSITIVE = {"Credential written into prose"}

# MULTILINE on everything, and it is load-bearing rather than tidy. Without it the
# `^`-anchored rules are DEAD in the whole-file and NUL-stripped passes, because `^` then
# matches only at offset zero: a UTF-16 file carrying the credential on any line but the
# first shipped, and the NUL-stripped view is exactly the pass that exists to see it. The
# hook at `.claude/hooks/secret-scan.mjs` carries the same rules under the same flags, and
# `tests/test_secret_rule_parity.py` asserts that rather than trusting it.
COMPILED = [
    (label, re.compile(pattern, re.MULTILINE | (0 if label in CASE_SENSITIVE else re.IGNORECASE)))
    for label, pattern in RULES
]

#: WHICH path may claim the exemption, and how many findings it may suppress there. A bare
#: total was spendable two ways, both demonstrated. One exempt LINE holding a tuple of three
#: credentials shipped an AWS key, an LLM provider key and a GitLab token while the count
#: still read one, because the counter incremented per line rather than per match. And
#: shortening the legitimate double so it no longer matched, then adding a marked credential
#: under `tests/nested/`, kept the total at one while the credential moved to a path that had
#: never carried one, with byte-identical build output. Pinning the identity rather than the
#: arithmetic is what makes RELOCATION visible; the match count and the line digest below
#: are what make a multiple and a substitution visible. All three were needed, and each was
#: added only after the previous one had been defeated.
EXEMPT_ALLOWED = {
    "tests/test_entra_sign_in.py": {
        "matches": 1,
        "sha256": "7ed7ec605bec24f1d85af16e870e8f722b9ceea4fd06f88c0eec9f9a5504b21e",
    }
}
EXEMPT_MARKERS = ("# noqa: S105", "# nosec")


def _exempt(path, line):
    """Whether this line may claim the declared-test-double exemption.

    Anchored to the PACKAGE ROOT. `"tests" in path.parts` tested the absolute stage path,
    so any committed directory named `tests` anywhere satisfied it: `docs/tests/probe.py`
    with a marked credential shipped in a clean-stamped package, and the comment claiming
    the exemption applies only inside `tests/*.py` was false.
    """
    if not any(marker in line for marker in EXEMPT_MARKERS):
        return False
    return str(path.relative_to(STAGE)) in EXEMPT_ALLOWED


STAGE = pathlib.Path(sys.argv[1])

hits = []
examined = 0
suppressed = collections.Counter()
found_on_a_line = set()
for path in pathlib.Path(sys.argv[1]).rglob("*"):
    if not path.is_file():
        continue
    try:
        raw = path.read_bytes()
    except OSError as error:
        # NOT a `continue`. A file the sweep cannot open is a file the sweep did not check,
        # and this is a credential control: the unexamined file is exactly where a secret
        # would be. The same principle the interpreter check above already states.
        hits.append(f"{path}: could not be read ({error.__class__.__name__})")
        continue
    # Decoded with replacement rather than skipped on a decode error. A single trailing
    # 0xFF byte appended to a Markdown file made `read_text` raise, the sweep moved on, and
    # the credential shipped in a package the build called clean. A credential inside a PNG
    # shipped the same way. Replacement never raises and still matches an ASCII pattern
    # embedded in binary, which is the shape that actually gets exfiltrated.
    # Two views of the same bytes. UTF-8 with replacement never raises, and it does not
    # SEE a UTF-16 file: the credential is there in plain sight as `s\x00k\x00-\x00`, and
    # no ASCII rule matches it. That is not an exotic encoding, it is what PowerShell's
    # `Out-File` and `>` produce by default, so a redirected capture pasted into the
    # repository lands in exactly this shape. Stripping the NUL bytes gives a second view
    # in which the same credential is ordinary ASCII, and it also covers UTF-32 and plain
    # NUL-interleaved text.
    #
    # What this still does NOT see, recorded because the accreditation record now names
    # this sweep as the compensating control for the whole secret regime: base64 or other
    # encodings of a credential, anything inside a compressed container, and a credential
    # carried in a filename or a directory name rather than a file body, an UNQUOTED
    # assignment outside the dotenv and table shapes the rules below match, and an
    # assignment split across lines by an intervening COMMENT, which neither pass sees
    # because the rule's whitespace class cannot cross the comment text. The path case is
    # closed just below, for every component. The rest are open and are real limits, not
    # theoretical. Be specific about the unquoted case, because it has been described too
    # loosely once already: `NAME=value` is caught with an `ENV`, `ARG`, `export`, `-e`,
    # `--env` or list-marker prefix and at any indent, and `| NAME | value |` is caught as
    # a document table row, but `NAME = value` with spaces around the equals is NOT, and a
    # `name: value` mapping in YAML or JSON is NOT. The spaces form was measured: widening
    # the equals to allow them gives 22 findings on 22 lines across all 159 tracked files,
    # so the rule would fire on every build and be turned off within a week. The experiment
    # is to replace `=` with `[ \t]*=[ \t]*` in the unquoted rule alone and scan every
    # tracked file. It is a real gap and it is recorded here rather than closed.
    text = raw.decode("utf-8", errors="replace")
    stripped = raw.replace(b"\x00", b"").decode("utf-8", errors="replace")
    examined += 1
    # Two passes over the same text. The line pass gives a number to report; the whole-file
    # pass catches an assignment split across lines, which the pre-write hook sees because
    # it matches one joined blob and a line-based sweep does not. Only where the halves are
    # separated by whitespace: neither route crosses an intervening comment, recorded above. Exempted lines are removed
    # before both, so the exemption cannot be defeated by the whole-file pass and cannot be
    # claimed by it either.
    scannable = []
    for number, line in enumerate(text.splitlines(), start=1):
        matched = [label for label, rule in COMPILED if rule.search(line)]
        marked = any(marker in line for marker in EXEMPT_MARKERS)
        if matched and marked:
            # Counted as claiming the exemption only when it would otherwise have been a
            # finding. A line that merely MENTIONS the marker, as this script's own tests
            # do when they write a probe, is not relying on it, and counting those made the
            # pinned total meaningless.
            if _exempt(path, line):
                # By the number of real MATCHES. `matched` holds one entry per RULE, so a
                # line carrying three credentials of the same shape scored one and shipped
                # all three. `findall` counts the credentials, not the kinds.
                suppressed[str(path.relative_to(STAGE))] += sum(
                    len(rule.findall(line)) for _, rule in COMPILED
                )
                # And the line is pinned by digest, so substituting a real secret for the
                # declared double is a change to the allowance rather than a silent one.
                # Swapping the double for a production-shaped secret shipped it, exit 0.
                digest = hashlib.sha256(line.strip().encode("utf-8")).hexdigest()
                if digest != EXEMPT_ALLOWED[str(path.relative_to(STAGE))]["sha256"]:
                    hits.append(f"{path}:{number}: the exempt line has changed; review it")
                continue
            hits.append(f"{path}:{number}: an exemption marker outside the allowed paths")
        scannable.append(line)
        for label in matched:
            hits.append(f"{path}:{number}: {label}")
            found_on_a_line.add((str(path), label))
    for label, rule in COMPILED:
        if rule.search("\n".join(scannable)) and (str(path), label) not in found_on_a_line:
            hits.append(f"{path}: {label}, split across lines")
    if stripped != text:
        for label, rule in COMPILED:
            if rule.search(stripped) and (str(path), label) not in found_on_a_line:
                hits.append(f"{path}: {label}, in a NUL-separated encoding such as UTF-16")
    # Every PATH COMPONENT, not just the leaf. A key pasted as a filename never reaches the
    # body scan, and `docs/glpat-<token>/notes.md` put one in a directory name instead.
    # Every component AND the joined path. A credential whose assignment opens in one
    # directory name and closes in the next is invisible to a per-component scan, and the
    # example is not written out here because the sweep would, correctly, match it.
    relative = path.relative_to(STAGE)
    path_labels = set()
    for candidate in (*relative.parts, str(relative)):
        for label, rule in COMPILED:
            if rule.search(candidate):
                path_labels.add(label)
    for label in sorted(path_labels):
        hits.append(f"{relative}: {label}, in the path")

if not examined:
    print("FAIL: the credential sweep examined no files at all")
    sys.exit(1)
allowed_counts = {path: rule["matches"] for path, rule in EXEMPT_ALLOWED.items()}
if dict(suppressed) != allowed_counts:
    hits.append(f"exemptions claimed {dict(suppressed)} against {allowed_counts} allowed")
try:
    for hit in hits:
        print(f"FAIL: {hit}")
    if hits:
        sys.exit(1)
    print(f"credential sweep: {examined} files examined, exemptions {allowed_counts} honoured")
except BrokenPipeError:
    # `sh scripts/build-package.sh | head -1` closes stdout under the sweep. The build
    # already fails closed, but in POSIX sh the pipeline's status is `head`'s, which is 0,
    # and the last line the operator sees is the success-shaped verification banner. So the
    # refusal is written to stderr, which the pipe has not closed.
    print("FAIL: the credential sweep could not finish; stdout closed", file=sys.stderr)
    sys.exit(1)
SWEEP

# The assertion that would have caught the gate's finding. The suite reads these from the
# package root, so a package without them fails the platform test stage even though the
# same suite is green in the repository. Derived from the tests, not from memory:
# `grep -rn "parents\[1\]" tests/` names every one, and the list below is that grep's
# answer in full. The lockfiles are named here as well as in the allowlist above, because
# `_pins` reads all three from the package root and a second check costs nothing.
for needed in .env.example docs/DEPLOYMENT.md pyproject.toml Dockerfile \
              requirements-runtime.txt requirements.txt requirements-dev.txt; do
  [ -e "$STAGE/$needed" ] || { echo "FAIL: the suite reads $needed from the package root and it is not in the package"; exit 1; }
done
# A nested Dockerfile breaks template detection. There must be exactly one, at the root.
NESTED="$(find "$STAGE" -mindepth 2 -name Dockerfile -print | head -1)"
[ -z "$NESTED" ] || { echo "FAIL: nested Dockerfile at $NESTED breaks template detection"; exit 1; }
# No secret may ride along. `.env.example` holds placeholders only and is checked by the
# suite; a real `.env` is git-ignored and must never reach the package.
! [ -e "$STAGE/.env" ] || { echo "FAIL: .env is in the package"; exit 1; }
[ -f "$STAGE/.env.example" ] || { echo "FAIL: .env.example must ship; the suite reads it"; exit 1; }

(cd "$STAGE" && zip -q -r -X "../package.zip" . )
mv -f "$BUILT" "$OUT"

# The builder names what it built. The simulation used to pick the newest zip by
# modification time, which meant parsing `ls` output and guessing; with two packages in
# `dist/` from different commits it is a guess that can be wrong, and it was.
# Written through a temporary name and moved into place, because `> dist/latest` writes
# through whatever path exists at that moment: a symlink planted in the build's own window
# redirected the pointer, and the artefact was written outside `dist/`. The SHA-256 goes
# beside it so the simulation can bind the pointer to the bytes rather than to a filename.
# Written inside a PRIVATE DIRECTORY, not to a temporary file name.
#
# Three attempts and three defeats, each narrower than the last. A fixed name was a redirect
# target; clearing it immediately before the write closed the first window and left the one
# between the write and the `mv`; `mktemp` made the name unguessable and the file O_EXCL,
# and the shell then threw that descriptor away and RE-OPENED the name with `>`, which an
# inotify watcher won on four real builds out of five, two of them exiting 0, destroying a
# file outside the repository and leaving both pointers as links out of `dist/`.
#
# `mktemp -d` gives a directory at mode 0700. A non-owner cannot traverse it, so the path
# the shell re-opens is one nobody else can reach, and the window stops existing rather than
# getting smaller.
printf '%s\n' "$OUT" > "$WORK/pointer"
mv -f "$WORK/pointer" dist/latest
sha256sum "$OUT" | cut -d' ' -f1 > "$WORK/digest"
mv -f "$WORK/digest" dist/latest.sha256

echo "package: $OUT"
echo "size:    $(wc -c < "$OUT") bytes"
echo "sha256:  $(sha256sum "$OUT" | cut -d' ' -f1)"
echo "files:   $(unzip -Z1 "$OUT" | wc -l)"
