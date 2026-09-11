#!/bin/sh
# The verification loop, ordered cheapest first so a cheap failure never pays for an
# expensive one. Pure POSIX sh: the platform runs build and test steps under a minimal
# shell (BusyBox sh on Alpine), where bash and every bash-only feature is absent.
set -eu

# No silent fallback to a bare python3. An interpreter the lockfile does not pin can
# print LOOP: PASS while running different dependency versions, which is a green loop
# that proves nothing.
PY="${PYTHON:-.venv/bin/python}"
if [ ! -x "$PY" ]; then
  echo "FAIL: no interpreter at $PY."
  echo "Create it, then install: /usr/bin/python3.12 -m venv .venv"
  exit 1
fi
PINNED="$(cat .python-version)"
ACTUAL="$("$PY" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if [ "$PINNED" != "$ACTUAL" ]; then
  echo "FAIL: .python-version pins $PINNED but $PY is $ACTUAL"
  exit 1
fi
echo "interpreter: $PY (Python $ACTUAL, pinned $PINNED)"

echo "== shell =="
# Three POSIX scripts carry the verification, packaging and pipeline-simulation logic and
# nothing statically checked them. `shellcheck` may be absent from a development machine, so the
# absence is reported rather than passed over: the Continuous Integration runner image
# provides the binary and that job fails hard, exactly as it does for the dependency scan.
# If a future runner image drops it the step fails on a missing command, which is the right
# direction. Do not lower the severity to make this leg pass: it exits non-zero on an
# info-level finding, and it was added to this loop having only ever run its skip path,
# which is how it shipped red.
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -s sh scripts/*.sh
  echo "shellcheck: clean"
else
  echo "SKIPPED: shellcheck is not installed, so scripts/*.sh was NOT statically checked."
  echo "Compensating control: the CI runner image provides it and that job fails hard."
fi

echo "== format =="
"$PY" -m ruff format --check .

echo "== lint (the platform analyser profile, not a looser local default) =="
"$PY" -m ruff check .

echo "== types (strict) =="
"$PY" -m mypy

echo "== static application security testing (AMD-001 section 10.6) =="
# ruff and mypy are a linter and a type checker; neither is SAST, which AMD-001 requires
# on every code change. bandit is the leg that satisfies that clause. Low severity is
# reported and not failed: it is dominated by assert-in-test findings, and failing on
# them would train the reader to ignore the output.
"$PY" -m bandit --configfile pyproject.toml --quiet --recursive src wsgi.py

echo "== tests with coverage =="
# --cov-report=xml is what produces the Cobertura file the Code Quality gate reads. A
# comprehensive suite that emits no report scores 0%.
"$PY" -m pytest --cov --cov-report=xml --cov-report=term

echo "== coverage artefact =="
if [ ! -s coverage.xml ]; then
  echo "FAIL: coverage.xml is missing or empty, so the quality gate would read 0%"
  exit 1
fi
echo "coverage.xml present and non-empty"

echo "== dependency vulnerabilities =="
# All three lockfiles. The tooling tree is what executes in the build pipeline, which is
# exactly where a compromised dependency lands, so scanning only the runtime tree leaves
# the more exposed one unchecked.
#
# pip-audit fails open when it cannot reach the advisory service, so distinguish "clean"
# from "could not check": an honest skip on an offline runner, a hard failure on a
# networked one. Never report a failure to check as a pass.
REPORT="$(mktemp)"
trap 'rm -f "$REPORT"' EXIT

for LOCKFILE in requirements-runtime.txt requirements.txt requirements-dev.txt; do
  echo "-- $LOCKFILE"
  if "$PY" -m pip_audit -r "$LOCKFILE" > "$REPORT" 2>&1; then
    cat "$REPORT"
  elif grep -qiE "vulnerabilit|found [0-9]+ known" "$REPORT"; then
    cat "$REPORT"
    echo "FAIL: a known vulnerability was reported in $LOCKFILE"
    exit 1
  elif grep -qiE "temporary failure|connection|resolve|timed out|network|unreachable" "$REPORT"; then
    echo "SKIPPED: the advisory service was unreachable, so $LOCKFILE was NOT checked."
    echo "Compensating control: the CI job on a networked runner fails hard on this."
  else
    # Neither a finding nor a network failure. Reported as what it is rather than as a
    # vulnerability: an unpinned requirement under `--require-hashes` exits non-zero here
    # and was announced as a CVE, which is the mirror image of the mis-triage this loop set
    # out to fix.
    cat "$REPORT"
    echo "FAIL: $LOCKFILE could not be audited; the report above says why"
    exit 1
  fi
done

echo "== software bill of materials =="
# A CycloneDX SBOM of the RUNTIME tree, `requirements-runtime.txt`, which is what ships. Emitted by
# pip-audit, so this leg adds no dependency: the alternative was a new packaging tool in
# the build path, which is the thing a supply-chain control should add least of.
#
# Why generate one at all when the platform generates its own. Two reasons, both dated.
# The App Store's Dependency Scanning stage reports a crash and a genuine advisory with the
# same message, and the presence of an SBOM artefact is what tells the two apart; holding
# our own means a gate failure can be triaged rather than guessed at. And the Cyber
# Resilience Act's vulnerability reporting duty binds from 11 September 2026 with a 24-hour
# early warning, which leaves no time to work out which shipped versions carry a component.
#
# Be exact about what this file is and is not. It is CycloneDX 1.4, inside the 1.4 to 1.6
# range the App Store accepts for a bring-your-own SBOM. It carries component names,
# versions and the dependency graph. It does NOT carry component hashes, licences, or the
# generating tool's own identity, so it does NOT satisfy the CISA 2026 minimum elements.
# The hashes exist in requirements.txt and merging them in by hand would make this file
# less trustworthy, not more. Closing that gap needs a real SBOM generator; recorded in
# docs/DEPLOYMENT.md rather than implied to be done.
#
# Built from an INSTALL of the runtime lockfile rather than from the lockfile text, because
# the text route is incomplete and silently so. `pip-audit -r` returned 8 of the 9 pins:
# `packaging` was absent from the audit AND from the bill of materials, with no skip notice,
# no warning and exit 0. A package that ships in the image and is examined by nothing is the
# exact hole a dependency gate exists to close, and the artefact naming 8 of 9 components is
# evidence that is quietly wrong. Installing the lockfile into a throwaway directory and
# auditing THAT by path returns all 9. It also inventories what is really there rather than
# what a parser made of a file, which is the stronger claim to put in front of an assessor.
TARGET="$(mktemp -d)"
trap 'rm -f "$REPORT"; rm -rf "$TARGET"' EXIT
if ! "$PY" -m pip install -q --require-hashes --no-deps --target "$TARGET" \
       -r requirements-runtime.txt > "$REPORT" 2>&1; then
  cat "$REPORT"
  echo "FAIL: the runtime tree could not be installed for the bill of materials"
  exit 1
fi
# Split from the install above, because `pip-audit` exits non-zero on a FINDING as well as
# on a failure. Folded together, a genuine vulnerability in a shipped package reported as
# "the SBOM could not be generated", which mis-triages the one case this leg uniquely
# catches: `packaging` is audited here and nowhere else.
if "$PY" -m pip_audit --path "$TARGET" --format cyclonedx-json \
     --progress-spinner off -o sbom.cdx.json > "$REPORT" 2>&1; then
  echo "sbom.cdx.json written, $("$PY" -c 'import json,sys; print(len(json.load(open("sbom.cdx.json"))["components"]))') components"
  # The assertion that makes the omission above impossible to repeat. Nothing compared the
  # audited set to the pin set, so a missing package looked exactly like a clean scan.
  "$PY" - <<'COMPLETE'
import json
import re
import sys

pins = {
    name.lower()
    for name, _ in re.findall(
        r"^[ \t]*([A-Za-z0-9_.\-]+)==([^ ;\\\n]+)",
        open("requirements-runtime.txt", encoding="utf-8").read(),
        re.MULTILINE,
    )
}
listed = {c["name"].lower() for c in json.load(open("sbom.cdx.json", encoding="utf-8"))["components"]}
missing = sorted(pins - listed)
if missing or not pins:
    print(f"FAIL: the bill of materials omits {missing or 'everything'} from the shipped set")
    print("      A component nothing inventories is a component nothing scans.")
    sys.exit(1)
print(f"every one of the {len(pins)} shipped pins is in the bill of materials")
COMPLETE
elif grep -qiE "temporary failure|connection|resolve|timed out|network|unreachable" "$REPORT"; then
  echo "SKIPPED: the advisory service was unreachable, so no SBOM was written."
  echo "Compensating control: the CI job on a networked runner fails hard on this."
elif grep -qiE "vulnerabilit|found [0-9]+ known" "$REPORT"; then
  cat "$REPORT"
  echo "FAIL: a known vulnerability was reported in the tree the image installs"
  exit 1
else
  cat "$REPORT"
  echo "FAIL: the SBOM could not be generated"
  exit 1
fi

echo "== dependency nesting =="
# The platform never checks this and it is what a divergence would hide. The scanner reads
# `requirements.txt` by name and never `requirements-runtime.txt`, so a package resolved to
# one version in the file that SHIPS and another in the file that is SCANNED would put a
# version through no gate at all. It is not hypothetical: splitting these files resolved
# click to 8.5.0 in one and 8.4.2 in the other on the first attempt.
"$PY" - <<'NESTING'
import re
import sys

def pins(path):
    text = open(path, encoding="utf-8").read()
    if "--strip-extras" not in text:
        print(f"FAIL: {path} was not compiled with --strip-extras, so the pin parser below")
        print("      would silently drop an extras-bearing line out of the subset check")
        raise SystemExit(1)
    found = re.findall(r"^[ \t]*([A-Za-z0-9_.\-]+)==([^ ;\\\n]+)", text, re.MULTILINE)
    # `^` alone missed a pin written with leading whitespace, which pip honours: an indented
    # `requests==2.19.1` appended to the runtime lockfile was downloaded by pip while all
    # three nesting tests stayed green. And an empty parse would satisfy every subset check
    # vacuously, so the count is compared with the file's own `==` occurrences.
    declared = len(re.findall(r"^[ \t]*[A-Za-z0-9_.\-]+==", text, re.MULTILINE))
    if not found or len(found) != declared:
        print(f"FAIL: {path} parsed {len(found)} pins against {declared} declared")
        raise SystemExit(1)
    return dict(found)

failed = False
for inner, outer in (
    ("requirements-runtime.txt", "requirements.txt"),
    ("requirements.txt", "requirements-dev.txt"),
):
    small, large = pins(inner), pins(outer)
    for name, version in small.items():
        if large.get(name) != version:
            print(f"FAIL: {name}=={version} in {inner} but {large.get(name)} in {outer}")
            failed = True
sys.exit(1 if failed else 0)
NESTING
echo "runtime subset of test subset of dev, at identical versions"

echo "LOOP: PASS"
