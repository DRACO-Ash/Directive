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
# Both lockfiles. The tooling tree is what executes in the build pipeline, which is
# exactly where a compromised dependency lands, so scanning only the runtime tree leaves
# the more exposed one unchecked.
#
# pip-audit fails open when it cannot reach the advisory service, so distinguish "clean"
# from "could not check": an honest skip on an offline runner, a hard failure on a
# networked one. Never report a failure to check as a pass.
REPORT="$(mktemp)"
trap 'rm -f "$REPORT"' EXIT

for LOCKFILE in requirements.txt requirements-dev.txt; do
  echo "-- $LOCKFILE"
  if "$PY" -m pip_audit -r "$LOCKFILE" > "$REPORT" 2>&1; then
    cat "$REPORT"
  elif grep -qiE "temporary failure|connection|resolve|timed out|network|unreachable" "$REPORT"; then
    echo "SKIPPED: the advisory service was unreachable, so $LOCKFILE was NOT checked."
    echo "Compensating control: the CI job on a networked runner fails hard on this."
  else
    cat "$REPORT"
    echo "FAIL: a known vulnerability was reported in $LOCKFILE"
    exit 1
  fi
done

echo "== software bill of materials =="
# A CycloneDX SBOM of the RUNTIME tree, which is the tree the image installs. Emitted by
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
if "$PY" -m pip_audit -r requirements.txt --format cyclonedx-json \
     --progress-spinner off -o sbom.cdx.json > "$REPORT" 2>&1; then
  echo "sbom.cdx.json written, $("$PY" -c 'import json,sys; print(len(json.load(open("sbom.cdx.json"))["components"]))') components"
elif grep -qiE "temporary failure|connection|resolve|timed out|network|unreachable" "$REPORT"; then
  echo "SKIPPED: the advisory service was unreachable, so no SBOM was written."
  echo "Compensating control: the CI job on a networked runner fails hard on this."
else
  cat "$REPORT"
  echo "FAIL: the SBOM could not be generated"
  exit 1
fi

echo "LOOP: PASS"
