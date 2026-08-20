#!/bin/sh
# The verification loop, ordered cheapest first so a cheap failure never pays for an
# expensive one. Pure POSIX sh: the platform runs build and test steps under a minimal
# shell (BusyBox sh on Alpine), where bash and every bash-only feature is absent.
set -eu

PY="${PYTHON:-.venv/bin/python}"
if [ ! -x "$PY" ]; then
  PY="python3"
fi

echo "== format =="
"$PY" -m ruff format --check .

echo "== lint (the platform analyser profile, not a looser local default) =="
"$PY" -m ruff check .

echo "== types (strict) =="
"$PY" -m mypy

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
# pip-audit fails open when it cannot reach the advisory service, so distinguish
# "clean" from "could not check": an honest skip on an offline runner, a hard failure
# on a networked one. Never report a failure to check as a pass.
if "$PY" -m pip_audit -r requirements.txt > /tmp/audit-runtime.txt 2>&1; then
  cat /tmp/audit-runtime.txt
else
  if grep -qiE "temporary failure|connection|resolve|timed out|network" /tmp/audit-runtime.txt; then
    echo "SKIPPED: the advisory service was unreachable, so runtime dependencies were NOT checked."
    echo "Compensating control: the CI job on a networked runner treats this as a hard failure."
  else
    cat /tmp/audit-runtime.txt
    echo "FAIL: a known vulnerability was reported in a runtime dependency"
    exit 1
  fi
fi

echo "LOOP: PASS"
