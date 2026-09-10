#!/bin/sh
# Run the platform's test stage against the built PACKAGE, not against the repository.
#
# The distinction is the whole point. The repository's loop installs both requirement
# files and runs from a tree where every file exists. The platform unzips the package
# into a fresh container, installs ONE file, and runs pytest from there. A green loop
# says nothing about that, which is how a package that has never been unzipped reaches
# an upload and fails in seconds with eight later stages skipped.
#
# Stage 5 of the platform pipeline is `pip install -r requirements.txt` then pytest.
# That is the command run below, verbatim, with no second requirements file, because
# adding one is what hides the failure this script exists to find.
set -eu

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

PKG="${1:-}"
if [ -z "$PKG" ]; then
  PKG="$(ls -1t dist/comply-ops-*.zip 2>/dev/null | head -1 || true)"
fi
[ -n "$PKG" ] && [ -f "$PKG" ] || { echo "FAIL: no package. Run scripts/build-package.sh first."; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
echo "package:     $PKG"
echo "unpacked to: $WORK"
unzip -q "$PKG" -d "$WORK"

PY312="${PYTHON312:-/usr/bin/python3.12}"
[ -x "$PY312" ] || { echo "SKIP: no interpreter at $PY312; this leg cannot run locally."; exit 1; }

cd "$WORK"
"$PY312" -m venv .venv
echo "== stage 5, install: pip install -r requirements.txt =="
.venv/bin/python -m pip install -q --upgrade pip >/dev/null 2>&1 || true
.venv/bin/python -m pip install -q -r requirements.txt

echo "== stage 5, test: pytest with coverage to the path the quality gate reads =="
set +e
.venv/bin/python -m pytest --cov --cov-report=xml -q
STATUS=$?
set -e
echo "PYTEST EXIT: $STATUS"
[ "$STATUS" -eq 0 ] || { echo "SIMULATION: FAIL at stage 5"; exit "$STATUS"; }

# Stage 6 reads this exact path. A suite that passes while writing the report somewhere
# else still fails the quality gate, so the artefact is asserted rather than assumed.
[ -f coverage.xml ] || { echo "SIMULATION: FAIL, coverage.xml was not written"; exit 1; }
echo "coverage.xml: $(wc -c < coverage.xml) bytes"
echo "SIMULATION: PASS"
