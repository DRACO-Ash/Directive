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

# The package to test: the argument, or whatever the builder last wrote. Reading the
# builder's own record beats picking the newest file by modification time, which meant
# parsing `ls` output and could pick the wrong one of two packages built from different
# commits.
PKG="${1:-}"
FROM_POINTER=no
if [ -z "$PKG" ] && [ -f dist/latest ]; then
  PKG="$(cat dist/latest)"
  FROM_POINTER=yes
fi
if [ -z "$PKG" ] || [ ! -f "$PKG" ]; then
  echo "FAIL: no package at '${PKG:-dist/latest}'. Run scripts/build-package.sh first."
  exit 1
fi

# A package built from a different tree tests the wrong thing and reports PASS for it,
# which is the one answer this script must never give. Checked only when the package came
# from the pointer: an explicit argument is a deliberate choice to test that file.
#
# The match is on the FILENAME the builder writes, not anywhere in the path. `*$HEAD_SHORT*`
# accepted `dist/3a0661f/comply-ops-2.2-20260101-deadbee.zip` because the commit appeared in
# a directory name, which is looser than the check reads.
#
# The commit stamp is NOT sufficient on its own, and saying otherwise was an over-claim
# this file made about itself. It matches the commit the package was BUILT at, and says
# nothing about what the tree holds NOW: build clean, edit a source file, run from the
# pointer, and the stale package sails through. Demonstrated with the register state
# vocabulary check disabled in the tree and SIMULATION: PASS returned anyway.
#
# So the tree is checked at simulation time as well, which is a superset of the stamp: any
# difference between the package and the tree under test, whenever it appeared, shows up as
# a dirty worktree here. The stamp stays because it marks the artefact itself, so a package
# file on disk declares its own provenance.
if [ "$FROM_POINTER" = yes ]; then
  HEAD_SHORT=nogit
  if command -v git >/dev/null 2>&1; then
    HEAD_SHORT="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
  fi
  if [ "$HEAD_SHORT" = nogit ]; then
    # Either git is absent or this is not a repository. Both leave the package unchecked,
    # and a `nogit` stamp would otherwise match a `nogit` package from any tree at any time,
    # which is a tautology rather than a check.
    echo "SKIPPED: no commit is resolvable, so the package was NOT checked against the tree."
    echo "Compensating control: none here. Pass the package explicitly to be sure of it."
  else
    case "${PKG##*/}" in
      comply-ops-*-"$HEAD_SHORT".zip) ;;
      comply-ops-*-"$HEAD_SHORT"-dirty.zip)
        echo "FAIL: ${PKG##*/} was built from a dirty tree, so it may already be stale."
        echo "Commit, rebuild, or pass the package explicitly to test it anyway."
        exit 1
        ;;
      *)
        echo "FAIL: $PKG was not built from the current commit ($HEAD_SHORT)."
        echo "Run scripts/build-package.sh, or pass the package explicitly to test it anyway."
        exit 1
        ;;
    esac
    if [ -n "$(git status --porcelain)" ]; then
      echo "FAIL: the working tree has changed, so $PKG no longer represents it."
      echo "Rebuild, or pass the package explicitly to test it anyway."
      exit 1
    fi
  fi
fi

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
